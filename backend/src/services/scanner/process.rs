//! The out-of-process scanner runner (`specs/spinoff-local-scan.md`, section 7; decisions 5, 19,
//! 28 and 29).
//!
//! Rules enforced here, for every scanner run:
//! - The program is an absolute path and the arguments are an argument vector. No shell runs,
//!   and no `PATH` is searched.
//! - The environment is cleared first. Only the variables a caller passes in the allow-list are
//!   set, so `DOCKWARD_ENCRYPTION_KEY` and the other secrets never reach the child.
//! - The child leads its own process group. On timeout, or when its captured output goes over
//!   the cap, the whole group is killed.
//! - stdout is captured up to the cap. It is the report, and it is returned to the caller. It is
//!   stored as a log line only when [`Invocation::log_stdout`] is set (update steps).
//! - stderr is kept as a tail for the step log (#308): the newest lines, redacted and capped, by
//!   [`ScannerRunner::run_recorded`]. It is never returned as a report.
//! - One scanner process runs at a time, through a lock held by [`ScannerRunner`].
//!
//! This module holds no database code.

use std::collections::VecDeque;
use std::ffi::OsString;
use std::path::Path;
use std::process::{ExitStatus, Stdio};
use std::sync::{Arc, Mutex as SyncMutex, MutexGuard, PoisonError};
use std::time::Duration;

use nix::sys::signal::{Signal, killpg};
use nix::unistd::Pid;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;
use tokio::sync::Mutex;

use crate::error::{AppError, ScannerFault};
use crate::services::app_log::{MAX_LINE_CHARS, MAX_LINES as MAX_STEP_LINES, truncate_line};
use crate::services::scanner::redact::redact_line;
use crate::worker::now_secs;

/// The default timeout of one scanner run (decision 19).
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(600);

/// The default cap on captured output: 64 MiB (decision 19).
pub const DEFAULT_OUTPUT_MAX_BYTES: u64 = 64 * 1024 * 1024;

/// Read chunk size for captured output.
const CHUNK_BYTES: usize = 64 * 1024;

/// The longest partial line kept while its end is awaited. Four bytes per character, so this
/// always holds more than [`MAX_LINE_CHARS`] characters; a longer line is cut anyway.
const MAX_PENDING_BYTES: usize = MAX_LINE_CHARS * 4;

/// How long the stderr drain may finish after the child is gone, before it is abandoned. The
/// lines it has read so far are kept either way.
const DRAIN_JOIN: Duration = Duration::from_secs(1);

/// The limits of one run. Operator settings replace the defaults (section 13).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub timeout: Duration,
    pub output_max_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_TIMEOUT,
            output_max_bytes: DEFAULT_OUTPUT_MAX_BYTES,
        }
    }
}

/// One run request. `program` must be absolute. `env` is the allow-list: the only variables the
/// child sees. `log_stdout` stores stdout as log lines; it is set for update steps only, never
/// for a scan, whose stdout is the report.
#[derive(Debug)]
pub struct Invocation<'a> {
    pub program: &'a Path,
    pub args: &'a [OsString],
    pub env: &'a [(OsString, OsString)],
    pub limits: Limits,
    pub log_stdout: bool,
}

/// How a recorded step ended. The `outcome` column of `job_log_steps`, except `running`, which
/// is written before the step starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepOutcome {
    Ok,
    Failed,
    TimedOut,
    OutputTooLarge,
    SpawnFailed,
}

impl StepOutcome {
    /// The stored text.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Failed => "failed",
            Self::TimedOut => "timed_out",
            Self::OutputTooLarge => "output_too_large",
            Self::SpawnFailed => "spawn_failed",
        }
    }
}

/// The stream a log line came from. The stored text is `stderr` or `stdout`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineStream {
    Stderr,
    Stdout,
}

impl LineStream {
    /// The stored text.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Stderr => "stderr",
            Self::Stdout => "stdout",
        }
    }
}

/// One redacted, capped line of a step, with the Unix second it was read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepLine {
    pub stream: LineStream,
    pub at: i64,
    pub text: String,
}

/// What one step did. Stored by `db::job_log` with the lines. Holds no secret: `command` is the
/// program's file name and its fixed arguments, redacted, and the lines are redacted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepRecord {
    pub command: String,
    pub started_at: i64,
    pub finished_at: i64,
    pub timeout_secs: u64,
    pub outcome: StepOutcome,
    pub exit_code: Option<i32>,
    /// True when older lines were dropped to keep the newest [`MAX_STEP_LINES`].
    pub truncated: bool,
    pub lines: Vec<StepLine>,
}

/// Runs scanner processes one at a time. Clone the handle to share the lock.
#[derive(Debug, Clone, Default)]
pub struct ScannerRunner {
    lock: Arc<Mutex<()>>,
}

impl ScannerRunner {
    /// Creates a runner with its own lock.
    pub fn new() -> Self {
        Self::default()
    }

    /// Runs one invocation and returns its captured stdout. Failures return
    /// [`AppError::Scanner`] with one of the fixed texts of section 6. The step record is
    /// dropped; use [`Self::run_recorded`] to keep it. Production runs go through
    /// `ScanEnv::run_scanner`, which adds the fallback on a launch failure (#390).
    #[cfg_attr(not(test), allow(dead_code))]
    pub async fn run(&self, invocation: Invocation<'_>) -> Result<Vec<u8>, AppError> {
        self.run_recorded(invocation).await.0
    }

    /// Runs one invocation like [`Self::run`], and also returns the step record: the command,
    /// the times, the outcome, the exit status and the redacted stderr tail (and stdout when
    /// `log_stdout` is set). The record is returned on every outcome, including a failure.
    pub async fn run_recorded(
        &self,
        invocation: Invocation<'_>,
    ) -> (Result<Vec<u8>, AppError>, StepRecord) {
        let _guard = self.lock.lock().await;
        let started_at = now_secs();
        let command = command_text(&invocation);
        let timeout_secs = invocation.limits.timeout.as_secs();
        let attempt = run_unlocked(&invocation).await;
        let finished_at = now_secs().max(started_at);
        let record = StepRecord {
            command,
            started_at,
            finished_at,
            timeout_secs,
            outcome: attempt.outcome,
            exit_code: attempt.exit_code,
            truncated: attempt.truncated,
            lines: attempt.lines,
        };
        (attempt.result.map_err(AppError::Scanner), record)
    }
}

/// The result of one run, before the lock is released.
struct Attempt {
    result: Result<Vec<u8>, ScannerFault>,
    outcome: StepOutcome,
    exit_code: Option<i32>,
    lines: Vec<StepLine>,
    truncated: bool,
}

/// An attempt that never started a process.
fn spawn_failed() -> Attempt {
    Attempt {
        result: Err(ScannerFault::Failed),
        outcome: StepOutcome::SpawnFailed,
        exit_code: None,
        lines: Vec::new(),
        truncated: false,
    }
}

/// The step's command: the program's file name and its arguments, redacted.
fn command_text(invocation: &Invocation<'_>) -> String {
    let name = invocation
        .program
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut parts = vec![name];
    parts.extend(
        invocation
            .args
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned()),
    );
    redact_line(&parts.join(" "))
}

/// The outcome of a run that the runner itself ended with a fault.
fn outcome_of(fault: ScannerFault) -> StepOutcome {
    match fault {
        ScannerFault::TimedOut => StepOutcome::TimedOut,
        ScannerFault::OutputTooLarge => StepOutcome::OutputTooLarge,
        _ => StepOutcome::Failed,
    }
}

/// Runs one invocation with no lock. The caller holds the runner lock.
async fn run_unlocked(invocation: &Invocation<'_>) -> Attempt {
    if !invocation.program.is_absolute() {
        return spawn_failed();
    }
    let mut command = Command::new(invocation.program);
    command
        .args(invocation.args)
        .env_clear()
        .envs(invocation.env.iter().map(|(k, v)| (k, v)))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .process_group(0);
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(_) => return spawn_failed(),
    };
    let pid = child.id();
    let (Some(mut stdout), Some(stderr)) = (child.stdout.take(), child.stderr.take()) else {
        kill_group(pid);
        return spawn_failed();
    };
    // stderr is drained on its own task so a chatty child cannot block on a full pipe. Its
    // lines go into a tail shared with this function, so the lines read so far survive a drain
    // that has to be abandoned.
    let stderr_tail = Arc::new(SyncMutex::new(LineTail::new(LineStream::Stderr)));
    let mut stderr_drain = tokio::spawn(drain_into(stderr, Arc::clone(&stderr_tail)));
    let cap = invocation.limits.output_max_bytes;
    // A background child of the leader inherits stdout, so stdout may not reach its end once the
    // leader has exited. The read therefore ends at whichever comes first: stdout's end, or the
    // leader's exit. The leader is waited for, and then its group is killed while the leader is
    // still unreaped, so the pid is still ours. Bytes read before the exit are kept.
    let work = async {
        let (bytes, status) = read_until_exit(&mut stdout, cap, &mut child).await?;
        kill_group(pid);
        Ok::<_, ScannerFault>((bytes, status))
    };
    let waited = tokio::time::timeout(invocation.limits.timeout, work).await;
    // The group is killed only while the child is unreaped (timeout, or a read fault before the
    // wait). After a successful wait the pid can be reused, so it is never signalled then.
    let mut stdout_tail: Option<LineTail> = None;
    let (result, outcome, exit_code) = match waited {
        Err(_elapsed) => {
            kill_group(pid);
            (Err(ScannerFault::TimedOut), StepOutcome::TimedOut, None)
        }
        Ok(Err(fault)) => {
            kill_group(pid);
            (Err(fault), outcome_of(fault), None)
        }
        Ok(Ok((bytes, status))) => {
            if invocation.log_stdout {
                let mut tail = LineTail::new(LineStream::Stdout);
                tail.push(&bytes, now_secs());
                stdout_tail = Some(tail);
            }
            let exit_code = status.code();
            if status.success() {
                (Ok(bytes), StepOutcome::Ok, exit_code)
            } else {
                (Err(ScannerFault::Failed), StepOutcome::Failed, exit_code)
            }
        }
    };
    // The group is gone, so the drain's pipe is closed and it ends on its own. The bound only
    // stops a drain that a surviving descendant keeps open.
    if tokio::time::timeout(DRAIN_JOIN, &mut stderr_drain)
        .await
        .is_err()
    {
        stderr_drain.abort();
    }
    let now = now_secs();
    let (mut lines, mut truncated) = lock_tail(&stderr_tail).take(now);
    if let Some(mut tail) = stdout_tail {
        let (out_lines, out_truncated) = tail.take(now);
        truncated |= out_truncated;
        let mut merged = out_lines;
        merged.append(&mut lines);
        // Stable by time: stdout lines come before stderr lines read in the same second.
        merged.sort_by_key(|line| line.at);
        lines = merged;
    }
    if lines.len() > MAX_STEP_LINES {
        let excess = lines.len() - MAX_STEP_LINES;
        lines.drain(..excess);
        truncated = true;
    }
    Attempt {
        result,
        outcome,
        exit_code,
        lines,
        truncated,
    }
}

/// Reads stdout until the leader exits, and returns the bytes with the exit status. The leader is
/// waited for, not the pipe: a child left in the group may hold stdout open after the leader is
/// done. After the exit, the bytes already in the pipe are drained without blocking, still under
/// the cap. Returns [`ScannerFault::OutputTooLarge`] as soon as the total would pass `cap`.
async fn read_until_exit(
    stdout: &mut tokio::process::ChildStdout,
    cap: u64,
    child: &mut tokio::process::Child,
) -> Result<(Vec<u8>, ExitStatus), ScannerFault> {
    let mut out: Vec<u8> = Vec::new();
    let mut chunk = vec![0u8; CHUNK_BYTES];
    let status = loop {
        tokio::select! {
            status = child.wait() => {
                break status.map_err(|_| ScannerFault::Failed)?;
            }
            read = stdout.read(&mut chunk) => {
                let read = read.map_err(|_| ScannerFault::Failed)?;
                if read == 0 {
                    // stdout closed before the leader exited. Keep waiting for the leader.
                    break child.wait().await.map_err(|_| ScannerFault::Failed)?;
                }
                push_capped(&mut out, &chunk[..read], cap)?;
            }
        }
    };
    // The leader is gone. Drain what is already buffered, without waiting on a pipe a child may
    // still hold open.
    loop {
        match tokio::time::timeout(Duration::from_millis(50), stdout.read(&mut chunk)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(read)) => push_capped(&mut out, &chunk[..read], cap)?,
        }
    }
    Ok((out, status))
}

/// Appends bytes unless the total would pass `cap`.
fn push_capped(out: &mut Vec<u8>, bytes: &[u8], cap: u64) -> Result<(), ScannerFault> {
    let total = out.len().saturating_add(bytes.len());
    match u64::try_from(total) {
        Ok(total) if total <= cap => {
            out.extend_from_slice(bytes);
            Ok(())
        }
        _ => Err(ScannerFault::OutputTooLarge),
    }
}

/// Reads a stream to its end into `tail`. Read errors end the drain; the lines read so far are
/// kept.
async fn drain_into<R>(mut reader: R, tail: Arc<SyncMutex<LineTail>>)
where
    R: AsyncRead + Unpin,
{
    let mut chunk = vec![0u8; CHUNK_BYTES];
    loop {
        match reader.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(read) => lock_tail(&tail).push(&chunk[..read], now_secs()),
        }
    }
}

/// Locks a tail. A poisoned lock still holds its lines, so the lines are used.
fn lock_tail(tail: &SyncMutex<LineTail>) -> MutexGuard<'_, LineTail> {
    tail.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The newest lines of one stream. Splits on `\n` and `\r` (a progress line that ends in `\r`
/// is its own line), strips control characters, redacts, and cuts each line at
/// [`MAX_LINE_CHARS`] with the truncation marker. Keeps the newest [`MAX_STEP_LINES`].
#[derive(Debug)]
struct LineTail {
    stream: LineStream,
    pending: Vec<u8>,
    pending_over: bool,
    lines: VecDeque<StepLine>,
    truncated: bool,
}

impl LineTail {
    fn new(stream: LineStream) -> Self {
        Self {
            stream,
            pending: Vec::new(),
            pending_over: false,
            lines: VecDeque::new(),
            truncated: false,
        }
    }

    /// Adds bytes read at `at`.
    fn push(&mut self, bytes: &[u8], at: i64) {
        for &byte in bytes {
            if byte == b'\n' || byte == b'\r' {
                self.end_line(at);
            } else if self.pending.len() < MAX_PENDING_BYTES {
                self.pending.push(byte);
            } else {
                self.pending_over = true;
            }
        }
    }

    /// Ends the pending line. Blank lines are skipped, so a `\r\n` pair stores one line.
    fn end_line(&mut self, at: i64) {
        let raw = String::from_utf8_lossy(&self.pending).into_owned();
        let over = self.pending_over;
        self.pending.clear();
        self.pending_over = false;
        let cleaned: String = raw
            .chars()
            .filter_map(|c| match c {
                '\t' => Some(' '),
                c if c.is_control() => None,
                c => Some(c),
            })
            .collect();
        if cleaned.trim().is_empty() && !over {
            return;
        }
        // Redact before the cut, so a secret that straddles the cut is masked whole.
        let text = truncate_line(redact_line(&cleaned));
        self.lines.push_back(StepLine {
            stream: self.stream,
            at,
            text,
        });
        if self.lines.len() > MAX_STEP_LINES {
            self.lines.pop_front();
            self.truncated = true;
        }
    }

    /// Ends a final line with no newline, and returns the lines and whether any were dropped.
    fn take(&mut self, at: i64) -> (Vec<StepLine>, bool) {
        if !self.pending.is_empty() || self.pending_over {
            self.end_line(at);
        }
        let lines = Vec::from(std::mem::take(&mut self.lines));
        (lines, std::mem::take(&mut self.truncated))
    }
}

/// Kills every process in the child's group. The group id is the child's pid, because the child
/// was started with `process_group(0)`. A failure (the group is already gone) is ignored.
fn kill_group(pid: Option<u32>) {
    let Some(pid) = pid else {
        return;
    };
    let Ok(raw) = i32::try_from(pid) else {
        return;
    };
    let _ = killpg(Pid::from_raw(raw), Signal::SIGKILL);
}

#[cfg(test)]
pub(crate) mod tests;
