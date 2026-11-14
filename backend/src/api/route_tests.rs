//! Route tests for the spinoff routes of section 10: hubs, sources, source credentials, the
//! credential test, the tag preview, the image lists and the admin scan settings. Each route is
//! checked for the success shape, `401` with no session, the role or tenancy answer, and its
//! error codes. A canary token proves a credential never reaches a response or a log line.

use std::sync::Arc;

use axum::Router;
use axum::http::StatusCode;
use serde_json::{Value, json};

use crate::services::discovery::tests as fake;
use crate::tests::{get_json, send_json, session_cookie, test_router};
use crate::{auth, config, db};

/// A canary registry token. It must appear in no response, log line or audit row.
const CANARY: &str = "dckr_pat_CANARY-0a1b2c3d4e5f";

struct Fixture {
    router: Router,
    pool: sqlx::SqlitePool,
    dir: std::path::PathBuf,
    csrf: String,
    owner: String,
    other: String,
    admin: String,
    anonymous: String,
    script: Arc<fake::Script>,
}

async fn fixture(name: &str) -> Fixture {
    let (router, pool, dir) = test_router(name).await;
    let mut conn = pool.acquire().await.unwrap();
    for (id, role) in [("o1", "user"), ("x2", "user"), ("a3", "admin")] {
        db::users::insert_local(&mut conn, id, id, None, "h", role)
            .await
            .unwrap();
    }
    drop(conn);
    sqlx::query(
        "INSERT INTO user_credentials (id, user_id, label, encrypted_token)
         VALUES ('gc1', 'o1', 'g', 'v1:fake'), ('gc2', 'x2', 'g', 'v1:fake')",
    )
    .execute(&pool)
    .await
    .unwrap();
    let script = Arc::new(fake::Script::default());
    let authority = fake::serve(script.clone()).await;
    sqlx::query("INSERT INTO hubs (id, host, kind) VALUES ('hub-fake', ?, 'custom')")
        .bind(&authority)
        .execute(&pool)
        .await
        .unwrap();
    let root =
        config::parse_encryption_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap();
    let csrf = auth::csrf::issue(&auth::crypto::csrf_key(&root).unwrap()).unwrap();
    let csrf_cookie = format!("{}={csrf}", auth::csrf::CSRF_COOKIE);
    let cookie =
        |user: &str, role: &str| format!("{}; {csrf_cookie}", session_cookie(user, role, 0));
    Fixture {
        owner: cookie("o1", "user"),
        other: cookie("x2", "user"),
        admin: cookie("a3", "admin"),
        anonymous: csrf_cookie.clone(),
        router,
        pool,
        dir,
        csrf,
        script,
    }
}

impl Fixture {
    async fn call(&self, method: &str, uri: &str, who: &str, body: Value) -> (StatusCode, Value) {
        let text = if body.is_null() {
            String::new()
        } else {
            body.to_string()
        };
        send_json(
            &self.router,
            method,
            uri,
            Some(who),
            Some(&self.csrf),
            &text,
        )
        .await
    }

    async fn read(&self, uri: &str, who: &str) -> (StatusCode, Value) {
        get_json(&self.router, uri, who).await
    }

    async fn finish(self) {
        self.pool.close().await;
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn source_body(hub_id: &str, tag: &str) -> Value {
    json!({
        "hub_id": hub_id,
        "repository": "team/app",
        "tag_value": tag,
        "github_cred_id": "gc1",
        "github_owner": "octo",
        "github_repo": "app",
        "default_branch": "main",
        "auto_create_issues": true,
        "min_issue_severity": "HIGH",
    })
}

/// Creates a source for the owner and returns its id.
async fn make_source(fx: &Fixture, tag: &str) -> String {
    let (status, body) = fx
        .call(
            "POST",
            "/api/v1/image-sources",
            &fx.owner,
            source_body("hub-fake", tag),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    body["id"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn hubs_list_create_delete() {
    let fx = fixture("rt-hubs").await;
    // 401 without a session.
    let (status, _) = fx.read("/api/v1/hubs", &fx.anonymous).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // Any session lists; the shape has no display name.
    let (status, body) = fx.read("/api/v1/hubs", &fx.owner).await;
    assert_eq!(status, StatusCode::OK);
    let items = body["items"].as_array().unwrap();
    assert!(items.len() >= 3);
    for hub in items {
        let mut keys: Vec<&str> = hub
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(keys, ["host", "id", "kind", "pull_endpoint"]);
    }
    assert_eq!(items[0]["kind"], "default");

    // Create: admin only.
    let new_hub = json!({ "host": "127.0.0.1:5000", "pull_endpoint": "127.0.0.1:5001" });
    let (status, _) = fx
        .call("POST", "/api/v1/hubs", &fx.anonymous, new_hub.clone())
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = fx
        .call("POST", "/api/v1/hubs", &fx.owner, new_hub.clone())
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, body) = fx
        .call("POST", "/api/v1/hubs", &fx.admin, new_hub.clone())
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["kind"], "custom");
    assert_eq!(body["pull_endpoint"], "127.0.0.1:5001");
    let hub_id = body["id"].as_str().unwrap().to_owned();
    // A second add of the same host is 409.
    let (status, _) = fx.call("POST", "/api/v1/hubs", &fx.admin, new_hub).await;
    assert_eq!(status, StatusCode::CONFLICT);
    // Grammar errors are 422; a malformed body is 400.
    for bad in ["https://x.example", "UPPER.example", "a b", ""] {
        let (status, _) = fx
            .call("POST", "/api/v1/hubs", &fx.admin, json!({ "host": bad }))
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{bad}");
    }
    let (status, _) = fx
        .call("POST", "/api/v1/hubs", &fx.admin, json!({ "nope": 1 }))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Delete: admin only, 404 for a missing hub, 204 for an unused custom hub.
    let uri = format!("/api/v1/hubs/{hub_id}");
    let (status, _) = fx.call("DELETE", &uri, &fx.anonymous, Value::Null).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = fx.call("DELETE", &uri, &fx.owner, Value::Null).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = fx.call("DELETE", &uri, &fx.admin, Value::Null).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = fx.call("DELETE", &uri, &fx.admin, Value::Null).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let audited: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_log WHERE action IN ('hub.create', 'hub.delete')",
    )
    .fetch_one(&fx.pool)
    .await
    .unwrap();
    assert_eq!(audited, 2);
    fx.finish().await;
}

#[tokio::test]
async fn hub_delete_is_409_for_a_default_hub_and_a_hub_in_use() {
    let fx = fixture("rt-hub-409").await;
    for id in ["hub-default-ghcr", "hub-default-docker"] {
        let (status, _) = fx
            .call(
                "DELETE",
                &format!("/api/v1/hubs/{id}"),
                &fx.admin,
                Value::Null,
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{id}");
    }
    make_source(&fx, "1.0").await;
    let (status, _) = fx
        .call("DELETE", "/api/v1/hubs/hub-fake", &fx.admin, Value::Null)
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM hubs")
        .fetch_one(&fx.pool)
        .await
        .unwrap();
    assert_eq!(left, 3);
    fx.finish().await;
}

#[tokio::test]
async fn a_private_address_hub_host_is_refused_at_create() {
    let fx = fixture("rt-hub-private").await;
    for host in [
        "10.0.0.5",
        "169.254.169.254",
        "192.168.1.1:5000",
        "localhost",
    ] {
        let (status, _) = fx
            .call("POST", "/api/v1/hubs", &fx.admin, json!({ "host": host }))
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{host}");
    }
    // A private pull endpoint is refused too.
    let (status, _) = fx
        .call(
            "POST",
            "/api/v1/hubs",
            &fx.admin,
            json!({ "host": "registry.example.org", "pull_endpoint": "10.0.0.5" }),
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    let custom: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM hubs WHERE kind = 'custom'")
        .fetch_one(&fx.pool)
        .await
        .unwrap();
    assert_eq!(custom, 1, "only the fixture hub exists");
    fx.finish().await;
}

#[tokio::test]
async fn hub_create_is_limited_to_60_per_minute_per_user() {
    let fx = fixture("rt-hub-limit").await;
    let mut last = StatusCode::OK;
    for _ in 0..61 {
        let (status, _) = fx
            .call(
                "POST",
                "/api/v1/hubs",
                &fx.admin,
                json!({ "host": "10.0.0.5" }),
            )
            .await;
        last = status;
    }
    assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);
    fx.finish().await;
}

#[tokio::test]
async fn source_crud_tenancy_and_errors() {
    let fx = fixture("rt-sources").await;
    let uri = "/api/v1/image-sources";
    let (status, _) = fx.read(uri, &fx.anonymous).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = fx
        .call("POST", uri, &fx.anonymous, source_body("hub-fake", "1.0"))
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Create: 201, has_credential false, no token field.
    let (status, created) = fx
        .call("POST", uri, &fx.owner, source_body("hub-fake", "1.*"))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_eq!(created["has_credential"], false);
    assert_eq!(created["anonymous_pull"], false);
    assert!(created.get("token").is_none());
    let id = created["id"].as_str().unwrap().to_owned();
    // The same hub, repository and tag value is 409.
    let (status, _) = fx
        .call("POST", uri, &fx.owner, source_body("hub-fake", "1.*"))
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    // 422: bad repository, bad tag, bad severity; 404: unknown hub, foreign GitHub credential.
    let mut bad = source_body("hub-fake", "1.0");
    bad["repository"] = json!("Team/App");
    assert_eq!(
        fx.call("POST", uri, &fx.owner, bad).await.0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(
        fx.call(
            "POST",
            uri,
            &fx.owner,
            source_body("hub-fake", "sha256:abc")
        )
        .await
        .0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let mut bad = source_body("hub-fake", "2.0");
    bad["min_issue_severity"] = json!("LOW");
    assert_eq!(
        fx.call("POST", uri, &fx.owner, bad).await.0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(
        fx.call("POST", uri, &fx.owner, source_body("no-hub", "2.0"))
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    let mut foreign = source_body("hub-fake", "2.0");
    foreign["github_cred_id"] = json!("gc2");
    assert_eq!(
        fx.call("POST", uri, &fx.owner, foreign).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        fx.call("POST", uri, &fx.owner, json!({ "x": 1 })).await.0,
        StatusCode::BAD_REQUEST
    );

    // List: the owner sees it, another user does not, an admin needs scope=all.
    let (_, mine) = fx.read(uri, &fx.owner).await;
    assert_eq!(mine["total"], 1);
    let (_, theirs) = fx.read(uri, &fx.other).await;
    assert_eq!(theirs["total"], 0);
    let (_, admin_default) = fx.read(uri, &fx.admin).await;
    assert_eq!(admin_default["total"], 0);
    let (_, admin_all) = fx.read(&format!("{uri}?scope=all"), &fx.admin).await;
    assert_eq!(admin_all["total"], 1);
    assert_eq!(
        fx.read(&format!("{uri}?scope=all"), &fx.owner).await.0,
        StatusCode::FORBIDDEN
    );

    // Get: owner 200, admin 200 (read), other user 404, missing 404.
    let one = format!("{uri}/{id}");
    assert_eq!(fx.read(&one, &fx.owner).await.0, StatusCode::OK);
    assert_eq!(fx.read(&one, &fx.admin).await.0, StatusCode::OK);
    assert_eq!(fx.read(&one, &fx.other).await.0, StatusCode::NOT_FOUND);
    assert_eq!(
        fx.read(&one, &fx.anonymous).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        fx.read(&format!("{uri}/nope"), &fx.owner).await.0,
        StatusCode::NOT_FOUND
    );

    // Update: owner 200; other 404; admin 403 (read only); duplicate 409.
    let mut edit = source_body("hub-fake", "2.*");
    edit["default_branch"] = json!("release");
    let (status, updated) = fx.call("PUT", &one, &fx.owner, edit.clone()).await;
    assert_eq!(status, StatusCode::OK, "{updated}");
    assert_eq!(updated["tag_value"], "2.*");
    assert_eq!(updated["default_branch"], "release");
    assert_eq!(
        fx.call("PUT", &one, &fx.other, edit.clone()).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        fx.call("PUT", &one, &fx.admin, edit.clone()).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        fx.call("PUT", &one, &fx.anonymous, edit).await.0,
        StatusCode::UNAUTHORIZED
    );
    let (_, second) = fx
        .call("POST", uri, &fx.owner, source_body("hub-fake", "3.0"))
        .await;
    let second_uri = format!("{uri}/{}", second["id"].as_str().unwrap());
    assert_eq!(
        fx.call(
            "PUT",
            &second_uri,
            &fx.owner,
            source_body("hub-fake", "2.*")
        )
        .await
        .0,
        StatusCode::CONFLICT
    );

    // Delete: anonymous 401, other 404, admin 403, owner 204 then 404.
    assert_eq!(
        fx.call("DELETE", &one, &fx.anonymous, Value::Null).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        fx.call("DELETE", &one, &fx.other, Value::Null).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        fx.call("DELETE", &one, &fx.admin, Value::Null).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        fx.call("DELETE", &one, &fx.owner, Value::Null).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        fx.call("DELETE", &one, &fx.owner, Value::Null).await.0,
        StatusCode::NOT_FOUND
    );
    let audited: Vec<String> = sqlx::query_scalar(
        "SELECT action FROM audit_log WHERE action LIKE 'source.%' ORDER BY rowid",
    )
    .fetch_all(&fx.pool)
    .await
    .unwrap();
    assert_eq!(
        audited,
        [
            "source.create",
            "source.update",
            "source.create",
            "source.delete"
        ]
    );
    fx.finish().await;
}

#[tokio::test]
async fn editing_a_value_keeps_recorded_data_and_delete_removes_unobserved_images() {
    let fx = fixture("rt-source-data").await;
    let id = make_source(&fx, "1.*").await;
    for sql in [
        "INSERT INTO images (id, hub_id, repository, digest, is_index)
         VALUES ('img1', 'hub-fake', 'team/app', 'sha256:aa', 0),
                ('img2', 'hub-fake', 'team/app', 'sha256:bb', 0)",
        "INSERT INTO image_platforms (id, image_id, platform, platform_digest, state)
         VALUES ('ffffffffffffffffffffffffffffff01', 'img1', 'linux/amd64', 'sha256:a1', 'stored'),
                ('ffffffffffffffffffffffffffffff02', 'img2', 'linux/amd64', 'sha256:b1', 'stored')",
    ] {
        sqlx::query(sql).execute(&fx.pool).await.unwrap();
    }
    sqlx::query("INSERT INTO tag_observations (source_id, tag, image_id) VALUES (?, ?, ?)")
        .bind(&id)
        .bind("1.0")
        .bind("img1")
        .execute(&fx.pool)
        .await
        .unwrap();
    // Another source also observes img2 only, so it must survive the first delete.
    let (_, other_source) = fx
        .call(
            "POST",
            "/api/v1/image-sources",
            &fx.owner,
            source_body("hub-fake", "9.9"),
        )
        .await;
    let other_id = other_source["id"].as_str().unwrap().to_owned();
    sqlx::query("INSERT INTO tag_observations (source_id, tag, image_id) VALUES (?, ?, ?)")
        .bind(&other_id)
        .bind("9.9")
        .bind("img2")
        .execute(&fx.pool)
        .await
        .unwrap();

    // An edit that no longer matches the recorded tag deletes nothing.
    let one = format!("/api/v1/image-sources/{id}");
    let (status, _) = fx
        .call("PUT", &one, &fx.owner, source_body("hub-fake", "7.*"))
        .await;
    assert_eq!(status, StatusCode::OK);
    let kept: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tag_observations")
        .fetch_one(&fx.pool)
        .await
        .unwrap();
    assert_eq!(kept, 2);

    // Deleting removes img1 (nobody observes it) and keeps img2.
    assert_eq!(
        fx.call("DELETE", &one, &fx.owner, Value::Null).await.0,
        StatusCode::NO_CONTENT
    );
    let images: Vec<String> = sqlx::query_scalar("SELECT id FROM images")
        .fetch_all(&fx.pool)
        .await
        .unwrap();
    assert_eq!(images, ["img2"]);
    fx.finish().await;
}

#[tokio::test]
async fn credential_put_delete_test_and_the_canary() {
    let fx = fixture("rt-credential").await;
    let id = make_source(&fx, "1.0").await;
    let uri = format!("/api/v1/image-sources/{id}/credential");
    let body = json!({ "username": "robot", "token": CANARY, "expires_at": 1_900_000_000 });

    let sink = crate::tests::LogSink::default();
    let writer = sink.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || writer.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    // 401, 404 for another user, 403 for an admin (owner only).
    assert_eq!(
        fx.call("PUT", &uri, &fx.anonymous, body.clone()).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        fx.call("PUT", &uri, &fx.other, body.clone()).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        fx.call("PUT", &uri, &fx.admin, body.clone()).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        fx.call(
            "PUT",
            "/api/v1/image-sources/nope/credential",
            &fx.owner,
            body.clone()
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    // 422: empty username, empty token.
    for bad in [
        json!({ "username": "", "token": CANARY }),
        json!({ "username": "robot", "token": "" }),
    ] {
        let (status, response) = fx.call("PUT", &uri, &fx.owner, bad).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(!response.to_string().contains(CANARY));
    }
    // 201 on create, 200 on replace.
    let (status, created) = fx.call("PUT", &uri, &fx.owner, body.clone()).await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_eq!(created["source_id"], id);
    assert_eq!(created["username"], "robot");
    assert!(created["expires_at"].is_string());
    assert!(created.get("token").is_none());
    let (status, replaced) = fx.call("PUT", &uri, &fx.owner, body.clone()).await;
    assert_eq!(status, StatusCode::OK);
    assert!(!replaced.to_string().contains(CANARY));

    // The stored value is a v1: ciphertext bound to the row, and it decrypts to the token.
    let stored: (String, String) =
        sqlx::query_as("SELECT id, encrypted_token FROM source_credentials WHERE source_id = ?")
            .bind(&id)
            .fetch_one(&fx.pool)
            .await
            .unwrap();
    assert!(stored.1.starts_with("v1:"));
    assert!(!stored.1.contains(CANARY));
    let root =
        config::parse_encryption_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap();
    let key = auth::crypto::credentials_key(&root).unwrap();
    let plain = auth::crypto::decrypt(
        &key,
        &auth::crypto::aad("source_credentials", "encrypted_token", &stored.0),
        &stored.1,
    )
    .unwrap();
    assert_eq!(plain.as_slice(), CANARY.as_bytes());

    // The source reports has_credential, never the token.
    let (_, source) = fx
        .read(&format!("/api/v1/image-sources/{id}"), &fx.owner)
        .await;
    assert_eq!(source["has_credential"], true);

    // The test route: owner only, fixed result, never the token.
    fake::set_tags(&fx.script, "team/app", &["1.0"]);
    fx.script.route("/v2/", fake::Reply::new(200, b"{}"));
    fx.script.route(
        "/v2/team/app/tags/list?n=1",
        fake::Reply::new(200, br#"{"tags":["1.0"]}"#),
    );
    let test_uri = format!("{uri}/test");
    let test_body = json!({ "repository": "team/app" });
    assert_eq!(
        fx.call("POST", &test_uri, &fx.anonymous, test_body.clone())
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        fx.call("POST", &test_uri, &fx.other, test_body.clone())
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        fx.call("POST", &test_uri, &fx.admin, test_body.clone())
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        fx.call(
            "POST",
            &test_uri,
            &fx.owner,
            json!({ "repository": "Bad Name" })
        )
        .await
        .0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let (status, ok) = fx
        .call("POST", &test_uri, &fx.owner, test_body.clone())
        .await;
    assert_eq!(status, StatusCode::OK, "{ok}");
    assert_eq!(ok["ok"], true);
    assert!(ok["detail"].is_string());
    // A registry that refuses the credential is a 200 with ok false and a fixed text.
    fx.script.route(
        "/v2/team/app/tags/list?n=1",
        fake::Reply::new(401, b"{}").header("Www-Authenticate", "Bearer"),
    );
    let (status, refused) = fx
        .call("POST", &test_uri, &fx.owner, test_body.clone())
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(refused["ok"], false);
    assert!(!refused.to_string().contains(CANARY));
    // A registry that cannot be reached is 502.
    fx.script
        .route("/v2/team/app/tags/list?n=1", fake::Reply::new(500, b"{}"));
    let (status, down) = fx.call("POST", &test_uri, &fx.owner, test_body).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert!(!down.to_string().contains(CANARY));

    // Delete: 401, 404 for another user, 204, then 404 (none left).
    assert_eq!(
        fx.call("DELETE", &uri, &fx.anonymous, Value::Null).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        fx.call("DELETE", &uri, &fx.other, Value::Null).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        fx.call("DELETE", &uri, &fx.owner, Value::Null).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        fx.call("DELETE", &uri, &fx.owner, Value::Null).await.0,
        StatusCode::NOT_FOUND
    );
    let (_, source) = fx
        .read(&format!("/api/v1/image-sources/{id}"), &fx.owner)
        .await;
    assert_eq!(source["has_credential"], false);

    // The canary is in no log line and no audit row.
    let logged = String::from_utf8_lossy(&sink.0.lock().unwrap()).to_string();
    assert!(!logged.contains(CANARY), "the token reached the log");
    let audit: Vec<String> =
        sqlx::query_scalar("SELECT COALESCE(details, '') || target FROM audit_log")
            .fetch_all(&fx.pool)
            .await
            .unwrap();
    assert!(audit.iter().all(|row| !row.contains(CANARY)));
    let actions: Vec<String> = sqlx::query_scalar(
        "SELECT action FROM audit_log WHERE action LIKE 'credential.%' ORDER BY rowid",
    )
    .fetch_all(&fx.pool)
    .await
    .unwrap();
    assert_eq!(
        actions,
        [
            "credential.create",
            "credential.rotate",
            "credential.delete"
        ]
    );
    fx.finish().await;
}

#[tokio::test]
async fn ghcr_refuses_a_fine_grained_token_and_docker_hub_works_anonymously() {
    let fx = fixture("rt-ghcr").await;
    let (status, ghcr) = fx
        .call(
            "POST",
            "/api/v1/image-sources",
            &fx.owner,
            source_body("hub-default-ghcr", "1.0"),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let uri = format!(
        "/api/v1/image-sources/{}/credential",
        ghcr["id"].as_str().unwrap()
    );
    let (status, response) = fx
        .call(
            "PUT",
            &uri,
            &fx.owner,
            json!({ "username": "u", "token": format!("github_pat_{CANARY}") }),
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(!response.to_string().contains(CANARY));
    let (status, _) = fx
        .call(
            "PUT",
            &uri,
            &fx.owner,
            json!({ "username": "u", "token": "ghp_classic" }),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);

    // A Docker Hub source with no credential is anonymous and says so.
    let (status, docker) = fx
        .call(
            "POST",
            "/api/v1/image-sources",
            &fx.owner,
            source_body("hub-default-docker", "1.0"),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(docker["has_credential"], false);
    assert_eq!(docker["anonymous_pull"], true);
    fx.finish().await;
}

#[tokio::test]
async fn tag_preview_reads_observations_without_the_registry() {
    let fx = fixture("rt-preview").await;
    let id = make_source(&fx, "1.*").await;
    sqlx::query(
        "INSERT INTO images (id, hub_id, repository, digest, is_index)
         VALUES ('img1', 'hub-fake', 'team/app', 'sha256:aa', 0)",
    )
    .execute(&fx.pool)
    .await
    .unwrap();
    for tag in ["1.0", "1.2.3", "2.0", "latest"] {
        sqlx::query(
            "INSERT INTO tag_observations (source_id, tag, image_id) VALUES (?, ?, 'img1')",
        )
        .bind(&id)
        .bind(tag)
        .execute(&fx.pool)
        .await
        .unwrap();
    }
    let uri = format!("/api/v1/image-sources/{id}/tag-preview");
    assert_eq!(
        fx.read(&uri, &fx.anonymous).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(fx.read(&uri, &fx.other).await.0, StatusCode::NOT_FOUND);
    assert_eq!(fx.read(&uri, &fx.admin).await.0, StatusCode::FORBIDDEN);
    assert_eq!(
        fx.read("/api/v1/image-sources/nope/tag-preview", &fx.owner)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    let (status, body) = fx.read(&uri, &fx.owner).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["matches"], json!(["1.0", "1.2.3"]));
    assert_eq!(body["truncated"], false);
    assert!(fx.script.hits().is_empty(), "the registry was contacted");
    fx.finish().await;
}

#[tokio::test]
async fn tag_preview_is_limited_to_60_per_minute_per_user() {
    let fx = fixture("rt-preview-limit").await;
    let id = make_source(&fx, "1.*").await;
    let uri = format!("/api/v1/image-sources/{id}/tag-preview");
    let mut last = StatusCode::OK;
    for _ in 0..61 {
        last = fx.read(&uri, &fx.owner).await.0;
    }
    assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);
    fx.finish().await;
}

#[tokio::test]
async fn image_lists_show_platform_state_and_scan_status() {
    let fx = fixture("rt-images").await;
    let id = make_source(&fx, "1.*").await;
    let other_id = {
        let mut body = source_body("hub-fake", "5.*");
        body["github_cred_id"] = json!("gc2");
        let (status, created) = fx
            .call("POST", "/api/v1/image-sources", &fx.other, body)
            .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        created["id"].as_str().unwrap().to_owned()
    };
    for sql in [
        "INSERT INTO images (id, hub_id, repository, digest, is_index)
         VALUES ('img1', 'hub-fake', 'team/app', 'sha256:aa', 0),
                ('img2', 'hub-fake', 'team/app', 'sha256:bb', 0)",
        "INSERT INTO image_platforms (id, image_id, platform, platform_digest, state, size_bytes, pulled_at)
         VALUES ('p1', 'img1', 'linux/amd64', 'sha256:a1', 'stored', 1234, 1700000000),
                ('p2', 'img2', 'linux/arm64', 'sha256:b1', 'evicted', 99, 1700000100)",
        "INSERT INTO scan_runs (id, image_platform_id, scanner, scanner_version, db_built_at, trigger, status, error)
         VALUES ('r1', 'p1', 'grype', '0.1', 1700000000, 'first_pull', 'failed', 'scanner failed'),
                ('r2', 'p1', 'grype', '0.1', 1700000500, 'db_update', 'done', NULL),
                ('r3', 'p1', 'trivy', '0.2', 1700000000, 'first_pull', 'queued', NULL)",
    ] {
        sqlx::query(sql).execute(&fx.pool).await.unwrap();
    }
    for (source, tag, image) in [(&id, "1.0", "img1"), (&other_id, "5.0", "img2")] {
        sqlx::query("INSERT INTO tag_observations (source_id, tag, image_id) VALUES (?, ?, ?)")
            .bind(source)
            .bind(tag)
            .bind(image)
            .execute(&fx.pool)
            .await
            .unwrap();
    }
    let per_source = format!("/api/v1/image-sources/{id}/images");
    assert_eq!(
        fx.read(&per_source, &fx.anonymous).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        fx.read(&per_source, &fx.other).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        fx.read("/api/v1/images", &fx.anonymous).await.0,
        StatusCode::UNAUTHORIZED
    );
    let (status, body) = fx.read(&per_source, &fx.owner).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["total"], 1);
    let image = &body["items"][0];
    assert_eq!(image["tags"], json!(["1.0"]));
    let platform = &image["platforms"][0];
    assert_eq!(platform["platform"], "linux/amd64");
    assert_eq!(platform["state"], "stored");
    assert_eq!(platform["size_bytes"], 1234);
    assert!(platform["pulled_at"].is_string());
    let scans = platform["scans"].as_array().unwrap();
    assert_eq!(scans.len(), 2, "the latest run of each scanner");
    assert_eq!(scans[0]["scanner"], "grype");
    assert_eq!(scans[0]["status"], "done");
    assert_eq!(scans[0]["version"], "0.1");
    assert!(scans[0]["db_built_at"].is_string());
    assert_eq!(scans[1]["scanner"], "trivy");
    assert_eq!(scans[1]["status"], "queued");

    // The admin reads any source's images.
    assert_eq!(fx.read(&per_source, &fx.admin).await.0, StatusCode::OK);
    // GET /images is the caller's own, filters by state, and admin scope=all sees both.
    let (_, mine) = fx.read("/api/v1/images", &fx.owner).await;
    assert_eq!(mine["total"], 1);
    let (_, evicted) = fx.read("/api/v1/images?state=evicted", &fx.owner).await;
    assert_eq!(evicted["total"], 0);
    let (_, all) = fx.read("/api/v1/images?scope=all", &fx.admin).await;
    assert_eq!(all["total"], 2);
    let (_, only_other) = fx
        .read(
            &format!("/api/v1/images?scope=all&source_id={other_id}"),
            &fx.admin,
        )
        .await;
    assert_eq!(only_other["total"], 1);
    assert_eq!(only_other["items"][0]["platforms"][0]["state"], "evicted");
    // A user cannot widen the scope; a bad state is 400.
    assert_eq!(
        fx.read("/api/v1/images?scope=all", &fx.owner).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        fx.read("/api/v1/images?state=zzz", &fx.owner).await.0,
        StatusCode::BAD_REQUEST
    );
    fx.finish().await;
}

#[tokio::test]
async fn admin_scan_settings_get_put_and_bounds() {
    let fx = fixture("rt-settings").await;
    let uri = "/api/v1/admin/scan-settings";
    assert_eq!(
        fx.read(uri, &fx.anonymous).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(fx.read(uri, &fx.owner).await.0, StatusCode::FORBIDDEN);
    let (status, current) = fx.read(uri, &fx.admin).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(current["max_stored"], 20);
    assert_eq!(current["scanners_enabled"], json!(["grype", "trivy"]));
    assert_eq!(current["scanner_timeout_s"], 600);
    assert_eq!(current["scanner_output_max_bytes"], 64u64 * 1024 * 1024);
    assert_eq!(current["pull_cap_bytes"], 10u64 * 1024 * 1024 * 1024);
    assert_eq!(current["min_free_disk_bytes"], 10u64 * 1024 * 1024 * 1024);

    let mut next = current.clone();
    next["max_stored"] = json!(5);
    next["scanners_enabled"] = json!(["trivy"]);
    next["scanner_timeout_s"] = json!(120);
    assert_eq!(
        fx.call("PUT", uri, &fx.anonymous, next.clone()).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        fx.call("PUT", uri, &fx.owner, next.clone()).await.0,
        StatusCode::FORBIDDEN
    );
    let (status, saved) = fx.call("PUT", uri, &fx.admin, next.clone()).await;
    assert_eq!(status, StatusCode::OK, "{saved}");
    assert_eq!(saved, next);
    let (_, reread) = fx.read(uri, &fx.admin).await;
    assert_eq!(reread, next);
    // The worker reads the same keys.
    let stored: String =
        sqlx::query_scalar("SELECT value FROM system_config WHERE key = 'images.max_stored'")
            .fetch_one(&fx.pool)
            .await
            .unwrap();
    assert_eq!(stored, "5");
    let details: String =
        sqlx::query_scalar("SELECT details FROM audit_log WHERE action = 'settings.change'")
            .fetch_one(&fx.pool)
            .await
            .unwrap();
    let details: Value = serde_json::from_str(&details).unwrap();
    assert_eq!(details["old"]["max_stored"], 20);
    assert_eq!(details["new"]["max_stored"], 5);

    // 422 for every bound, an unknown scanner and an empty scanner list; 400 for a bad body.
    for (field, value) in [
        ("max_stored", json!(0)),
        ("max_stored", json!(1_000_000)),
        ("scanner_timeout_s", json!(1)),
        ("scanner_output_max_bytes", json!(10)),
        ("pull_cap_bytes", json!(0)),
        ("min_free_disk_bytes", json!(u64::MAX / 2)),
        ("scanners_enabled", json!([])),
        ("scanners_enabled", json!(["clair"])),
    ] {
        let mut bad = next.clone();
        bad[field] = value;
        assert_eq!(
            fx.call("PUT", uri, &fx.admin, bad).await.0,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{field}"
        );
    }
    assert_eq!(
        fx.call("PUT", uri, &fx.admin, json!({ "max_stored": 3 }))
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    let (_, unchanged) = fx.read(uri, &fx.admin).await;
    assert_eq!(unchanged, next);
    fx.finish().await;
}

/// Every route of section 10's table is mounted: a request with no session is `401`, not `404`
/// or `405`.
#[tokio::test]
async fn every_section_10_route_is_mounted() {
    let fx = fixture("rt-coverage").await;
    let routes = [
        ("GET", "/api/v1/hubs"),
        ("POST", "/api/v1/hubs"),
        ("DELETE", "/api/v1/hubs/x"),
        ("GET", "/api/v1/image-sources"),
        ("POST", "/api/v1/image-sources"),
        ("GET", "/api/v1/image-sources/x"),
        ("PUT", "/api/v1/image-sources/x"),
        ("DELETE", "/api/v1/image-sources/x"),
        ("PUT", "/api/v1/image-sources/x/credential"),
        ("DELETE", "/api/v1/image-sources/x/credential"),
        ("POST", "/api/v1/image-sources/x/credential/test"),
        ("GET", "/api/v1/image-sources/x/tag-preview"),
        ("POST", "/api/v1/image-sources/x/scan"),
        ("POST", "/api/v1/image-sources/x/tags/1.0/pull"),
        ("POST", "/api/v1/image-sources/x/tags/1.0/scan"),
        ("GET", "/api/v1/image-sources/x/images"),
        ("GET", "/api/v1/images"),
        ("GET", "/api/v1/admin/scan-settings"),
        ("PUT", "/api/v1/admin/scan-settings"),
    ];
    for (method, uri) in routes {
        let (status, _) = fx.call(method, uri, &fx.anonymous, Value::Null).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{method} {uri}");
    }
    // A state-changing route without the CSRF token is 403.
    let (status, _) = send_json(
        &fx.router,
        "POST",
        "/api/v1/hubs",
        Some(&fx.admin),
        None,
        r#"{"host":"x.example"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    fx.finish().await;
}

/// The job log route (#308). Seeds an owned `scan` job with one step and one line, and an admin
/// `db_update` job, and checks access, the shape, paging and a running job.
mod job_log {
    use super::*;

    /// Adds a `scan` job owned by `o1` (through source `s-log`), and an admin `db_update` job.
    async fn seed(fx: &Fixture) {
        sqlx::query(
            "INSERT INTO image_sources (id, user_id, hub_id, repository, tag_value, github_cred_id,
                 github_owner, github_repo)
             VALUES ('s-log', 'o1', 'hub-fake', 'team/app', '*', 'gc1', 'octo', 'app')",
        )
        .execute(&fx.pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO jobs (id, source_id, status, attempts, payload)
             VALUES ('job-scan', 's-log', 'done', 0, '{\"kind\":\"scan\"}'),
                    ('job-db', NULL, 'done', 0, '{\"kind\":\"db_update\",\"scanner\":\"trivy\"}')",
        )
        .execute(&fx.pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO job_log_steps (id, job_id, attempt, seq, command, started_at, finished_at,
                 timeout_secs, outcome, exit_code, truncated)
             VALUES ('st-scan', 'job-scan', 1, 0, 'trivy scan', 100, 103, 600, 'failed', 3, 0),
                    ('st-db', 'job-db', 1, 0, 'trivy image --download-db-only', 200, 230, 600, 'ok', 0, 1)",
        )
        .execute(&fx.pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO job_log_lines (step_id, at, stream, text) VALUES
                 ('st-scan', 101, 'stderr', 'first'),
                 ('st-scan', 102, 'stderr', 'second'),
                 ('st-db', 201, 'stderr', 'db line')",
        )
        .execute(&fx.pool)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn the_log_route_checks_session_access_and_existence() {
        let fx = fixture("job-log-access").await;
        seed(&fx).await;
        let anon = fx.read("/api/v1/jobs/job-scan/log", &fx.anonymous).await.0;
        assert_eq!(anon, StatusCode::UNAUTHORIZED);
        // Another user is refused as a missing job, so the id is not revealed.
        let other = fx.read("/api/v1/jobs/job-scan/log", &fx.other).await.0;
        assert_eq!(other, StatusCode::NOT_FOUND);
        let missing = fx.read("/api/v1/jobs/no-such/log", &fx.owner).await.0;
        assert_eq!(missing, StatusCode::NOT_FOUND);
        // A user has no right to a db_update job, which has no owner.
        let user_db = fx.read("/api/v1/jobs/job-db/log", &fx.owner).await.0;
        assert_eq!(user_db, StatusCode::NOT_FOUND);
        let admin_db = fx.read("/api/v1/jobs/job-db/log", &fx.admin).await.0;
        assert_eq!(admin_db, StatusCode::OK);
        fx.finish().await;
    }

    #[tokio::test]
    async fn the_log_route_returns_the_shape_with_steps_and_lines() {
        let fx = fixture("job-log-shape").await;
        seed(&fx).await;
        let (status, body) = fx.read("/api/v1/jobs/job-scan/log", &fx.owner).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["job_id"], "job-scan");
        assert_eq!(body["kind"], "scan");
        assert_eq!(body["status"], "done");
        assert_eq!(body["attempt"], 1);
        let step = &body["steps"][0];
        assert_eq!(step["seq"], 0);
        assert_eq!(step["command"], "trivy scan");
        assert_eq!(step["outcome"], "failed");
        assert_eq!(step["exit_code"], 3);
        assert_eq!(step["truncated"], false);
        let line = &body["lines"][0];
        assert_eq!(line["seq"], 0);
        assert_eq!(line["stream"], "stderr");
        assert_eq!(line["text"], "first");
        assert!(line["id"].is_i64());
        assert!(line["at"].is_string(), "{line}");
        fx.finish().await;
    }

    #[tokio::test]
    async fn after_pages_return_only_later_lines_and_a_next_cursor() {
        let fx = fixture("job-log-paging").await;
        seed(&fx).await;
        let (_, first) = fx.read("/api/v1/jobs/job-scan/log", &fx.owner).await;
        let last_id = first["lines"][1]["id"].as_i64().unwrap_or_default();
        assert_eq!(first["next_after"], last_id);
        let uri = format!("/api/v1/jobs/job-scan/log?after={last_id}");
        let (status, page) = fx.read(&uri, &fx.owner).await;
        assert_eq!(status, StatusCode::OK, "{page}");
        assert_eq!(page["lines"].as_array().map(Vec::len), Some(0));
        fx.finish().await;
    }

    #[tokio::test]
    async fn a_running_job_returns_its_partial_steps_and_a_running_step() {
        let fx = fixture("job-log-running").await;
        seed(&fx).await;
        sqlx::query("UPDATE jobs SET status = 'running' WHERE id = 'job-scan'")
            .execute(&fx.pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO job_log_steps (id, job_id, attempt, seq, command, started_at, timeout_secs, outcome)
             VALUES ('st-run', 'job-scan', 1, 1, 'trivy scan', 300, 600, 'running')",
        )
        .execute(&fx.pool)
        .await
        .unwrap();
        let (status, body) = fx.read("/api/v1/jobs/job-scan/log", &fx.owner).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["status"], "running");
        let outcomes: Vec<&str> = body["steps"]
            .as_array()
            .map(|steps| steps.iter().filter_map(|s| s["outcome"].as_str()).collect())
            .unwrap_or_default();
        assert_eq!(outcomes, vec!["failed", "running"]);
        assert!(body["steps"][1]["finished_at"].is_null());
        fx.finish().await;
    }
}

/// The display name of a source (#323): create returns it, update changes it, a name over 80
/// characters or with a control character is `422`, and an empty name is stored as null.
#[tokio::test]
async fn source_display_name_create_update_and_limits() {
    let fx = fixture("rt-source-name").await;
    let uri = "/api/v1/image-sources";

    // Create with a name returns it, trimmed.
    let mut named = source_body("hub-fake", "3.0");
    named["name"] = json!("  Team app  ");
    let (status, created) = fx.call("POST", uri, &fx.owner, named).await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_eq!(created["name"], "Team app");
    let id = created["id"].as_str().unwrap().to_owned();

    // Update changes it.
    let one = format!("/api/v1/image-sources/{id}");
    let mut renamed = source_body("hub-fake", "3.0");
    renamed["name"] = json!("Payments");
    let (status, updated) = fx.call("PUT", &one, &fx.owner, renamed).await;
    assert_eq!(status, StatusCode::OK, "{updated}");
    assert_eq!(updated["name"], "Payments");
    let (_, read) = fx.read(&one, &fx.owner).await;
    assert_eq!(read["name"], "Payments");

    // 80 characters is allowed; 81 is rejected.
    let mut long_ok = source_body("hub-fake", "4.0");
    long_ok["name"] = json!("a".repeat(80));
    assert_eq!(
        fx.call("POST", uri, &fx.owner, long_ok).await.0,
        StatusCode::CREATED
    );
    let mut too_long = source_body("hub-fake", "5.0");
    too_long["name"] = json!("a".repeat(81));
    assert_eq!(
        fx.call("POST", uri, &fx.owner, too_long).await.0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let mut control = source_body("hub-fake", "6.0");
    control["name"] = json!("bad\u{7}name");
    assert_eq!(
        fx.call("POST", uri, &fx.owner, control).await.0,
        StatusCode::UNPROCESSABLE_ENTITY
    );

    // Empty (or blank) is unset: stored as null and returned as null.
    let mut empty = source_body("hub-fake", "7.0");
    empty["name"] = json!("   ");
    let (status, blank) = fx.call("POST", uri, &fx.owner, empty).await;
    assert_eq!(status, StatusCode::CREATED, "{blank}");
    assert!(blank["name"].is_null());
    let stored: Option<String> = sqlx::query_scalar("SELECT name FROM image_sources WHERE id = ?")
        .bind(blank["id"].as_str().unwrap())
        .fetch_one(&fx.pool)
        .await
        .unwrap();
    assert_eq!(stored, None);
    fx.finish().await;
}

/// Queuing a discover job when a source is created or its repository, tag or hub changes (#331).
mod discovery_on_save {
    use super::*;

    /// The statuses of the discover jobs scoped to one source, oldest first.
    async fn scoped_jobs(fx: &Fixture, source_id: &str) -> Vec<String> {
        sqlx::query_scalar(
            "SELECT status FROM jobs
             WHERE json_extract(payload, '$.kind') = 'discover' AND source_id = ? ORDER BY rowid",
        )
        .bind(source_id)
        .fetch_all(&fx.pool)
        .await
        .unwrap()
    }

    async fn all_discover_jobs(fx: &Fixture) -> i64 {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM jobs WHERE json_extract(payload, '$.kind') = 'discover'",
        )
        .fetch_one(&fx.pool)
        .await
        .unwrap()
    }

    /// Marks the source's jobs done, as the worker would after a run.
    async fn settle(fx: &Fixture, source_id: &str) {
        sqlx::query("UPDATE jobs SET status = 'done' WHERE source_id = ?")
            .bind(source_id)
            .execute(&fx.pool)
            .await
            .unwrap();
    }

    async fn put(fx: &Fixture, id: &str, body: Value) -> StatusCode {
        let uri = format!("/api/v1/image-sources/{id}");
        fx.call("PUT", &uri, &fx.owner, body).await.0
    }

    #[tokio::test]
    async fn creating_a_source_queues_one_scoped_discover_job() {
        let fx = fixture("rt-discover-create").await;
        let id = make_source(&fx, "1.*").await;
        assert_eq!(scoped_jobs(&fx, &id).await, vec!["queued".to_owned()]);
        let payload: String = sqlx::query_scalar("SELECT payload FROM jobs WHERE source_id = ?")
            .bind(&id)
            .fetch_one(&fx.pool)
            .await
            .unwrap();
        let value: Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(value["kind"], "discover");
        assert_eq!(value["hub_id"], "hub-fake");
        assert_eq!(value["repository"], "team/app");
        assert_eq!(value["source_id"], id.as_str());
        fx.finish().await;
    }

    async fn status_of(fx: &Fixture, uri: &str) -> String {
        let (code, body) = fx.read(uri, &fx.owner).await;
        assert_eq!(code, StatusCode::OK, "{body}");
        body["discovery_status"].as_str().unwrap().to_owned()
    }

    #[tokio::test]
    async fn the_source_shows_its_discovery_job_as_queued_then_running_then_idle() {
        let fx = fixture("rt-discover-status").await;
        let id = make_source(&fx, "1.*").await;
        let uri = format!("/api/v1/image-sources/{id}");
        assert_eq!(status_of(&fx, &uri).await, "queued");
        let (_, list) = fx.read("/api/v1/image-sources", &fx.owner).await;
        assert_eq!(list["items"][0]["discovery_status"], "queued");
        sqlx::query("UPDATE jobs SET status = 'running' WHERE source_id = ?")
            .bind(&id)
            .execute(&fx.pool)
            .await
            .unwrap();
        assert_eq!(status_of(&fx, &uri).await, "running");
        settle(&fx, &id).await;
        assert_eq!(status_of(&fx, &uri).await, "idle");
        fx.finish().await;
    }

    /// Box 2 of #331: the real worker claims the job the create handler queued, runs it against
    /// the fake registry, and the source then carries its images and last discovery time.
    #[tokio::test]
    async fn the_worker_runs_the_queued_discovery_and_the_source_shows_the_result() {
        use crate::services::discovery::handler::SpinoffJobs;
        use crate::worker::{self, Step};

        let fx = fixture("rt-discover-worker").await;
        fake::set_tags(&fx.script, "team/app", &["1.0", "1.1", "2.0"]);
        fake::put_single(&fx.script, "team/app", "1.0", "amd64", "a");
        fake::put_single(&fx.script, "team/app", "1.1", "amd64", "b");
        fake::put_single(&fx.script, "team/app", "2.0", "amd64", "c");

        let id = make_source(&fx, "1.*").await;
        let uri = format!("/api/v1/image-sources/{id}");
        let (_, before) = fx.read(&uri, &fx.owner).await;
        assert_eq!(before["discovery_status"], "queued");
        assert!(before["last_discovery_at"].is_null());

        let key = Arc::new(
            auth::crypto::credentials_key(
                &config::parse_encryption_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
                    .unwrap(),
            )
            .unwrap(),
        );
        let store = crate::services::storage::StoreRoot::at(fx.dir.join("images"));
        let handler = Arc::new(SpinoffJobs::new(
            crate::services::discovery::Discovery::for_test_with_pool(fx.pool.clone()),
            crate::services::alerts::Notifier::new(fx.pool.clone(), key.clone(), false),
            fx.pool.clone(),
            store.clone(),
            crate::services::scan::ScanEnv::under(&fx.dir),
            crate::services::publish::Publisher::new(
                fx.pool.clone(),
                key,
                store,
                crate::services::github_url::GithubTarget::default(),
            )
            .unwrap(),
        ));
        // One normal worker iteration: it claims the oldest due job, the discover job.
        let step = worker::tick(&fx.pool, &handler, worker::now_secs())
            .await
            .unwrap();
        assert_eq!(step, Step::Done);

        let (_, after) = fx.read(&uri, &fx.owner).await;
        assert_eq!(after["discovery_status"], "idle");
        assert!(after["last_discovery_at"].is_string(), "{after}");
        let (code, images) = fx.read(&format!("{uri}/images"), &fx.owner).await;
        assert_eq!(code, StatusCode::OK, "{images}");
        assert_eq!(images["total"], 2, "{images}");
        fx.finish().await;
    }

    #[tokio::test]
    async fn updating_the_repository_tag_or_hub_queues_one_scoped_job() {
        let fx = fixture("rt-discover-update").await;
        let id = make_source(&fx, "1.*").await;
        settle(&fx, &id).await;

        assert_eq!(
            put(&fx, &id, source_body("hub-fake", "1.*")).await,
            StatusCode::OK
        );
        // Unchanged save: nothing new.
        assert_eq!(scoped_jobs(&fx, &id).await, vec!["done".to_owned()]);

        let mut repo = source_body("hub-fake", "1.*");
        repo["repository"] = json!("team/other");
        assert_eq!(put(&fx, &id, repo).await, StatusCode::OK);
        assert_eq!(
            scoped_jobs(&fx, &id).await,
            vec!["done".to_owned(), "queued".to_owned()]
        );
        settle(&fx, &id).await;

        let mut tag = source_body("hub-fake", "2.*");
        tag["repository"] = json!("team/other");
        assert_eq!(put(&fx, &id, tag).await, StatusCode::OK);
        assert_eq!(scoped_jobs(&fx, &id).await.len(), 3);
        assert_eq!(scoped_jobs(&fx, &id).await[2], "queued");
        settle(&fx, &id).await;

        sqlx::query("INSERT INTO hubs (id, host, kind) VALUES ('hub-b', 'b.example', 'custom')")
            .execute(&fx.pool)
            .await
            .unwrap();
        let mut hub = source_body("hub-b", "2.*");
        hub["repository"] = json!("team/other");
        assert_eq!(put(&fx, &id, hub).await, StatusCode::OK);
        assert_eq!(scoped_jobs(&fx, &id).await.len(), 4);
        assert_eq!(scoped_jobs(&fx, &id).await[3], "queued");
        fx.finish().await;
    }

    #[tokio::test]
    async fn a_rename_only_update_queues_no_job() {
        let fx = fixture("rt-discover-rename").await;
        let id = make_source(&fx, "1.*").await;
        settle(&fx, &id).await;
        let mut renamed = source_body("hub-fake", "1.*");
        renamed["name"] = json!("Payments");
        assert_eq!(put(&fx, &id, renamed).await, StatusCode::OK);
        assert_eq!(scoped_jobs(&fx, &id).await, vec!["done".to_owned()]);
        fx.finish().await;
    }

    #[tokio::test]
    async fn a_failed_repository_job_does_not_block_a_new_source() {
        let fx = fixture("rt-discover-failed").await;
        // The hourly scheduler's job for the repository has failed.
        let repo_payload =
            crate::services::discovery::DiscoverPayload::new("hub-fake", "team/app", None)
                .to_text()
                .unwrap();
        sqlx::query(
            "INSERT INTO jobs (id, source_id, status, attempts, payload)
             VALUES ('failed-repo', NULL, 'failed', 8, ?)",
        )
        .bind(&repo_payload)
        .execute(&fx.pool)
        .await
        .unwrap();
        let id = make_source(&fx, "1.*").await;
        assert_eq!(scoped_jobs(&fx, &id).await, vec!["queued".to_owned()]);
        fx.finish().await;
    }

    #[tokio::test]
    async fn a_rejected_create_or_update_queues_nothing() {
        let fx = fixture("rt-discover-rejected").await;
        let mut bad = source_body("hub-fake", "1.*");
        bad["min_issue_severity"] = json!("LOW");
        let (status, _) = fx
            .call("POST", "/api/v1/image-sources", &fx.owner, bad)
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        let mut unknown = source_body("hub-fake", "1.*");
        unknown["github_cred_id"] = json!("nope");
        let (status, _) = fx
            .call("POST", "/api/v1/image-sources", &fx.owner, unknown)
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(all_discover_jobs(&fx).await, 0);

        let id = make_source(&fx, "1.*").await;
        settle(&fx, &id).await;
        let mut bad_update = source_body("hub-fake", "1.*");
        bad_update["repository"] = json!("team/other");
        bad_update["min_issue_severity"] = json!("LOW");
        assert_eq!(
            put(&fx, &id, bad_update).await,
            StatusCode::UNPROCESSABLE_ENTITY
        );
        let mut unknown_update = source_body("hub-fake", "2.*");
        unknown_update["github_cred_id"] = json!("nope");
        assert_eq!(put(&fx, &id, unknown_update).await, StatusCode::NOT_FOUND);
        assert_eq!(all_discover_jobs(&fx).await, 1);
        assert_eq!(scoped_jobs(&fx, &id).await, vec!["done".to_owned()]);
        fx.finish().await;
    }

    #[tokio::test]
    async fn saving_twice_while_the_job_is_queued_creates_no_second_job() {
        let fx = fixture("rt-discover-dup").await;
        let id = make_source(&fx, "1.*").await;
        assert_eq!(
            put(&fx, &id, source_body("hub-fake", "1.*")).await,
            StatusCode::OK
        );
        assert_eq!(
            put(&fx, &id, source_body("hub-fake", "2.*")).await,
            StatusCode::OK
        );
        assert_eq!(scoped_jobs(&fx, &id).await, vec!["queued".to_owned()]);
        fx.finish().await;
    }
}

/// Manual pull and forced scan of one tag (#335): `POST /api/v1/image-sources/{id}/tags/{tag}/pull`
/// and `.../scan`.
mod tag_actions {
    use super::*;

    const PA: &str = "000000000000000000000000000000c1";
    const PB: &str = "000000000000000000000000000000c2";
    const PO: &str = "000000000000000000000000000000c3";

    /// A source of the owner whose tag `1.0` points at `img1` with two platforms (one stored,
    /// one evicted), and whose tag `1.1` points at `img2` with one stored platform. The stored
    /// platforms have done runs of both scanners. The source's discover job is settled.
    async fn seeded(name: &str) -> (Fixture, String) {
        let fx = fixture(name).await;
        let id = make_source(&fx, "1.*").await;
        for sql in [
            "UPDATE jobs SET status = 'done'",
            "INSERT INTO images (id, hub_id, repository, digest, is_index)
             VALUES ('img1', 'hub-fake', 'team/app', 'sha256:aa', 1),
                    ('img2', 'hub-fake', 'team/app', 'sha256:bb', 0)",
        ] {
            sqlx::query(sql).execute(&fx.pool).await.unwrap();
        }
        for (pid, image, platform, state) in [
            (PA, "img1", "linux/amd64", "stored"),
            (PB, "img1", "linux/arm64", "evicted"),
            (PO, "img2", "linux/amd64", "stored"),
        ] {
            sqlx::query(
                "INSERT INTO image_platforms (id, image_id, platform, platform_digest, state, pulled_at)
                 VALUES (?, ?, ?, ?, ?, 5)",
            )
            .bind(pid)
            .bind(image)
            .bind(platform)
            .bind(format!("sha256:{pid}"))
            .bind(state)
            .execute(&fx.pool)
            .await
            .unwrap();
        }
        for (run, pid, scanner) in [
            ("ra", PA, "grype"),
            ("rb", PA, "trivy"),
            ("rc", PO, "grype"),
            ("rd", PO, "trivy"),
        ] {
            sqlx::query(
                "INSERT INTO scan_runs (id, image_platform_id, scanner, trigger, status, finished_at)
                 VALUES (?, ?, ?, 'first_pull', 'done', 10)",
            )
            .bind(run)
            .bind(pid)
            .bind(scanner)
            .execute(&fx.pool)
            .await
            .unwrap();
        }
        for (tag, image) in [("1.0", "img1"), ("1.1", "img2")] {
            sqlx::query("INSERT INTO tag_observations (source_id, tag, image_id) VALUES (?, ?, ?)")
                .bind(&id)
                .bind(tag)
                .bind(image)
                .execute(&fx.pool)
                .await
                .unwrap();
        }
        (fx, id)
    }

    fn uri(id: &str, tag: &str, action: &str) -> String {
        format!("/api/v1/image-sources/{id}/tags/{tag}/{action}")
    }

    /// `(platform_id, trigger)` of every queued pull job, by platform.
    async fn pull_jobs(fx: &Fixture) -> Vec<(String, String)> {
        sqlx::query_as(
            "SELECT json_extract(payload, '$.platform_id'), json_extract(payload, '$.trigger')
             FROM jobs WHERE json_extract(payload, '$.kind') = 'pull' AND status = 'queued'
             ORDER BY 1",
        )
        .fetch_all(&fx.pool)
        .await
        .unwrap()
    }

    /// `(platform_id, scanner)` of every manual scan run, by platform and scanner.
    async fn manual_runs(fx: &Fixture) -> Vec<(String, String)> {
        sqlx::query_as(
            "SELECT image_platform_id, scanner FROM scan_runs WHERE trigger = 'manual'
             ORDER BY 1, 2",
        )
        .fetch_all(&fx.pool)
        .await
        .unwrap()
    }

    async fn audit_count(fx: &Fixture, action: &str) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE action = ?")
            .bind(action)
            .fetch_one(&fx.pool)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn tag_action_on_other_users_source_is_404() {
        let (fx, id) = seeded("rt-tag-other").await;
        for action in ["pull", "scan"] {
            let (status, _) = fx
                .call("POST", &uri(&id, "1.0", action), &fx.other, Value::Null)
                .await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{action}");
            let (missing, _) = fx
                .call("POST", &uri("nope", "1.0", action), &fx.owner, Value::Null)
                .await;
            assert_eq!(missing, StatusCode::NOT_FOUND, "{action} missing source");
            let (anon, _) = fx
                .call("POST", &uri(&id, "1.0", action), &fx.anonymous, Value::Null)
                .await;
            assert_eq!(anon, StatusCode::UNAUTHORIZED, "{action} anonymous");
        }
        assert!(pull_jobs(&fx).await.is_empty());
        assert!(manual_runs(&fx).await.is_empty());
        // The refused calls used no slot: the owner may still act on the tag.
        let (status, _) = fx
            .call("POST", &uri(&id, "1.0", "scan"), &fx.owner, Value::Null)
            .await;
        assert_eq!(status, StatusCode::OK);
        fx.finish().await;
    }

    #[tokio::test]
    async fn tag_not_observed_is_404_and_uses_no_limiter_slot() {
        let (fx, id) = seeded("rt-tag-unobserved").await;
        for action in ["pull", "scan"] {
            for _ in 0..2 {
                let (status, _) = fx
                    .call("POST", &uri(&id, "2.0", action), &fx.owner, Value::Null)
                    .await;
                assert_eq!(status, StatusCode::NOT_FOUND, "{action}");
            }
        }
        // A tag outside the grammar is 404 as well, never a registry call.
        let (bad, _) = fx
            .call("POST", &uri(&id, "-bad", "pull"), &fx.owner, Value::Null)
            .await;
        assert_eq!(bad, StatusCode::NOT_FOUND);
        // Once discovery observes the tag, the first call of each action is allowed.
        sqlx::query(
            "INSERT INTO tag_observations (source_id, tag, image_id) VALUES (?, '2.0', 'img2')",
        )
        .bind(&id)
        .execute(&fx.pool)
        .await
        .unwrap();
        for action in ["pull", "scan"] {
            let (status, body) = fx
                .call("POST", &uri(&id, "2.0", action), &fx.owner, Value::Null)
                .await;
            assert_eq!(status, StatusCode::OK, "{action}: {body}");
        }
        fx.finish().await;
    }

    #[tokio::test]
    async fn same_tag_twice_is_429_other_tag_ok() {
        let (fx, id) = seeded("rt-tag-limit").await;
        for action in ["pull", "scan"] {
            let (first, _) = fx
                .call("POST", &uri(&id, "1.0", action), &fx.owner, Value::Null)
                .await;
            assert_eq!(first, StatusCode::OK, "{action}");
            let (second, _) = fx
                .call("POST", &uri(&id, "1.0", action), &fx.owner, Value::Null)
                .await;
            assert_eq!(second, StatusCode::TOO_MANY_REQUESTS, "{action}");
            let (other_tag, _) = fx
                .call("POST", &uri(&id, "1.1", action), &fx.owner, Value::Null)
                .await;
            assert_eq!(other_tag, StatusCode::OK, "{action} other tag");
        }
        // The tag limiter does not use the source-wide "Scan now" slot.
        let (scan_now, body) = fx
            .call(
                "POST",
                &format!("/api/v1/image-sources/{id}/scan"),
                &fx.owner,
                Value::Null,
            )
            .await;
        assert_ne!(scan_now, StatusCode::TOO_MANY_REQUESTS, "{body}");
        fx.finish().await;
    }

    #[tokio::test]
    async fn admin_allowed() {
        let (fx, id) = seeded("rt-tag-admin").await;
        let (pull, body) = fx
            .call("POST", &uri(&id, "1.0", "pull"), &fx.admin, Value::Null)
            .await;
        assert_eq!(pull, StatusCode::OK, "{body}");
        assert_eq!(body, json!({"queued": 2}));
        let (scan, body) = fx
            .call("POST", &uri(&id, "1.0", "scan"), &fx.admin, Value::Null)
            .await;
        assert_eq!(scan, StatusCode::OK, "{body}");
        assert_eq!(audit_count(&fx, "source.tag_pull").await, 1);
        assert_eq!(audit_count(&fx, "source.tag_scan").await, 1);
        fx.finish().await;
    }

    #[tokio::test]
    async fn pull_queues_one_job_per_platform_with_trigger_manual() {
        let (fx, id) = seeded("rt-tag-pull").await;
        let (status, body) = fx
            .call("POST", &uri(&id, "1.0", "pull"), &fx.owner, Value::Null)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body, json!({"queued": 2}));
        assert_eq!(
            pull_jobs(&fx).await,
            vec![
                (PA.to_owned(), "manual".to_owned()),
                (PB.to_owned(), "manual".to_owned()),
            ]
        );
        // The evicted platform waits for its pull again; the stored one is unchanged.
        let states: Vec<(String, String)> = sqlx::query_as(
            "SELECT id, state FROM image_platforms WHERE image_id = 'img1' ORDER BY id",
        )
        .fetch_all(&fx.pool)
        .await
        .unwrap();
        assert_eq!(
            states,
            vec![
                (PA.to_owned(), "stored".to_owned()),
                (PB.to_owned(), "queued".to_owned()),
            ]
        );
        // The other tag's image is untouched, and no scan was forced.
        let other: String = sqlx::query_scalar("SELECT state FROM image_platforms WHERE id = ?")
            .bind(PO)
            .fetch_one(&fx.pool)
            .await
            .unwrap();
        assert_eq!(other, "stored");
        assert!(manual_runs(&fx).await.is_empty());
        let details: String =
            sqlx::query_scalar("SELECT details FROM audit_log WHERE action = 'source.tag_pull'")
                .fetch_one(&fx.pool)
                .await
                .unwrap();
        let details: Value = serde_json::from_str(&details).unwrap();
        assert_eq!(details, json!({"source_id": id, "tag": "1.0", "queued": 2}));
        fx.finish().await;
    }

    #[tokio::test]
    async fn pull_is_409_while_a_platform_is_pulling_or_evicting() {
        let (fx, id) = seeded("rt-tag-busy").await;
        for state in ["pulling", "evicting"] {
            sqlx::query("UPDATE image_platforms SET state = ? WHERE id = ?")
                .bind(state)
                .bind(PB)
                .execute(&fx.pool)
                .await
                .unwrap();
            let (status, body) = fx
                .call("POST", &uri(&id, "1.0", "pull"), &fx.owner, Value::Null)
                .await;
            assert_eq!(status, StatusCode::CONFLICT, "{state}: {body}");
        }
        assert!(pull_jobs(&fx).await.is_empty());
        assert_eq!(audit_count(&fx, "source.tag_pull").await, 0);
        // The refusals used no limiter slot: once the eviction ends, the pull is allowed.
        sqlx::query("UPDATE image_platforms SET state = 'evicted' WHERE id = ?")
            .bind(PB)
            .execute(&fx.pool)
            .await
            .unwrap();
        let (status, body) = fx
            .call("POST", &uri(&id, "1.0", "pull"), &fx.owner, Value::Null)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        fx.finish().await;
    }

    #[tokio::test]
    async fn scan_forces_a_run_of_every_enabled_scanner_on_the_stored_platforms() {
        let (fx, id) = seeded("rt-tag-scan").await;
        let (status, body) = fx
            .call("POST", &uri(&id, "1.0", "scan"), &fx.owner, Value::Null)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        // The evicted platform has nothing to scan; the stored one is scanned again by both.
        assert_eq!(body, json!({"queued": 2}));
        assert_eq!(
            manual_runs(&fx).await,
            vec![
                (PA.to_owned(), "grype".to_owned()),
                (PA.to_owned(), "trivy".to_owned()),
            ]
        );
        let details: String =
            sqlx::query_scalar("SELECT details FROM audit_log WHERE action = 'source.tag_scan'")
                .fetch_one(&fx.pool)
                .await
                .unwrap();
        let details: Value = serde_json::from_str(&details).unwrap();
        assert_eq!(details, json!({"source_id": id, "tag": "1.0", "queued": 2}));
        fx.finish().await;
    }
}

/// `DELETE /api/v1/admin/image-sources/{source_id}/cves/{cve_id}` (#349).
mod cve_delete {
    use super::*;

    const GHSA: &str = "GHSA-8rvm-662m-jvqv";

    fn uri(source: &str, cve: &str) -> String {
        format!("/api/v1/admin/image-sources/{source}/cves/{cve}")
    }

    async fn exec(fx: &Fixture, sql: &'static str, binds: &[&str]) {
        let mut query = sqlx::query(sql);
        for bind in binds {
            query = query.bind((*bind).to_owned());
        }
        query.execute(&fx.pool).await.unwrap();
    }

    async fn count(fx: &Fixture, sql: &'static str, binds: &[&str]) -> i64 {
        let mut query = sqlx::query_scalar(sql);
        for bind in binds {
            query = query.bind((*bind).to_owned());
        }
        query.fetch_one(&fx.pool).await.unwrap()
    }

    /// Source A (tag 1.0, image img1, run ra) and source B (tag 2.0, image img2, run rb), both
    /// holding `cve_findings` and `scanner_findings` for GHSA-... and for CVE-2026-0002. A
    /// `github_issues` row for the GHSA is pointed at by both sources' findings.
    async fn seeded(name: &str) -> (Fixture, String, String) {
        let fx = fixture(name).await;
        let a = make_source(&fx, "1.*").await;
        let b = make_source(&fx, "2.*").await;
        exec(
            &fx,
            "INSERT INTO images (id, hub_id, repository, digest, is_index)
             VALUES ('img1', 'hub-fake', 'team/app', 'sha256:aa', 0),
                    ('img2', 'hub-fake', 'team/app', 'sha256:bb', 0)",
            &[],
        )
        .await;
        for (pid, image) in [("pa", "img1"), ("pb", "img2")] {
            exec(
                &fx,
                "INSERT INTO image_platforms (id, image_id, platform, platform_digest, state)
                 VALUES (?, ?, 'linux/amd64', ?, 'stored')",
                &[pid, image, pid],
            )
            .await;
        }
        for (run, pid) in [("ra", "pa"), ("rb", "pb")] {
            exec(
                &fx,
                "INSERT INTO scan_runs (id, image_platform_id, scanner, trigger, status, finished_at)
                 VALUES (?, ?, 'grype', 'first_pull', 'done', 10)",
                &[run, pid],
            )
            .await;
            for cve in [GHSA, "CVE-2026-0002"] {
                exec(
                    &fx,
                    "INSERT INTO scanner_findings (run_id, cve_id, package, severity)
                     VALUES (?, ?, 'pkg', 'HIGH')",
                    &[run, cve],
                )
                .await;
            }
        }
        for (source, tag, image) in [(&a, "1.0", "img1"), (&b, "2.0", "img2")] {
            exec(
                &fx,
                "INSERT INTO tag_observations (source_id, tag, image_id) VALUES (?, ?, ?)",
                &[source, tag, image],
            )
            .await;
        }
        exec(
            &fx,
            "INSERT INTO github_issues (id, github_owner, github_repo, cve_id, github_issue_number, github_issue_url)
             VALUES ('gi1', 'octo', 'app', ?, 7, 'https://github.com/octo/app/issues/7')",
            &[GHSA],
        )
        .await;
        for (source, tag) in [(&a, "1.0"), (&a, "1.1"), (&b, "2.0")] {
            for cve in [GHSA, "CVE-2026-0002"] {
                let id = format!("f-{source}-{tag}-{cve}");
                let issue = if cve == GHSA { "gi1" } else { "" };
                exec(
                    &fx,
                    "INSERT INTO cve_findings (id, source_id, image_tag, cve_id, severity, github_issue_id)
                     VALUES (?, ?, ?, ?, 'HIGH', NULLIF(?, ''))",
                    &[&id, source, tag, cve, issue],
                )
                .await;
            }
        }
        (fx, a, b)
    }

    #[tokio::test]
    async fn admin_deletes_one_cve_record_for_one_source() {
        let (fx, a, _b) = seeded("cvedel-ok").await;
        let (status, _) = fx
            .call("DELETE", &uri(&a, GHSA), &fx.admin, Value::Null)
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let sql = "SELECT COUNT(*) FROM cve_findings WHERE source_id = ? AND cve_id = ?";
        assert_eq!(count(&fx, sql, &[&a, GHSA]).await, 0);
        // The same source's other CVE stays.
        assert_eq!(count(&fx, sql, &[&a, "CVE-2026-0002"]).await, 2);
        let runs = "SELECT COUNT(*) FROM scanner_findings WHERE run_id = 'ra' AND cve_id = ?";
        assert_eq!(count(&fx, runs, &[GHSA]).await, 0);
        assert_eq!(count(&fx, runs, &["CVE-2026-0002"]).await, 1);
        fx.finish().await;
    }

    #[tokio::test]
    async fn non_admin_is_refused() {
        let (fx, a, _b) = seeded("cvedel-user").await;
        for who in [&fx.owner, &fx.other] {
            let (status, _) = fx.call("DELETE", &uri(&a, GHSA), who, Value::Null).await;
            assert_eq!(status, StatusCode::FORBIDDEN);
        }
        let (status, _) = fx
            .call("DELETE", &uri(&a, GHSA), &fx.anonymous, Value::Null)
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let sql = "SELECT COUNT(*) FROM cve_findings WHERE source_id = ? AND cve_id = ?";
        assert_eq!(count(&fx, sql, &[&a, GHSA]).await, 2);
        assert_eq!(
            count(
                &fx,
                "SELECT COUNT(*) FROM audit_log WHERE action = 'cve.delete'",
                &[]
            )
            .await,
            0
        );
        fx.finish().await;
    }

    #[tokio::test]
    async fn foreign_or_missing_source_is_404() {
        let (fx, a, b) = seeded("cvedel-404").await;
        for (source, cve) in [
            ("no-such-source", GHSA),
            (a.as_str(), "CVE-9999-0000"),
            (a.as_str(), "bad%20id"),
        ] {
            let (status, _) = fx
                .call("DELETE", &uri(source, cve), &fx.admin, Value::Null)
                .await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{source} {cve}");
        }
        // A record that exists only on source B is not found through a source with none.
        exec(
            &fx,
            "DELETE FROM cve_findings WHERE source_id = ? AND cve_id = 'CVE-2026-0002'",
            &[&a],
        )
        .await;
        let (status, _) = fx
            .call("DELETE", &uri(&a, "CVE-2026-0002"), &fx.admin, Value::Null)
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let sql =
            "SELECT COUNT(*) FROM cve_findings WHERE source_id = ? AND cve_id = 'CVE-2026-0002'";
        assert_eq!(count(&fx, sql, &[&b]).await, 1);
        assert_eq!(
            count(
                &fx,
                "SELECT COUNT(*) FROM audit_log WHERE action = 'cve.delete'",
                &[]
            )
            .await,
            0
        );
        fx.finish().await;
    }

    #[tokio::test]
    async fn active_acceptance_blocks_the_delete_with_409() {
        let (fx, a, _b) = seeded("cvedel-409").await;
        exec(
            &fx,
            "INSERT INTO cve_acceptances (id, source_id, cve_id, reason, created_by_username)
             VALUES ('acc1', ?, ?, 'risk', 'o1')",
            &[&a, GHSA],
        )
        .await;
        let (status, _) = fx
            .call("DELETE", &uri(&a, GHSA), &fx.admin, Value::Null)
            .await;
        assert_eq!(status, StatusCode::CONFLICT);
        let sql = "SELECT COUNT(*) FROM cve_findings WHERE source_id = ? AND cve_id = ?";
        assert_eq!(count(&fx, sql, &[&a, GHSA]).await, 2);
        // Once revoked, the delete goes through.
        exec(
            &fx,
            "UPDATE cve_acceptances SET revoked_at = 5, revoked_by = 'a3' WHERE id = 'acc1'",
            &[],
        )
        .await;
        let (status, _) = fx
            .call("DELETE", &uri(&a, GHSA), &fx.admin, Value::Null)
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        fx.finish().await;
    }

    #[tokio::test]
    async fn delete_leaves_other_sources_and_github_issues_untouched() {
        let (fx, a, b) = seeded("cvedel-scope").await;
        let (status, _) = fx
            .call("DELETE", &uri(&a, GHSA), &fx.admin, Value::Null)
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let sql = "SELECT COUNT(*) FROM cve_findings WHERE source_id = ? AND cve_id = ?";
        assert_eq!(count(&fx, sql, &[&b, GHSA]).await, 1);
        assert_eq!(count(&fx, sql, &[&b, "CVE-2026-0002"]).await, 1);
        let runs = "SELECT COUNT(*) FROM scanner_findings WHERE run_id = 'rb'";
        assert_eq!(count(&fx, runs, &[]).await, 2);
        assert_eq!(
            count(&fx, "SELECT COUNT(*) FROM github_issues", &[]).await,
            1
        );
        let issue = "SELECT status FROM github_issues WHERE id = 'gi1'";
        assert_eq!(
            count(
                &fx,
                "SELECT COUNT(*) FROM cve_findings WHERE github_issue_id = 'gi1'",
                &[]
            )
            .await,
            1
        );
        let status: String = sqlx::query_scalar(issue).fetch_one(&fx.pool).await.unwrap();
        assert_eq!(status, "open");
        fx.finish().await;
    }

    #[tokio::test]
    async fn a_scan_run_of_an_image_another_source_also_tracks_is_kept() {
        let (fx, a, b) = seeded("cvedel-shared").await;
        exec(
            &fx,
            "INSERT INTO tag_observations (source_id, tag, image_id) VALUES (?, '2.1', 'img1')",
            &[&b],
        )
        .await;
        let (status, _) = fx
            .call("DELETE", &uri(&a, GHSA), &fx.admin, Value::Null)
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let runs = "SELECT COUNT(*) FROM scanner_findings WHERE run_id = 'ra' AND cve_id = ?";
        assert_eq!(count(&fx, runs, &[GHSA]).await, 1);
        fx.finish().await;
    }

    #[tokio::test]
    async fn delete_writes_one_audit_row_with_ids_only() {
        let (fx, a, _b) = seeded("cvedel-audit").await;
        let (status, _) = fx
            .call("DELETE", &uri(&a, GHSA), &fx.admin, Value::Null)
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let rows: Vec<(String, String, Option<String>)> = sqlx::query_as(
            "SELECT actor_username, target, details FROM audit_log WHERE action = 'cve.delete'",
        )
        .fetch_all(&fx.pool)
        .await
        .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, "a3");
        let details: Value = serde_json::from_str(rows[0].2.as_deref().unwrap()).unwrap();
        assert_eq!(details, json!({"source_id": a, "cve_id": GHSA}));
        fx.finish().await;
    }

    #[tokio::test]
    async fn delete_without_csrf_is_refused() {
        let (fx, a, _b) = seeded("cvedel-csrf").await;
        let (status, _) = send_json(
            &fx.router,
            "DELETE",
            &uri(&a, GHSA),
            Some(&fx.admin),
            None,
            "",
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let sql = "SELECT COUNT(*) FROM cve_findings WHERE source_id = ? AND cve_id = ?";
        assert_eq!(count(&fx, sql, &[&a, GHSA]).await, 2);
        fx.finish().await;
    }
}

#[tokio::test]
async fn about_returns_the_dockward_and_both_scanner_versions() {
    let fx = fixture("rt-about").await;
    // The same session rule as the other read routes: 401 without one.
    let (status, _) = fx.read("/api/v1/about", &fx.anonymous).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // Any signed-in user reads it, user or admin.
    for who in [&fx.owner, &fx.admin] {
        let (status, body) = fx.read("/api/v1/about", who).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body,
            json!({
                "dockward": env!("CARGO_PKG_VERSION"),
                "trivy": "v0.76.2",
                "grype": "v0.121.3",
                "scanners": {
                    "trivy": idle_scanner(),
                    "grype": idle_scanner(),
                },
            })
        );
    }
    // A stored daily check shows the latest stable release and whether it is newer (#390).
    let stored =
        crate::db::scanner_releases::put(&fx.pool, "trivy", "0.77.0", true, 1_800_000_000).await;
    assert!(stored.is_ok());
    let (status, body) = fx.read("/api/v1/about", &fx.owner).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["scanners"]["trivy"],
        json!({
            "in_use": "bundled",
            "downloaded_version": null,
            "broken_version": null,
            "latest_version": "v0.77.0",
            "update_available": true,
            "checked_at": "2027-01-15T08:00:00Z",
        })
    );
    assert_eq!(body["scanners"]["grype"], idle_scanner());
}

/// A scanner on its bundled binary with no check recorded yet.
fn idle_scanner() -> serde_json::Value {
    json!({
        "in_use": "bundled",
        "downloaded_version": null,
        "broken_version": null,
        "latest_version": null,
        "update_available": false,
        "checked_at": null,
    })
}
