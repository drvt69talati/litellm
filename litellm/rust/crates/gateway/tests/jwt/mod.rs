//! An identity provider as a gateway test holds it: one Ed25519 key, the JWKS that publishes it
//! over HTTP, and tokens it signs.

// Shared across test targets; each target uses a different subset.
#![allow(dead_code)]

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Map, Value, json};

pub const KID: &str = "k1";

const PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIEjkuYWkj6THWjxVRFL36QT1XS2a1KjdV89JMvLev7r2
-----END PRIVATE KEY-----
";
const PUBLIC_X: &str = "iO5qGwVLMzVNKsLll1PGbMPQzI_aTO9tZuoe8AEWCo4";

/// `claims` signed with the provider's key, as a compact JWS.
pub fn sign(claims: &Value) -> String {
    let encode = |value: &Value| URL_SAFE_NO_PAD.encode(serde_json::to_vec(value).unwrap());
    let header = json!({"alg": "EdDSA", "typ": "JWT", "kid": KID});
    let input = format!("{}.{}", encode(&header), encode(claims));
    let key = jsonwebtoken::EncodingKey::from_ed_pem(PRIVATE_PEM.as_bytes()).unwrap();
    let signature =
        jsonwebtoken::crypto::sign(input.as_bytes(), &key, jsonwebtoken::Algorithm::EdDSA).unwrap();
    format!("{input}.{signature}")
}

/// `claims` with `iat` now and `exp` `expires_in` seconds from now, signed.
pub fn issue(claims: &Map<String, Value>, expires_in: i64) -> String {
    let now = jiff::Timestamp::now().as_second();
    let stamped = claims
        .clone()
        .into_iter()
        .chain([
            ("iat".to_owned(), json!(now)),
            ("exp".to_owned(), json!(now + expires_in)),
        ])
        .collect::<Map<_, _>>();
    sign(&Value::Object(stamped))
}

/// Serves the provider's JWKS and answers its URL, which `JWT_PUBLIC_KEY_URL` names.
pub async fn serve_jwks() -> String {
    let jwks = json!({"keys": [{"kty": "OKP", "kid": KID, "crv": "Ed25519", "x": PUBLIC_X}]});
    let app = axum::Router::new().route(
        "/jwks.json",
        axum::routing::get(move || async move { axum::Json(jwks) }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    litellm_call_scope::spawn_detached(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{addr}/jwks.json")
}
