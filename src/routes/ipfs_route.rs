use crate::services::auth_service::Token;
use rocket_contrib::json::Json;
use serde_json::Value;

#[get("/ipfs_hash", format = "application/json")]
pub fn ipfs_hash(_token: Token) -> Json<Value> {
    Json(json!({
        "status": 200,
        "result": "Some(&token)"
    }))
}
