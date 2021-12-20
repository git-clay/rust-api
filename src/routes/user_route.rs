use crate::db::Conn as DbConn;
use crate::services::auth_service::{handle_login, handle_register};
use crate::structs::auth_struct::LoginRequest;
use rocket_contrib::json::Json;
use serde_json::Value;

#[post("/register", format = "application/json", data = "<new_user>")]
pub fn register_user(conn: DbConn, new_user: Json<LoginRequest>) -> Json<Value> {
    let register = handle_register(conn, new_user.into_inner());
    Json(json!({
        "status": true,
        "result": register
    }))
}

#[post("/login", format = "application/json", data = "<login>")]
pub fn login_user(conn: DbConn, login: Json<LoginRequest>) -> Json<Value> {
    let token = handle_login(conn, login.into_inner());
    Json(json!({
        "status": match &token{Some(_)=> 200, None=>401},
        "token": Some(&token)
    }))
}
