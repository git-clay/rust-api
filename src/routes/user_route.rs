use crate::db::Conn as DbConn;
use rocket_contrib::json::Json;
use crate::models::user_model::{User, NewUser,UserData};
use serde_json::Value;

#[post("/register", format = "application/json", data = "<new_user>")]
pub fn register(conn: DbConn, new_user: Json<NewUser>) -> Json<Value> {
    Json(json!({
        "status": User::insert_user(new_user.into_inner(), &conn),
        "result": User::get_all_users(&conn).first(),
    }))
}

#[post("/login", format = "application/json", data = "<user_data>")]
pub fn login(conn: DbConn, user_data: Json<UserData>) -> Json<Value> {
    Json(json!({
        "status": 200,
        "result": User::get_user_by_username(user_data.into_inner(), &conn),
    }))
}

