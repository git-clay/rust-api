use crate::db::Conn as DbConn;
use crate::schema::users;
use crate::schema::users::dsl::users as all_users;
use crate::structs::auth_struct::LoginRequest;

use diesel;
use diesel::pg::PgConnection;
use diesel::prelude::*;

#[derive(Serialize, Queryable)]
pub struct User {
    pub id: i32,
    pub username: String,
    pub password_hash: String,
    pub role: String,
}
#[derive(Deserialize)]
pub struct UserData {
    pub username: String,
}
#[derive(Serialize, Deserialize, Insertable)]
#[table_name = "users"]
pub struct NewUser {
    pub username: String,
    pub password_hash: String,
}

/*
    I would move this into a DAO on a larger project.
    If objects need to be joined, I would add repositories for the more complicated queries
*/
impl User {
    pub fn get_all_users(conn: &PgConnection) -> Vec<User> {
        all_users
            .order(users::id.desc())
            .load::<User>(conn)
            .expect("error!")
    }

    pub fn insert_user(user: NewUser, conn: &PgConnection) -> bool {
        diesel::insert_into(users::table)
            .values(user)
            .execute(conn)
            .is_ok()
    }

    pub fn get_user_by_username(login: &LoginRequest, conn: &PgConnection) -> Vec<User> {
        let user = all_users
            .filter(users::username.eq(&login.username))
            .load::<User>(conn)
            .expect("error!");

        user
    }
}
