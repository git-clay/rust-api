use crate::db::Conn as DbConn;
use crate::models::role_model::Role;
use crate::models::user_model::NewUser;
use crate::models::user_model::User;
use crate::structs::auth_struct::LoginRequest;

use argon2::{self, Config};
use chrono::Utc;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rocket::http::HeaderMap;
use rocket::http::Status;
use rocket::request::FromRequest;
use rocket::request::Outcome;
use rocket::Request;
use rocket::Response;
use std::convert::Infallible;
use std::env;
use std::fmt;

const BEARER: &str = "Bearer ";
const TOKEN_EXPIRATION_MINUTES: i64 = 60;

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Role::User => write!(f, "User"),
            Role::Admin => write!(f, "Admin"),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct Claims {
    sub: String,
    role: String,
    exp: usize,
}

pub struct Token(String);
#[derive(Debug)]
pub enum ApiTokenError {
    Missing,
    Invalid,
}
fn jwt_secret() -> String {
    env::var("JWT_SECRET").expect("set JWT_SECRET")
}

impl<'a, 'r> FromRequest<'a, 'r> for Token {
    type Error = ApiTokenError;

    fn from_request(request: &'a Request<'r>) -> Outcome<Self, Self::Error> {
        let bearer = request.headers().get_one("Authorization");

        if let Some(bearer) = bearer {
            let token: String = bearer
                .chars()
                .take(0)
                .chain(bearer.chars().skip(7))
                .collect();
            authorize(&token);
            Outcome::Success(Token(token.to_string()))
        } else {
            Outcome::Failure((Status::Unauthorized, ApiTokenError::Missing))
        }
    }
}
fn authorize(jwt: &str) {
    decode::<Claims>(
        &jwt.to_string(),
        &DecodingKey::from_secret(jwt_secret().as_bytes()),
        &Validation::new(Algorithm::HS512),
    );
}

fn create_jwt(user: &User) -> String {
    let expiration = Utc::now()
        .checked_add_signed(chrono::Duration::minutes(TOKEN_EXPIRATION_MINUTES))
        .expect("valid timestamp")
        .timestamp();

    let claims = Claims {
        sub: user.id.to_string(),
        role: user.role.to_string(),
        exp: expiration as usize,
    };
    let header = Header::new(Algorithm::HS512);

    let mut token = String::new();
    token += BEARER;
    token += &encode(
        &header,
        &claims,
        &EncodingKey::from_secret(jwt_secret().as_bytes()),
    )
    .unwrap();
    token
}

fn password_hasher(password: &String) -> String {
    let password = password.as_bytes();
    let salt: String = env::var("SALT").expect("set SALT");

    let config = Config::default();
    argon2::hash_encoded(password, salt.as_bytes(), &config).unwrap()
}
fn password_matches(password: &String, user: &User) -> Option<String> {
    match argon2::verify_encoded(&user.password_hash, password.as_bytes()).unwrap() {
        true => Some(create_jwt(&user)),
        false => None,
    }
}
pub fn handle_register(conn: DbConn, new_user: LoginRequest) -> Vec<User> {
    User::insert_user(
        NewUser {
            username: new_user.username.clone(),
            password_hash: password_hasher(&new_user.password),
        },
        &conn,
    );

    User::get_user_by_username(&new_user, &conn)
}
pub fn handle_login(conn: DbConn, login: LoginRequest) -> Option<String> {
    match User::get_user_by_username(&login, &conn).first() {
        Some(u) => password_matches(&login.password, u),
        None => None,
    }
}
