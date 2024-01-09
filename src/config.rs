use serde::Deserialize;
use std::{collections::HashMap, env, path::PathBuf, sync::OnceLock};

#[derive(Debug, Clone, Deserialize)]
pub struct Env {
    pub data_dir: Option<String>,
}

static ENV: OnceLock<Env> = OnceLock::new();

pub fn get_env() -> &'static Env {
    ENV.get_or_init(|| {
        envy::prefixed("AUTH_")
            .from_env::<Env>()
            .expect("Failed to read env")
    })
}

#[derive(Debug, Clone, Deserialize)]
pub struct RawUser {
    pub email: String,
    pub password_hash: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RawUserDatabase {
    pub users: HashMap<String, RawUser>,
}

pub fn load_raw_user_database() -> RawUserDatabase {
    let data_dir = get_env()
        .data_dir
        .as_ref()
        .map(|dir| PathBuf::from(dir))
        .unwrap_or_else(|| env::current_dir().unwrap().join("data"));
    let db_path = data_dir.join("users.yml");
    let users = serde_yaml::from_str(&std::fs::read_to_string(db_path).unwrap()).unwrap();
    users
}

#[derive(Debug, Clone, Deserialize)]
pub struct User {
    pub username: String,
    pub email: String,
    pub password_hash: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UserDatabase {
    pub users: HashMap<String, User>,
}

pub fn get_user_database() -> UserDatabase {
    let raw_users = load_raw_user_database().users;
    let mut users = HashMap::new();
    for (username, raw_user) in raw_users {
        users.insert(
            username.clone(),
            User {
                username,
                email: raw_user.email,
                password_hash: raw_user.password_hash,
            },
        );
    }

    UserDatabase { users }
}
