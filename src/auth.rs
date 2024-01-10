use crate::config::{User, UserDatabase};
use async_trait::async_trait;
use axum_login::{AuthUser, AuthnBackend, UserId};

impl AuthUser for User {
    type Id = String;

    fn id(&self) -> Self::Id {
        self.username.clone()
    }

    fn session_auth_hash(&self) -> &[u8] {
        &self.password_hash.as_bytes()
    }
}

#[derive(Clone)]
pub struct Credentials {
    pub username: String,
}

#[async_trait]
impl AuthnBackend for UserDatabase {
    type User = User;
    type Credentials = Credentials;
    type Error = std::convert::Infallible;

    async fn authenticate(
        &self,
        Credentials { username }: Self::Credentials,
    ) -> Result<Option<Self::User>, Self::Error> {
        Ok(self.users.get(&username).cloned())
    }

    async fn get_user(&self, username: &UserId<Self>) -> Result<Option<Self::User>, Self::Error> {
        Ok(self.users.get(username).cloned())
    }
}
