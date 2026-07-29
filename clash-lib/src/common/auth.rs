use std::{collections::HashMap, sync::Arc};

pub trait Authenticator {
    fn authenticate(&self, username: &str, password: &str) -> bool;
    fn users(&self) -> Vec<String>;
    fn enabled(&self) -> bool;
}

pub type ThreadSafeAuthenticator = Arc<dyn Authenticator + Send + Sync>;

pub struct User(String, String);

impl User {
    pub fn new(username: String, password: String) -> Self {
        Self(username, password)
    }
}

pub struct PlainAuthenticator {
    store: HashMap<String, String>,
    usernames: Vec<String>,
}

impl PlainAuthenticator {
    pub fn new(users: Vec<User>) -> Self {
        let mut store = HashMap::new();
        let mut usernames = Vec::new();
        for user in users {
            store.insert(user.0.clone(), user.1.clone());
            usernames.push(user.0.clone());
        }
        Self { store, usernames }
    }
}

/// Compare two byte strings without an early exit on the first difference.
///
/// The length is still observable — that is inherent to comparing a
/// variable-length secret — but the contents are not.
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

impl Authenticator for PlainAuthenticator {
    fn authenticate(&self, username: &str, password: &str) -> bool {
        match self.store.get(username) {
            Some(p) => constant_time_eq(p.as_bytes(), password.as_bytes()),
            None => false,
        }
    }

    fn users(&self) -> Vec<String> {
        self.usernames.clone()
    }

    fn enabled(&self) -> bool {
        !self.usernames.is_empty()
    }
}
