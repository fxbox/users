/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#![feature(associated_consts, plugin)]

#![cfg_attr(test, feature(const_fn))] // Dependency of stainless
#![cfg_attr(test, plugin(stainless))] // Test runner
#![cfg_attr(test, plugin(clippy))]    // Linter

#[cfg(test)]
extern crate iron_test;

extern crate crypto;
extern crate iron;
extern crate jwt;
extern crate libc;
extern crate pwhash;
extern crate rand;
extern crate router;
extern crate rustc_serialize;
extern crate rusqlite;
extern crate unicase;
extern crate urlencoded;

mod users_db;
mod users_router;
mod auth_middleware;
mod errors;

pub use users_db::UsersDb as UsersDb;
pub use users_db::UserBuilder as UserBuilder;
pub use users_db::UserBuilderError as UserBuilderError;
pub use users_db::ReadFilter as ReadFilter;
pub use users_db::User as User;
pub use users_router::UsersRouter as UsersRouter;
pub use auth_middleware::AuthMiddleware as AuthMiddleware;
pub use auth_middleware::AuthEndpoint as AuthEndpoint;

pub struct UsersManager {
    db_file_path: String,
}

impl UsersManager {

    /// Create the UsersManager. The database will be stored at
    /// `db_file_path`.
    pub fn new(db_file_path: &str) -> Self {
        UsersManager { db_file_path: String::from(db_file_path) }
    }

    /// Get a new database connection.
    pub fn get_db(&self) -> UsersDb {
        UsersDb::new(&self.db_file_path)
    }

    /// Get a new router chain
    pub fn get_router_chain(&self) -> iron::middleware::Chain {
        UsersRouter::init(&self.db_file_path)
    }

    pub fn get_middleware(&self, auth_endpoints: Vec<AuthEndpoint>)
                          -> AuthMiddleware {
        AuthMiddleware { auth_endpoints: auth_endpoints,
                         auth_db_file: self.db_file_path.to_owned() }
    }

    pub fn verify_token(&self, token: &str) -> Result<(), ()> {
        AuthMiddleware::verify(token, &self.db_file_path)
    }
}
