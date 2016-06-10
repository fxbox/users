/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#![feature(associated_consts, plugin)]

#![cfg_attr(test, feature(const_fn))] // Dependency of stainless
#![cfg_attr(test, plugin(stainless))] // Test runner
#![cfg_attr(test, plugin(clippy))]    // Linter

#[cfg(test)]
extern crate iron_test;
#[macro_use]
#[cfg(test)]
extern crate url;

extern crate crypto;
extern crate hyper;
extern crate iron;
extern crate iron_cors;
extern crate jwt;
extern crate libc;
extern crate pwhash;
extern crate router;
extern crate rustc_serialize;
extern crate rusqlite;
extern crate unicase;
extern crate urlencoded;
extern crate uuid;

mod auth_middleware;
mod errors;
mod invitation_middleware;
mod users_db;
mod users_router;

pub use users_db::UsersDb as UsersDb;
pub use users_db::UserBuilder as UserBuilder;
pub use users_db::UserBuilderError as UserBuilderError;
pub use users_db::ReadFilter as ReadFilter;
pub use users_db::User as User;
pub use users_router::UsersRouter as UsersRouter;
pub use auth_middleware::AuthMiddleware as AuthMiddleware;
pub use auth_middleware::AuthEndpoint as AuthEndpoint;
pub use auth_middleware::SessionToken as SessionToken;

pub struct UsersManager {
    db_file_path: String,
    router: UsersRouter
}

impl UsersManager {
    /// Create the UsersManager.
    /// The database will be stored at `db_file_path`.
    pub fn new(db_file_path: &str)-> Self {
        UsersManager {
            db_file_path: String::from(db_file_path),
            router: UsersRouter::new(db_file_path)
        }
    }

    /// Get a new database connection.
    pub fn get_db(&self) -> UsersDb {
        UsersDb::new(&self.db_file_path)
    }

    /// Get Iron chain containing the Users HTTP API routes.
    pub fn get_router_chain(&self) -> iron::middleware::Chain {
        self.router.init()
    }

    /// Allow the consumer to setup the invitation middleware specifying
    /// the url of the email server that should be an instance of
    /// https://github.com/fxbox/users-email-server
    /// and the URL prepath to be appended to the user activation endpoints.
    pub fn setup_invitation_middleware(&mut self,
                                       email_server: String,
                                       invitation_url_prepath: String) {
        self.router.setup_invitation_middleware(email_server,
                                                invitation_url_prepath);
    }

    pub fn get_middleware(&self, auth_endpoints: Vec<AuthEndpoint>)
                          -> AuthMiddleware {
        AuthMiddleware::new(auth_endpoints, self.db_file_path.to_owned())
    }

    pub fn verify_token(&self, token: &str) -> Result<(), ()> {
        AuthMiddleware::verify(token, &self.db_file_path)
    }
}
