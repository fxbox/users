/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

extern crate rusqlite;
extern crate uuid;

use self::rusqlite::Connection;
use self::uuid::Uuid;

#[derive(Debug)]
pub struct User {
    id: Option<i32>,
    name: String,
    email: String
}

pub struct UserDb {
    connection: Connection
}

#[derive(Debug)]
pub enum UserDbError {
    Unknown
}

pub type UserDbResult = Result<(), UserDbError>;

impl UserDb {
    pub fn new() -> UserDb {
        UserDb {
            connection: Connection::open_in_memory().unwrap()
        }
    }

    pub fn create(&self, user: &User) -> UserDbResult {
        let uuid = Uuid::new_v4();
        self.connection.execute("INSERT INTO users (
            id      INTEGER PRIMARY KEY,
            name    TEXT NOT NULL,
            email   TEXT NOT NULL
        ) VALUES ($1, $2, $3)", &[&uuid.to_urn_string(), &user.name, &user.email]).unwrap();

        Ok(())
    }
}
