/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

extern crate libc;
extern crate rusqlite;
extern crate crypto;

use self::crypto::digest::Digest;
use self::crypto::md5::Md5;
use self::libc::{c_int};
use self::rusqlite::Connection;

#[derive(Clone, Debug)]
pub struct User {
    pub id: Option<i32>,
    pub name: String,
    pub email: String,
    pub password: String
}

pub struct UsersDb {
    connection: Connection
}

impl UsersDb {
    pub fn new() -> UsersDb {
        let connection = Connection::open_in_memory().unwrap();
        connection.execute("CREATE TABLE IF NOT EXISTS users (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                name        TEXT NOT NULL,
                email       TEXT NOT NULL,
                password    TEXT NOT NULL
            )", &[]).unwrap();

        UsersDb {
            connection: connection
        }
    }

    pub fn create(&self, user: &User) -> rusqlite::Result<c_int> {
        let mut md5 = Md5::new();
        md5.input_str(&user.password);
        self.connection.execute("INSERT INTO users
            (name, email, password) VALUES ($1, $2, $3)",
            &[&user.name, &user.email, &md5.result_str()]
        )
    }

    pub fn read(&self) -> rusqlite::Result<Vec<User>> {
        let mut stmt = try!(self.connection.prepare("SELECT * FROM users"));
        let rows = try!(stmt.query(&[]));
        let mut users = Vec::new();
        for result_row in rows {
            let row = try!(result_row);
            users.push(User {
                id: row.get(0),
                name: row.get(1),
                email: row.get(2),
                password: row.get(3)
            });
        }
        Ok(users)
    }

    pub fn update(&self, user: &User) -> rusqlite::Result<c_int> {
        self.connection.execute("UPDATE users SET name=$1, email=$2
            WHERE id=$3", &[&user.name, &user.email, &user.id])
    }

    pub fn delete(&self, id: i32) -> rusqlite::Result<c_int> {
        self.connection.execute("DELETE FROM users WHERE id=$1", &[&id])
    }
}
