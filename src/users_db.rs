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

#[derive(Debug)]
pub struct UserBuilder {
    id: Option<i32>,
    name: String,
    email: String,
    password: String,
    error: Option<UserBuilderError>
}

#[derive(Clone, Debug)]
pub enum UserBuilderError {
    InvalideUsername,
    InvalidEmail,
    InvalidPassword
}

impl UserBuilder {
    pub fn new() -> UserBuilder {
        UserBuilder {
            id: None,
            name: "".to_string(),
            email: "".to_string(),
            password: "".to_string(),
            error: None
        }
    }

    pub fn id(&mut self, id: i32) -> &mut UserBuilder {
        self.id = Some(id);
        self
    }

    pub fn name(&mut self, name: String) -> &mut UserBuilder {
        self.name = name;
        self
    }

    pub fn email(&mut self, email: String) -> &mut UserBuilder {
        self.email = email;
        self
    }

    pub fn password(&mut self, password: String) -> &mut UserBuilder {
        let mut md5 = Md5::new();
        md5.input_str(&password);
        self.password = md5.result_str();
        self
    }

    pub fn finalize(&self) -> Result<User, UserBuilderError> {
        match self.error {
            Some(ref error) => Err(error.clone()),
            None => Ok(User {
                id: self.id,
                name: self.name.clone(),
                email: self.email.clone(),
                password: self.password.clone()
            })
        }
    }
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
        self.connection.execute("INSERT INTO users
            (name, email, password) VALUES ($1, $2, $3)",
            &[&user.name, &user.email, &user.password]
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

    pub fn update(&self, id: i32, user: &User) -> rusqlite::Result<c_int> {
        self.connection.execute("UPDATE users SET name=$1, email=$2, password=$3
            WHERE id=$3", &[&user.name, &user.email, &user.password, &id])
    }

    pub fn delete(&self, id: i32) -> rusqlite::Result<c_int> {
        self.connection.execute("DELETE FROM users WHERE id=$1", &[&id])
    }
}
