/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

extern crate crypto;
extern crate libc;
extern crate rusqlite;

use self::crypto::digest::Digest;
use self::crypto::md5::Md5;
use self::libc::{c_int};
use self::rusqlite::Connection;

#[derive(Clone, Debug, PartialEq, PartialOrd)]
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
    InvalidUsername,
    InvalidEmail,
    InvalidPassword
}

impl UserBuilder {
    const MIN_PASS_LEN: usize = 8;

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

    pub fn name(&mut self, name: &str) -> &mut UserBuilder {
        if name.is_empty() {
            self.error = Some(UserBuilderError::InvalidUsername);
            return self;
        }
        self.name = name.to_string();
        self
    }

    pub fn email(&mut self, email: &str) -> &mut UserBuilder {
        if email.is_empty() {
            self.error = Some(UserBuilderError::InvalidEmail);
            return self;
        }
        let parts: Vec<&str> = email.rsplitn(2, '@').collect();
        if parts[0].is_empty() || parts[1].is_empty() {
            self.error = Some(UserBuilderError::InvalidEmail);
            return self;
        }
        self.email = email.to_string();
        self
    }

    pub fn password(&mut self, password: &str) -> &mut UserBuilder {
        if password.is_empty() || password.len() < UserBuilder::MIN_PASS_LEN {
            self.error = Some(UserBuilderError::InvalidPassword);
            return self;
        }
        let mut md5 = Md5::new();
        md5.input_str(password);
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
            WHERE id=$4", &[&user.name, &user.email, &user.password, &id])
    }

    pub fn delete(&self, id: i32) -> rusqlite::Result<c_int> {
        self.connection.execute("DELETE FROM users WHERE id=$1", &[&id])
    }
}

describe! user_builder_tests {

    it "should build a user correctly" {
        use super::crypto::digest::Digest;
        use super::crypto::md5::Md5;

        let user = UserBuilder::new()
            .id(1)
            .name("Mr Fox")
            .email("fox@mozilla.org")
            .password("pass12345678")
            .finalize()
            .unwrap();

        assert_eq!(user.id, Some(1));
        assert_eq!(user.name, "Mr Fox");
        assert_eq!(user.email, "fox@mozilla.org");
        let mut md5 = Md5::new();
        md5.input_str("pass12345678");
        assert_eq!(user.password, md5.result_str());
    }

    failing "should panic if invalid user" {
        let _user = UserBuilder::new()
            .name("")
            .finalize()
            .unwrap();
    }
}

describe! user_db_tests {
    before_each {
        let usersDb = UsersDb::new();

        let defaultUsers = vec![
            UserBuilder::new().id(1).name("User1")
                .email("user1@mozilla.org").password("password1").finalize().unwrap(),
            UserBuilder::new().id(2).name("User2")
                .email("user2@mozilla.org").password("password2").finalize().unwrap(),
            UserBuilder::new().id(3).name("User3")
                .email("user3@mozilla.org").password("password3").finalize().unwrap(),
        ];

        for user in &defaultUsers {
            usersDb.create(user);
        }

        // Check integrity
        match usersDb.read() {
            Ok(users) => assert_eq!(users.len(), _users.len),
            Err(err) => panic!("Error reading database {}", err),
        }
    }

    it "should read users from db" {
        let usersInDb = usersDb.read().unwrap();
        assert_eq!(usersInDb.len(), defaultUsers.len());

        for i in 0..usersInDb.len() {
            assert_eq!(usersInDb[i], defaultUsers[i]);
        }
    }

    it "should delete users correctly" {
        usersDb.delete(1).unwrap();
        let usersInDb = usersDb.read().unwrap();
        assert_eq!(usersInDb.len(), defaultUsers.len() -1);

        assert_eq!(usersInDb, &defaultUsers[1..]);
    }

    it "should update users correctly" {
        let mut user = defaultUsers[0].clone();
        user.name = "New Name".to_string();

        usersDb.update(user.id.unwrap(), &user).unwrap();

        let users = usersDb.read().unwrap();

        assert_eq!(user, users[0]);
    }
}