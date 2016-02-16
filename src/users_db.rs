/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use crypto::digest::Digest;
use crypto::md5::Md5;
use libc::{c_int};
use rusqlite::{self, Connection};

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

#[derive(Clone, Debug, PartialEq)]
pub enum UserBuilderError {
    EmptyEmail,
    EmptyUsername,
    InvalidEmail,
    InvalidPassword
}

#[derive(Debug)]
pub struct UserWithError {
    pub user: User,
    pub error: UserBuilderError
}

fn escape(string: &str) -> String {
    // http://www.sqlite.org/faq.html#q14
    string.replace("'", "''")
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
            self.error = Some(UserBuilderError::EmptyUsername);
            return self;
        }
        self.name = escape(name);
        self
    }

    pub fn email(&mut self, email: &str) -> &mut UserBuilder {
        if email.is_empty() {
            self.error = Some(UserBuilderError::EmptyEmail);
            return self;
        }
        let parts: Vec<&str> = email.rsplitn(2, '@').collect();
        if parts[0].is_empty() || parts[1].is_empty() {
            self.error = Some(UserBuilderError::InvalidEmail);
            return self;
        }
        self.email = escape(email);
        self
    }

    pub fn password(&mut self, password: &str) -> &mut UserBuilder {
        if password.is_empty() || password.len() < UserBuilder::MIN_PASS_LEN {
            self.error = Some(UserBuilderError::InvalidPassword);
            return self;
        }
        let mut md5 = Md5::new();
        md5.input_str(&escape(password));
        self.password = md5.result_str();
        self
    }

    pub fn finalize(&self) -> Result<User, UserWithError> {
        match self.error {
            Some(ref error) => Err(UserWithError{
                user: User {
                    id: self.id,
                    name: self.name.clone(),
                    email: self.email.clone(),
                    password: self.password.clone()
                },
                error: error.clone()
            }),
            None => Ok(User {
                id: self.id,
                name: self.name.clone(),
                email: self.email.clone(),
                password: self.password.clone()
            })
        }
    }
}

pub enum ReadFilter {
    All,
    Id(i32),
    Name(String),
    Email(String),
    Credentials(String, String)
}

pub struct UsersDb {
    // rusqlite::Connection already implements the Drop trait for the
    // inner connection so we don't need to manually close it. It will
    // be closed when the UsersDb instances go out of scope.
    connection: Connection
}

#[cfg(test)]
fn get_db_environment() -> String {
    "./users_db_test.sqlite".to_string()
}

#[cfg(not(test))]
fn get_db_environment() -> String {
    "./users_db.sqlite".to_string()
}

impl UsersDb {
    pub fn new() -> UsersDb {
        let connection = Connection::open(get_db_environment()).unwrap();
        connection.execute("CREATE TABLE IF NOT EXISTS users (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                name        TEXT NOT NULL UNIQUE,
                email       TEXT NOT NULL UNIQUE,
                password    TEXT NOT NULL
            )", &[]).unwrap();

        UsersDb {
            connection: connection
        }
    }

    pub fn clear(&self) -> rusqlite::Result<()> {
        self.connection.execute_batch(
            "DELETE FROM users;
             DELETE FROM SQLITE_SEQUENCE WHERE name='users';
             VACUUM;"
        )
    }

    pub fn create(&self, user: &User) -> rusqlite::Result<c_int> {
        self.connection.execute("INSERT INTO users
            (name, email, password) VALUES ($1, $2, $3)",
            &[&user.name, &user.email, &user.password]
        )
    }

    pub fn read(&self, filter: ReadFilter) -> rusqlite::Result<Vec<User>> {
        let mut stmt = try!(
            self.connection.prepare("SELECT * FROM users")
        );

        let rows = match filter {
            ReadFilter::All => {
                try!(stmt.query(&[]))
            },
            ReadFilter::Id(id) => {
                stmt = try!(
                    self.connection.prepare("SELECT * FROM users WHERE id=$1")
                );
                try!(stmt.query(&[&id]))
            },
            ReadFilter::Name(name) => {
                stmt = try!(
                    self.connection.prepare("SELECT * FROM users WHERE name=$1")
                );
                try!(stmt.query(&[&escape(&name)]))
            },
            ReadFilter::Email(email) => {
                stmt = try!(
                    self.connection.prepare("SELECT * FROM users WHERE email=$1")
                );
                try!(stmt.query(&[&escape(&email)]))
            },
            ReadFilter::Credentials(user, password) => {
                let mut md5 = Md5::new();
                md5.input_str(&escape(&password));
                let password = md5.result_str();
                stmt = try!(
                    self.connection.prepare(
                        "SELECT * FROM users WHERE (name=$1 OR email=$2) AND (password=$3)"
                    )
                );
                try!(stmt.query(&[&escape(&user), &escape(&user), &password]))
            }
        };
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
        use crypto::digest::Digest;
        use crypto::md5::Md5;

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
        usersDb.clear();

        let defaultUsers = vec![
            UserBuilder::new().id(1).name("User1")
                .email("user1@mozilla.org").password("password1").finalize().unwrap(),
            UserBuilder::new().id(2).name("User2")
                .email("user2@mozilla.org").password("password2").finalize().unwrap(),
            UserBuilder::new().id(3).name("User3")
                .email("user3@mozilla.org").password("password3").finalize().unwrap(),
        ];

        for user in &defaultUsers {
            usersDb.create(user).unwrap();
        }

        // Check integrity
        match usersDb.read() {
            Ok(users) => assert_eq!(users.len(), _users.len),
            Err(err) => panic!("Error reading database {}", err),
        }
    }

    it "should read users from db" {
        let usersInDb = usersDb.read(ReadFilter::All).unwrap();
        assert_eq!(usersInDb.len(), defaultUsers.len());

        for i in 0..usersInDb.len() {
            assert_eq!(usersInDb[i], defaultUsers[i]);
        }
    }

    it "should read user by id" {
        for i in 0..defaultUsers.len() {
            let users = usersDb.read(
                ReadFilter::Id(defaultUsers[i].id.unwrap())).unwrap();
            assert_eq!(users.len(), 1);
            assert_eq!(users[0].id, defaultUsers[i].id);
            assert_eq!(users[0].name, defaultUsers[i].name);
            assert_eq!(users[0].email, defaultUsers[i].email);
            assert_eq!(users[0].password, defaultUsers[i].password);
        }
    }

    it "should read user by name" {
        for i in 0..defaultUsers.len() {
            let users = usersDb.read(
                ReadFilter::Name(defaultUsers[i].name.clone())).unwrap();
            assert_eq!(users.len(), 1);
            assert_eq!(users[0].id, defaultUsers[i].id);
            assert_eq!(users[0].name, defaultUsers[i].name);
            assert_eq!(users[0].email, defaultUsers[i].email);
            assert_eq!(users[0].password, defaultUsers[i].password);
        }
    }

    it "should read user by email" {
        for i in 0..defaultUsers.len() {
            let users = usersDb.read(
                ReadFilter::Email(defaultUsers[i].email.clone())).unwrap();
            assert_eq!(users.len(), 1);
            assert_eq!(users[0].id, defaultUsers[i].id);
            assert_eq!(users[0].name, defaultUsers[i].name);
            assert_eq!(users[0].email, defaultUsers[i].email);
            assert_eq!(users[0].password, defaultUsers[i].password);
        }
    }

    it "should read user by name or email with name" {
        for i in 0..defaultUsers.len() {
            let users = usersDb.read(ReadFilter::Credentials(
                defaultUsers[i].name.clone(), format!("password{}", i + 1))
            ).unwrap();
            assert_eq!(users.len(), 1);
            assert_eq!(users[0].id, defaultUsers[i].id);
            assert_eq!(users[0].name, defaultUsers[i].name);
            assert_eq!(users[0].email, defaultUsers[i].email);
            assert_eq!(users[0].password, defaultUsers[i].password);
        }
    }

    it "should read user by name or email with email" {
        for i in 0..defaultUsers.len() {
            let users = usersDb.read(ReadFilter::Credentials(
                defaultUsers[i].name.clone(), format!("password{}", i + 1))
            ).unwrap();
            assert_eq!(users.len(), 1);
            assert_eq!(users[0].id, defaultUsers[i].id);
            assert_eq!(users[0].name, defaultUsers[i].name);
            assert_eq!(users[0].email, defaultUsers[i].email);
            assert_eq!(users[0].password, defaultUsers[i].password);
        }
    }

    it "should delete users correctly" {
        usersDb.delete(1).unwrap();
        let usersInDb = usersDb.read(ReadFilter::All).unwrap();
        assert_eq!(usersInDb.len(), defaultUsers.len() -1);

        assert_eq!(usersInDb, &defaultUsers[1..]);
    }

    it "should update users correctly" {
        let mut user = defaultUsers[0].clone();
        user.name = "New Name".to_string();

        usersDb.update(user.id.unwrap(), &user).unwrap();

        let users = usersDb.read(ReadFilter::All).unwrap();

        assert_eq!(user, users[0]);
    }

    it "should not retrieve any records" {
        let users = usersDb.read(ReadFilter::Name(
            "Xyz' OR '1'='1".to_string())
        ).unwrap();
        assert_eq!(users.len(), 0);

        let users = usersDb.read(ReadFilter::Name(
            "Xyz\' OR \'1\'=\'1".to_string())
        ).unwrap();
        assert_eq!(users.len(), 0);

        let users = usersDb.read(ReadFilter::Name(
            "Xyz\\' OR \\'1\\'=\\'1".to_string())
        ).unwrap();
        assert_eq!(users.len(), 0);

        let users = usersDb.read(ReadFilter::Credentials(
            "1\' OR \'1\' = \'1\'))/*".to_string(), "foo".to_string()
        )).unwrap();
        assert_eq!(users.len(), 0);
    }
}
