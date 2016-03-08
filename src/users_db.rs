/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//! Provides the User type in addition to the database API.
//!
//! # The Users database
//!
//! The Users database API provides means to retrieve user sets, and to
//! create, update and remove single users.
//!
//! # Examples
//!
//! You can create a user with the UserBuilder type and by chaining
//! methods this way:
//!
//! ```
//! use foxbox_users::users_db::UserBuilder;
//!
//! let new_user =
//!     UserBuilder::new()
//!     .name(String::from("Miles"))                  // mandatory, not empty
//!     .email(String::from("mbdyson@cyberdyne.com")) // mandatory, not empty
//!     .password(String::from("s800t101"))           // mandatory, at least 8 characters
//!     .set_admin(true)                              // optional, defaults to false
//!     .secret(String::from("1234567890"))           // optional, defaults to random
//!     .finalize()
//!     .unwrap();
//! ```
//!
//! Calling `UserBuilder#finalize()` will return a `Result&lt;User, UserWithError&gt;`. You
//! can inspect `UserWithError#error` attribute to see what failed during initialization.
//!

use crypto::digest::Digest;
use crypto::md5::Md5;
use libc::{c_int};
use rusqlite::{self, Connection};

#[derive(Clone, Debug, PartialEq, PartialOrd)]
pub struct User {
    pub id: Option<i32>,
    pub name: String,
    pub email: String,
    pub password: String,
    pub secret: String,
    pub is_admin: Option<bool>
}

/// Creates instances of `User`.
///
/// Starting with `UserBuilder::new()` and chaining methods you can create users:
///
/// ```
/// # use foxbox_users::users_db::UserBuilder;
/// let new_user =
///     UserBuilder::new()
///     .name(String::from("Miles"))                  // mandatory, not empty
///     .email(String::from("mbdyson@cyberdyne.com")) // mandatory, not empty
///     .password(String::from("s800t101"))           // mandatory, at least 8 characters
///     .set_admin(true)                              // optional, defaults to false
///     .secret(String::from("1234567890"))           // optional, defaults to random
///     .finalize()
///     .unwrap();
/// ```
///
/// Calling `UserBuilder#finalize()` will return a `Result<User, UserWithError>`. You
/// can inspect `UserWithError#error` field to see what failed during initialization:
///
/// ```
/// # use foxbox_users::users_db::{UserBuilder, UserBuilderError};
/// let failing_user = UserBuilder::new()
///                    .name(String::from("Miles"))
///                    .password(String::from("short"))
///                    .finalize()
///                    .unwrap_err();
///
/// assert_eq!(failing_user.error, UserBuilderError::InvalidPassword);
/// ```
///
/// All users have a `secret` field that can be set with `UserBuilder#secret()`
/// although it will be automatically initialized to random if not provided.
///
/// ```
/// # use foxbox_users::users_db::UserBuilder;
/// let new_user =
///     UserBuilder::new()
///     .name(String::from("Miles"))                  // mandatory, not empty
///     .email(String::from("mbdyson@cyberdyne.com")) // mandatory, not empty
///     .password(String::from("s800t101"))           // mandatory, at least 8 characters
///     .set_admin(true)                              // optional, defaults to false
///     .finalize()
///     .unwrap();
///
/// assert!(!new_user.secret.is_empty());
/// ```
#[derive(Debug)]
pub struct UserBuilder {
    id: Option<i32>,
    name: String,
    email: String,
    password: String,
    secret: String,
    error: Option<UserBuilderError>,
    is_admin: Option<bool>
}

#[derive(Clone, Debug, PartialEq)]
pub enum UserBuilderError {
    EmptyEmail,
    EmptyUsername,
    EmptySecret,
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
            name: String::new(),
            email: String::new(),
            password: String::new(),
            secret: String::new(),
            error: None,
            is_admin: Some(false)
        }
    }

    pub fn id(mut self, id: i32) -> Self {
        self.id = Some(id);
        self
    }

    pub fn name(mut self, name: String) -> Self {
        if name.is_empty() {
            self.error = Some(UserBuilderError::EmptyUsername);
            return self;
        }
        self.name = escape(&name);
        self
    }

    pub fn email(mut self, email: String) -> Self {
        if email.is_empty() {
            self.error = Some(UserBuilderError::EmptyEmail);
            return self;
        }
        let parts: Vec<&str> = email.rsplitn(2, '@').collect();
        if parts[0].is_empty() || parts[1].is_empty() {
            self.error = Some(UserBuilderError::InvalidEmail);
            return self;
        }
        self.email = escape(&email);
        self
    }

    pub fn password(mut self, password: String) -> Self {
        if password.is_empty() || password.len() < UserBuilder::MIN_PASS_LEN {
            self.error = Some(UserBuilderError::InvalidPassword);
            return self;
        }
        let mut md5 = Md5::new();
        md5.input_str(&escape(&password));
        self.password = md5.result_str();
        self
    }

    pub fn secret(mut self, secret: String) -> Self {
        if secret.is_empty()  {
            self.error = Some(UserBuilderError::EmptySecret);
            return self;
        }
        self.secret = secret.to_owned();
        self
    }

    pub fn set_admin(mut self, admin: bool) -> Self {
        self.is_admin = Some(admin);
        self
    }

    pub fn finalize(mut self) -> Result<User, UserWithError> {
        use rand;
        if self.secret.is_empty() {
            self.secret = rand::random::<i32>().to_string();
        }
        match self.error {
            Some(error) => Err(UserWithError{
                user: User {
                    id: self.id,
                    name: self.name,
                    email: self.email,
                    password: self.password,
                    secret: self.secret,
                    is_admin: self.is_admin
                },
                error: error
            }),
            None => Ok(User {
                id: self.id,
                name: self.name,
                email: self.email,
                password: self.password,
                secret: self.secret,
                is_admin: self.is_admin
            })
        }
    }
}

pub enum ReadFilter {
    All,
    Id(i32),
    Name(String),
    Email(String),
    Credentials(String, String),
    IsAdmin(bool)
}

/// Provides [CRUD](https://en.wikipedia.org/wiki/Create,_read,_update_and_delete)
/// (create, read, update and delete) operations for the user collection.
pub struct UsersDb {
    // rusqlite::Connection already implements the Drop trait for the
    // inner connection so we don't need to manually close it. It will
    // be closed when the UsersDb instances go out of scope.
    connection: Connection
}

impl UsersDb {
    /// Opens the database and create it if not available yet.
    ///
    /// When the database instance exits the scope where it was created, it is
    /// automatically closed.
    pub fn new(db_name: Option<String>) -> UsersDb {
        let db_name = match db_name {
            Some(name) => name,
            None => "./users_db.sqlite".to_owned()
        };
        let connection = Connection::open(db_name).unwrap();
        connection.execute("CREATE TABLE IF NOT EXISTS users (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                name        TEXT NOT NULL UNIQUE,
                email       TEXT NOT NULL UNIQUE,
                password    TEXT NOT NULL,
                secret      TEXT NOT NULL,
                is_admin    BOOL NOT NULL DEFAULT 0
            )", &[]).unwrap();

        UsersDb {
            connection: connection
        }
    }

    /// Empties the complete database.
    ///
    /// # Examples
    ///
    /// ```
    /// # use foxbox_users::users_db::{UserBuilder, UsersDb, ReadFilter};
    /// let db = UsersDb::new(Some("./users_db.sqlite".to_owned()));
    /// # db.create(&UserBuilder::new().name(String::from("John Doe")).finalize().unwrap());
    /// db.clear();
    /// let users = db.read(ReadFilter::All).unwrap();
    /// assert!(users.is_empty());
    /// ```
    pub fn clear(&self) -> rusqlite::Result<()> {
        self.connection.execute_batch(
            "DELETE FROM users;
             DELETE FROM SQLITE_SEQUENCE WHERE name='users';
             VACUUM;"
        )
    }

    /// Creates a new user.
    ///
    /// # Examples
    ///
    /// ```
    /// # use foxbox_users::users_db::{User, UsersDb, ReadFilter, UserBuilder};
    /// let admin = UserBuilder::new().name(String::from("admin")).set_admin(true).finalize().unwrap();
    /// let db = UsersDb::new(Some("./users_db.sqlite".to_owned()));
    /// assert!(db.create(&admin).is_ok());
    /// ```
    pub fn create(&self, user: &User) -> rusqlite::Result<User> {
        match self.connection.execute("INSERT INTO users
            (name, email, password, secret, is_admin) VALUES ($1, $2, $3, $4, $5)",
            &[&user.name, &user.email, &user.password, &user.secret, &user.is_admin]
        ) {
            Ok(_) => {
               match self.read(ReadFilter::Name(user.name.to_owned())) {
                   Ok(users) => Ok(users[0].to_owned()),
                   Err(err) => Err(err)
               }
            },
            Err(err) => Err(err)
        }
    }

    /// Retrieve filtered users from the database.
    ///
    /// # Example
    ///
    /// Retrieving and filtering users is easy thanks to the `ReadFilter` enum.
    /// For instance, to get all users:
    ///
    /// ```
    /// # use foxbox_users::users_db::{User, UsersDb, ReadFilter};
    /// let all_users: Vec<User> =
    ///     UsersDb::new(Some("./users_db.sqlite".to_owned())).read(ReadFilter::All).unwrap();
    /// ```
    ///
    /// And to quickly find administrators:
    ///
    /// ```
    /// # use foxbox_users::users_db::{User, UsersDb, ReadFilter};
    /// let admins: Vec<User> =
    ///     UsersDb::new(Some("./users_db.sqlite".to_owned())).read(ReadFilter::IsAdmin(true)).unwrap();
    /// ```
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
            },
            ReadFilter::IsAdmin(is_admin) => {
                stmt = try!(
                    self.connection.prepare("SELECT * FROM users where is_admin=$1")
                );
                try!(stmt.query(&[&is_admin]))
            }
        };
        let mut users = Vec::new();
        for result_row in rows {
            let row = try!(result_row);
            users.push(User {
                id: row.get(0),
                name: row.get(1),
                email: row.get(2),
                password: row.get(3),
                secret: row.get(4),
                is_admin: row.get(5)
            });
        }
        Ok(users)
    }

    /// Replaces a pre-existent user, identified by its database id.
    pub fn update(&self, id: i32, user: &User) -> rusqlite::Result<c_int> {
        self.connection.execute("UPDATE users SET name=$1, email=$2, password=$3, secret=$4, is_admin=$5
            WHERE id=$6", &[&user.name, &user.email, &user.password, &user.secret, &user.is_admin, &id])
    }

    /// Removes a user identified by its id.
    pub fn delete(&self, id: i32) -> rusqlite::Result<c_int> {
        self.connection.execute("DELETE FROM users WHERE id=$1", &[&id])
    }
}

#[cfg(test)]
describe! user_builder_tests {
    it "should build a user correctly" {
        use crypto::digest::Digest;
        use crypto::md5::Md5;

        let user = UserBuilder::new()
            .id(1)
            .name(String::from("Mr Fox"))
            .email(String::from("fox@mozilla.org"))
            .password(String::from("pass12345678"))
            .secret(String::from("secret"))
            .finalize()
            .unwrap();

        assert_eq!(user.id, Some(1));
        assert_eq!(user.name, "Mr Fox");
        assert_eq!(user.email, "fox@mozilla.org");
        let mut md5 = Md5::new();
        md5.input_str("pass12345678");
        assert_eq!(user.password, md5.result_str());
        assert_eq!(user.secret, "secret");
    }

    it "should provide a secret event if not explicitly set" {
        use crypto::digest::Digest;
        use crypto::md5::Md5;

        let user = UserBuilder::new()
            .id(1)
            .name(String::from("Mr Fox"))
            .email(String::from("fox@mozilla.org"))
            .password(String::from("pass12345678"))
            .finalize()
            .unwrap();

        assert_eq!(user.id, Some(1));
        assert_eq!(user.name, "Mr Fox");
        assert_eq!(user.email, "fox@mozilla.org");
        let mut md5 = Md5::new();
        md5.input_str("pass12345678");
        assert_eq!(user.password, md5.result_str());
        assert!(!user.secret.is_empty());
    }

    failing "should panic if invalid user" {
        let _user = UserBuilder::new()
            .name(String::from(""))
            .finalize()
            .unwrap();
    }
}

#[cfg(test)]
describe! user_db_tests {
    before_each {
        let usersDb = UsersDb::new(Some("./users_db.sqlite".to_owned()));
        usersDb.clear().ok();

        let defaultUsers = vec![
            UserBuilder::new()
                .id(1).name(String::from("User1"))
                .email(String::from("user1@mozilla.org"))
                .password(String::from("password1"))
                .secret(String::from("secret1"))
                .finalize().unwrap(),
            UserBuilder::new()
                .id(2).name(String::from("User2"))
                .email(String::from("user2@mozilla.org"))
                .password(String::from("password2"))
                .secret(String::from("secret2"))
                .finalize().unwrap(),
            UserBuilder::new()
                .id(3).name(String::from("User3"))
                .email(String::from("user3@mozilla.org"))
                .password(String::from("password3"))
                .secret(String::from("secret3"))
                .finalize().unwrap(),
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
        for (user, defaultUser) in usersInDb.iter().zip(defaultUsers) {
            assert_eq!(*user, defaultUser);
        }
    }

    it "should read user by id" {
        for user in &defaultUsers {
            let users = usersDb.read(
                ReadFilter::Id(user.id.unwrap())).unwrap();
            assert_eq!(users.len(), 1);
            assert_eq!(users[0].id, user.id);
            assert_eq!(users[0].name, user.name);
            assert_eq!(users[0].email, user.email);
            assert_eq!(users[0].password, user.password);
            assert_eq!(users[0].secret, user.secret);
        }
    }

    it "should read user by name" {
        for user in &defaultUsers {
            let users = usersDb.read(
                ReadFilter::Name(user.name.clone())).unwrap();
            assert_eq!(users.len(), 1);
            assert_eq!(users[0].id, user.id);
            assert_eq!(users[0].name, user.name);
            assert_eq!(users[0].email, user.email);
            assert_eq!(users[0].password, user.password);
            assert_eq!(users[0].secret, user.secret);
        }
    }

    it "should read user by email" {
        for user in &defaultUsers {
            let users = usersDb.read(
                ReadFilter::Email(user.email.clone())).unwrap();
            assert_eq!(users.len(), 1);
            assert_eq!(users[0].id, user.id);
            assert_eq!(users[0].name, user.name);
            assert_eq!(users[0].email, user.email);
            assert_eq!(users[0].password, user.password);
            assert_eq!(users[0].secret, user.secret);
        }
    }

    it "should read user by name or email with name" {
        for (i, user) in defaultUsers.iter().enumerate() {
            let users = usersDb.read(ReadFilter::Credentials(
                user.name.clone(), format!("password{}", i + 1))
            ).unwrap();
            assert_eq!(users.len(), 1);
            assert_eq!(users[0].id, user.id);
            assert_eq!(users[0].name, user.name);
            assert_eq!(users[0].email, user.email);
            assert_eq!(users[0].password, user.password);
            assert_eq!(users[0].secret, user.secret);
        }
    }

    it "should read user by name or email with email" {
        for (i, user) in defaultUsers.iter().enumerate() {
            let users = usersDb.read(ReadFilter::Credentials(
                user.name.clone(), format!("password{}", i + 1))
            ).unwrap();
            assert_eq!(users.len(), 1);
            assert_eq!(users[0].id, user.id);
            assert_eq!(users[0].name, user.name);
            assert_eq!(users[0].email, user.email);
            assert_eq!(users[0].password, user.password);
            assert_eq!(users[0].secret, user.secret);
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
        user.name = "New Name".to_owned();

        usersDb.update(user.id.unwrap(), &user).unwrap();

        let users = usersDb.read(ReadFilter::All).unwrap();

        assert_eq!(user, users[0]);
    }

    it "should not retrieve any records" {
        let users = usersDb.read(ReadFilter::Name(
            "Xyz' OR '1'='1".to_owned())
        ).unwrap();
        assert_eq!(users.len(), 0);

        let users = usersDb.read(ReadFilter::Name(
            "Xyz\' OR \'1\'=\'1".to_owned())
        ).unwrap();
        assert_eq!(users.len(), 0);

        let users = usersDb.read(ReadFilter::Name(
            "Xyz\\' OR \\'1\\'=\\'1".to_owned())
        ).unwrap();
        assert_eq!(users.len(), 0);

        let users = usersDb.read(ReadFilter::Credentials(
            "1\' OR \'1\' = \'1\'))/*".to_owned(), "foo".to_owned()
        )).unwrap();
        assert_eq!(users.len(), 0);
    }

    it "should not create admin users by default" {
        let admins = usersDb.read(ReadFilter::IsAdmin(true)).unwrap();
        assert_eq!(admins.len(), 0);
    }

    it "should create admin user when requested" {
        let admin = UserBuilder::new().name(String::from("Admin"))
                .email(String::from("admin@mozilla.org"))
                .password(String::from("password!"))
                .set_admin(true)
                .finalize().unwrap();
        usersDb.create(&admin).unwrap();

        let admins = usersDb.read(ReadFilter::IsAdmin(true)).unwrap();

        assert_eq!(admins.len(), 1);
        assert_eq!(admins[0].name, admin.name);
    }
}
