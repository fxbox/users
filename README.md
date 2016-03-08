[![Build Status](https://travis-ci.org/fxbox/users.svg?branch=master)](https://travis-ci.org/fxbox/users)
[![License](https://img.shields.io/badge/license-MPL2-blue.svg)](https://raw.githubusercontent.com/fxbox/users/master/LICENSE)

# Project Link Users
This crate implements a user management and authentication library for the first iteration of [Project Link](https://wiki.mozilla.org/Project_Link). It is currently used by [FoxBox](https://github.com/fxbox/foxbox), the core of Project Link. It intentionally allows only the registration and authentication of a single user, although the database module is ready for a multi-user scenario. The crate is being built with Project Link's requirements in mind, but it is completely independent from it and could be reused and extended for other purposes.

The main modules that this crate exposes are:

* *users_router*:  Allows the extension of an Iron based server with the user management routes. You can read more about the HTTP API that is exposed on these routes on the [API documentation](https://github.com/fxbox/users/blob/master/doc/API.md).
* *users_db*: This module allows direct modification of the users' database. Based on [rusqlite](https://github.com/jgallagher/rusqlite).
* *auth_middleware*: Iron middleware that allows the authentication of specific endpoints.

## Usage
### Rust
Currently v1.9.x nightly is required
```bash
$ rustc -V
rustc 1.9.0-nightly (998a6720b 2016-03-07)
```
It's recommended that you use [`multirust`](https://github.com/brson/multirust) to install and switch between versions of Rust.
```bash
$ multirust override nightly-2016-03-07
```
### Exposing the HTTP API
```rust
extern crate foxbox_users;
extern crate iron;

use foxbox_users::users_router::UsersRouter;
use iron::prelude::*;

fn main() {
    let router = UsersRouter::init();
    Iron::new(router).http("localhost:3000").unwrap();
}
```
### Authenticating endpoints
```rust
extern crate foxbox_users;
extern crate iron;
extern crate router;

use foxbox_users::auth_middleware::{AuthEndpoint, AuthMiddleware};
use iron::method::Method;
use iron::prelude::*;
use iron::status;
use router::Router;

fn dummy_handler(_: &mut Request) -> IronResult<Response> {
    Ok(Response::with(status::Ok))
}

fn main() {
    let mut router =  Router::new();
    router.get("/authenticated", dummy_handler);
    router.get("/not_authenticated", dummy_handler);

    let mut chain = Chain::new(router);
    chain.around(AuthMiddleware{
        auth_endpoints: vec![
            AuthEndpoint(Method::Get, vec!["authenticated".to_string()])
        ]
    });

    Iron::new(chain).http("localhost:3000").unwrap();
}
```
### Direct access to users database
```rust
extern crate foxbox_users;

use foxbox_users::users_db::{ReadFilter, UserBuilder, UsersDb};

fn main() {
    let db = UsersDb::new();
    let user = UserBuilder::new()
        .name("MrFox")
        .email("fox@foxlink.org")
        .password("pass12345678")
        .finalize()
        .unwrap();
    db.create(&user).unwrap();
    match db.read(ReadFilter::All) {
        Ok(users) => {
            println!("Users {:?}", users);
        },
        Err(err) => println!("{}", err)
    }
}
```
## Contributing
Note: We're in an iterative prototyping phase of the project. Things are moving
really fast so it may be easier to contribute when the dust starts to settle.
You've been warned.
### Forks and feature branches
You should fork the main repo and create pull requests against feature branches
of your fork. If you need some guidance with this see:
 - https://guides.github.com/introduction/flow/
 - http://scottchacon.com/2011/08/31/github-flow.html

### Setup
```bash
$ git clone git@github.com:<username>/users.git
$ cd users
```
### Building the lib
```bash
$ cargo build
```
### Rust tests
```bash
$ RUST_TEST_THREADS=1 cargo test
```
### Documentation
```bash
$ cargo doc
```
Then open `./target/doc/foxbox_users/index.html`. There is not online version available yet.
