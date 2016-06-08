[![Build Status](https://travis-ci.org/fxbox/users.svg?branch=master)](https://travis-ci.org/fxbox/users)
[![License](https://img.shields.io/badge/license-MPL2-blue.svg)](https://raw.githubusercontent.com/fxbox/users/master/LICENSE)

# Project Link Users

This crate implements a user management and authentication library for the
first iteration of [Project Link](https://wiki.mozilla.org/Project_Link). It is
currently used by [FoxBox](https://github.com/fxbox/foxbox), the core of
Project Link. It intentionally allows only the registration and authentication
of a single user, although the database module is ready for a multi-user
scenario. The crate is being built with Project Link's requirements in mind,
but it is completely independent from it and could be reused and extended for
other purposes.

The main modules that this crate exposes are:

 - *users_router*:  Allows the extension of an Iron based server with the user
   management routes. You can read more about the HTTP API that is exposed on
   these routes on the [API
   documentation](https://github.com/fxbox/users/blob/master/doc/API.md).
 - *users_db*: This module allows direct modification of the users' database.
   Based on [rusqlite](https://github.com/jgallagher/rusqlite).
 - *auth_middleware*: Iron middleware that allows the authentication of
   specific endpoints.


## Usage

### Rust

Currently v1.10.x nightly is required

```bash
$ rustc -V
rustc 1.10.0-nightly (62e2b2fb7 2016-05-06)
```

It's recommended that you use [`multirust`](https://github.com/brson/multirust)
to install and switch between versions of Rust.

```bash
$ multirust override nightly-2016-05-07
```

### Exposing the HTTP API

```rust
extern crate foxbox_users;
extern crate iron;

use foxbox_users::UsersManager;
use iron::prelude::*;

fn main() {
    // Invitation email dispatcher
    fn dispatcher(email: String, path: String) -> () {
      // You are supposed to send an email here.
      println!("This is a dummy email dispatcher callback {}", path);
    };
    let manager = UsersManager::new("sqlite_db.sqlite");
    let users_router = manager.get_users_router();
    let router = Arc::new(RwLock::new(users_router.router));
    thread::spawn(move || {
        println!("Adding invitation dispatcher");
        thread::sleep(Duration::from_millis(1000));
        let mut guard = router.write().unwrap();
        guard.set_invitation_dispatcher(dispatcher);
    });
    Iron::new(users_router.chain).http("localhost:3000").unwrap();
}
```

### Authenticating endpoints

```rust
extern crate foxbox_users;
extern crate iron;
extern crate router;

use foxbox_users::{ AuthEndpoint, UsersManager };
use iron::method::Method;
use iron::prelude::*;
use iron::status;
use router::Router;
use std::thread;
use std::time::Duration;

fn dummy_handler(_: &mut Request) -> IronResult<Response> {
    Ok(Response::with(status::Ok))
}

fn main() {
    let manager = UsersManager::new("sqlite_db.sqlite");
    let mut router =  Router::new();
    router.get("/authenticated", dummy_handler);
    router.get("/authenticated2", dummy_handler);
    router.get("/not_authenticated", dummy_handler);

    let mut chain = Chain::new(router);
    let mut middleware = manager.get_middleware(
        vec![AuthEndpoint(vec![Method::Get, Method::Delete],
                          "/authenticated".to_owned())]
    );

    chain.link_around(middleware.clone());

    thread::spawn(move || {
        println!("Adding new auth endpoint");
        thread::sleep(Duration::from_millis(3000));
        // Add new authenticated endpoints after the middleware has been given
        // to the Iron chain and the Iron server has started.
        middleware.add_auth_endpoints(vec![
             AuthEndpoint(vec![Method::Get],
                          "/authenticated2".to_owned())
        ]);
    });

    Iron::new(chain).http("localhost:3000").unwrap();
}
```

### Direct access to users database

```rust
extern crate foxbox_users;

use foxbox_users::{ReadFilter, UserBuilder};

fn main() {
    let manager = UsersManager::new("sqlite_db.sqlite");
    let db = manager.get_db();
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
$ cargo test
```

### Documentation

```bash
$ cargo doc
```

Then open `./target/doc/foxbox_users/index.html`. There is not online version
available yet.
