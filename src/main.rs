/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// Usage example.

extern crate foxbox_users;
extern crate iron;
extern crate router;

use foxbox_users::users_db::{UserBuilder, UsersDb};
use foxbox_users::users_router::UsersRouter;
use iron::prelude::*;
use router::Router;

fn main() {
    let db = UsersDb::new();
    let user = UserBuilder::new()
        .name("Peter")
        .email("peter@domain.org")
        .password("pass12345678")
        .finalize()
        .unwrap();

    println!("Creating user {:?}", user);
    match db.create(&user) {
        Ok(_) => println!("Yay!"),
        Err(err) => println!("Crap {}", err)
    }
    match db.read() {
        Ok(users) => {
            println!("Users {:?}", users);
            let mut user = users[0].clone();
            user.name = "Pedro".to_string();
            db.update(user.id.unwrap(), &user).unwrap();
        },
        Err(err) => println!("Crap {}", err)
    }
    match db.read() {
        Ok(users) => {
            println!("Users {:?}", users);
            db.delete(users[0].id.unwrap());
        },
        Err(err) => println!("Crap {}", err)
    }
    match db.read() {
        Ok(users) => println!("Users {:?}", users),
        Err(err) => println!("Crap {}", err)
    }
    let mut router = Router::new();
    UsersRouter::start(&mut router, Some("/users"));
    // For an unprefixed solution do:
    // UsersRouter::start(&mut router, None);
    Iron::new(router).http("localhost:3000").unwrap();
}
