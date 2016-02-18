/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// Usage example.

extern crate foxbox_users;
extern crate iron;
extern crate router;

use foxbox_users::users_db::{ReadFilter, UserBuilder, UsersDb};
use foxbox_users::users_router::UsersRouter;
use foxbox_users::auth_middleware::AuthMiddleware;
use iron::prelude::*;

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
    match db.read(ReadFilter::All) {
        Ok(users) => {
            println!("Users {:?}", users);
            let mut user = users[0].clone();
            user.name = "Pedro".to_string();
            db.update(user.id.unwrap(), &user).unwrap();
        },
        Err(err) => println!("Crap {}", err)
    }
    match db.read(ReadFilter::All) {
        Ok(users) => {
            println!("Users {:?}", users);
            db.delete(users[0].id.unwrap()).unwrap();
        },
        Err(err) => println!("Crap {}", err)
    }
    match db.read(ReadFilter::All) {
        Ok(users) => println!("Users {:?}", users),
        Err(err) => println!("Crap {}", err)
    }
    let router = UsersRouter::new();
    let mut chain = Chain::new(router);
    chain.around(AuthMiddleware{
        auth_endpoints: vec![]
    });
    Iron::new(chain).http("localhost:3000").unwrap();
}
