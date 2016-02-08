/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// Usage example.

extern crate foxbox_users;
extern crate iron;
extern crate router;

use foxbox_users::users_router::{UsersRouter};
use iron::prelude::*;
use router::Router;

fn main() {
    let mut router = Router::new();

    UsersRouter::start(&mut router);

    Iron::new(router).http("localhost:3000").unwrap();
}
