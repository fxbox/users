extern crate foxbox_users;
extern crate iron;
extern crate router;

use foxbox_users::users_router::{UserRouter};
use iron::prelude::*;
use router::Router;

fn main() {
    let mut router = Router::new();

    UserRouter::start(&mut router);

    Iron::new(router).http("localhost:3000").unwrap();
}
