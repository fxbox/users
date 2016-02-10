/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

extern crate iron;
extern crate router;

use self::iron::prelude::*;
use self::iron::status;

pub struct UsersRouter;

impl UsersRouter {
    fn not_implemented(_: &mut Request) -> IronResult<Response> {
        println!("Not implemented");
        Ok(Response::with(status::NotImplemented))
    }

    pub fn start(router: &mut router::Router, prfx: Option<&'static str>) {
        let mut prefix = String::new();
        match prfx {
            Some(param) => prefix = param.to_string(),
            None => prefix = "".to_string(),
        }
        router.post(prefix.to_string() + "/setup", UsersRouter::not_implemented);

        router.post(prefix.to_string() + "/invitation", UsersRouter::not_implemented);
        router.get(prefix.to_string() + "/invitation", UsersRouter::not_implemented);
        router.delete(prefix.to_string() + "/invitation", UsersRouter::not_implemented);

        router.post(prefix.to_string() + "/users", UsersRouter::not_implemented);
        router.get(prefix.to_string() + "/users", UsersRouter::not_implemented);
        router.put(prefix.to_string() + "/users/:id", UsersRouter::not_implemented);
        router.post(prefix.to_string() + "/users/:id", UsersRouter::not_implemented);

        router.post(prefix.to_string() + "/recoveries/:user", UsersRouter::not_implemented);
        router.get(prefix.to_string() + "/recoveries/:user/:id", UsersRouter::not_implemented);

        router.get(prefix.to_string() + "/permissions", UsersRouter::not_implemented);
        router.get(prefix.to_string() + "/permissions/:user", UsersRouter::not_implemented);
        router.get(prefix.to_string() + "/permissions/:user/:taxon", UsersRouter::not_implemented);
        router.get(prefix.to_string() + "/permissions/_/:taxon", UsersRouter::not_implemented);
        router.put(prefix.to_string() + "/permissions/:user/:taxon", UsersRouter::not_implemented);
    }
}
