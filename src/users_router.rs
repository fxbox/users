/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

extern crate unicase;
extern crate iron;
extern crate router;

use self::iron::{AfterMiddleware, headers, status};
use self::iron::method::Method::*;
use self::iron::prelude::*;
use self::router::Router;
use self::unicase::UniCase;

struct CORS;

impl AfterMiddleware for CORS {
    fn after(&self, req: &mut Request, mut res: Response)
        -> IronResult<Response> {

        // Endpoints listed here will be denied CORS.
        // Endpoints containing a variable path can use '*' like in:
        // &["users", "*"]
        const SAME_ORIGIN_ONLY_ENDPOINTS: &'static[&'static[&'static str]] =
            &[&["setup"]];

        let mut is_soo_endpoint = false;
        for endpoint in SAME_ORIGIN_ONLY_ENDPOINTS {
            if endpoint.len() != req.url.path.len() {
                continue;
            }
            for (i, path) in endpoint.iter().enumerate() {
                is_soo_endpoint = false;
                if req.url.path[i] != path.to_string() &&
                   "*".to_string() != path.to_string() {
                    break;
                }
                is_soo_endpoint = true;
            }
            if is_soo_endpoint {
                break;
            }
        }

        if is_soo_endpoint {
            return Ok(res);
        }

        res.headers.set(headers::AccessControlAllowOrigin::Any);
        res.headers.set(headers::AccessControlAllowHeaders(
                vec![UniCase("accept".to_string()),
                UniCase("content-type".to_string())]));
        res.headers.set(headers::AccessControlAllowMethods(
                vec![Get,Head,Post,Delete,Options,Put,Patch]));
        Ok(res)
    }
}

pub struct UsersRouter;

impl UsersRouter {
    fn not_implemented(_: &mut Request) -> IronResult<Response> {
        println!("Not implemented");
        Ok(Response::with(status::NotImplemented))
    }

    pub fn new() -> iron::middleware::Chain {
        let mut router = Router::new();

        router.post("/setup", UsersRouter::not_implemented);

        router.post("/invitations", UsersRouter::not_implemented);
        router.get("/invitations", UsersRouter::not_implemented);
        router.delete("invitations", UsersRouter::not_implemented);

        router.post("/users", UsersRouter::not_implemented);
        router.get("/users", UsersRouter::not_implemented);
        router.put("/users/:id", UsersRouter::not_implemented);
        router.post("/users/:id", UsersRouter::not_implemented);

        router.post("/recoveries/:user", UsersRouter::not_implemented);
        router.get("/recoveries/:user/:id", UsersRouter::not_implemented);

        router.get("/permissions", UsersRouter::not_implemented);
        router.get("/permissions/:user", UsersRouter::not_implemented);
        router.get("/permissions/:user/:taxon", UsersRouter::not_implemented);
        router.get("/permissions/_/:taxon", UsersRouter::not_implemented);
        router.put("/permissions/:user/:taxon", UsersRouter::not_implemented);

        let mut chain = Chain::new(router);
        chain.link_after(CORS);

        chain
    }
}
