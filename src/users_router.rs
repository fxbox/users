/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use super::users_db::{UserBuilder, UsersDb};
use super::errors::*;

use iron::{AfterMiddleware, headers, status};
use iron::method::Method;
use iron::method::Method::*;
use iron::prelude::*;
use router::Router;
use rustc_serialize::json;
use unicase::UniCase;

use std::error::Error;
use std::io::Read;

type Endpoint = (Method, &'static[&'static str]);

struct CORS;

impl CORS {
    // Only endpoints listed here will allow CORS.
    // Endpoints containing a variable path part can use '*' like in:
    // &["users", "*"]
    pub const ENDPOINTS: &'static[Endpoint] = &[
        (Method::Post,      &["invitations"]),
        (Method::Get,       &["invitations"]),
        (Method::Delete,    &["invitations"]),
        (Method::Post,      &["users"]),
        (Method::Get,       &["users"]),
        (Method::Put,       &["users", "*"]),
        (Method::Post,      &["users", "*"]),
        (Method::Post,      &["recoveries", "*"]),
        (Method::Get,       &["recoveries", "*", "*"]),
        (Method::Get,       &["permissions"]),
        (Method::Get,       &["permissions", "*"]),
        (Method::Get,       &["permissions", "*", "*"]),
        (Method::Get,       &["permissions", "_", "*"]),
        (Method::Put,       &["permissions", "*", "*"]),
    ];
}

impl AfterMiddleware for CORS {
    fn after(&self, req: &mut Request, mut res: Response)
        -> IronResult<Response> {

        let mut is_cors_endpoint = false;
        for endpoint in CORS::ENDPOINTS {
            let (ref method, path) = *endpoint;
            if req.method != *method {
                continue;
            }
            if path.len() != req.url.path.len() {
                continue;
            }
            for (i, path) in path.iter().enumerate() {
                is_cors_endpoint = false;
                if req.url.path[i] != path.to_string() &&
                   "*".to_string() != path.to_string() {
                    break;
                }
                is_cors_endpoint = true;
            }
            if is_cors_endpoint {
                break;
            }
        }

        if !is_cors_endpoint {
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
        Ok(Response::with(status::NotImplemented))
    }

    fn setup(req: &mut Request) -> IronResult<Response> {
        #[derive(RustcDecodable, Debug)]
        struct SetupBody {
            username: String,
            email: String,
            password: String
        }

        let mut payload = String::new();
        req.body.read_to_string(&mut payload).unwrap();
        let body: SetupBody = match json::decode(&payload) {
            Ok(body) => body,
            Err(error) => {
                println!("{:?}", error);
                return from_decoder_error(error);
            }
        };

        let admin = match UserBuilder::new()
            .name(&body.username)
            .email(&body.email)
            .password(&body.password)
            .finalize() {
                Ok(user) => user,
                Err(error) => {
                    println!("{:?}", error);
                    return EndpointError::new(
                        status::BadRequest,
                        400
                    );
                }
            };

        let db = UsersDb::new();
        match db.create(&admin) {
            Ok(_) => Ok(Response::with(status::Ok)),
            Err(error) => {
                println!("{:?}", error);
                from_sqlite_error(error)
            }
        }
    }

    pub fn new() -> super::iron::middleware::Chain {
        let mut router = Router::new();

        router.post("/setup", UsersRouter::setup);

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

#[test]
fn test_cors_allowed_endpoints() {
    use iron::method;
    use super::stubs::*;

    // Test that all CORS allowed endpoints get the appropriate CORS headers.
    for endpoint in CORS::ENDPOINTS {
        let (ref method, path) = *endpoint;
        let path = path.join("/").replace("*", "foo");
        let mut req = request(method, &path);
        match CORS.after(&mut req, Response::new()) {
            Ok(res) => {
                let headers = &res.headers;
                assert!(headers.has::<headers::AccessControlAllowOrigin>());
                assert!(headers.has::<headers::AccessControlAllowHeaders>());
                assert!(headers.has::<headers::AccessControlAllowMethods>());
            },
            _ => assert!(false)
        }
    }

    // Test that non-CORS-allowed endpoints like POST /setup don't get CORS
    // headers in the response.
    let mut req = request(&method::Post, "/setup");
    match CORS.after(&mut req, Response::new()) {
        Ok(res) => {
            let headers = &res.headers;
            assert!(!headers.has::<headers::AccessControlAllowOrigin>());
            assert!(!headers.has::<headers::AccessControlAllowHeaders>());
            assert!(!headers.has::<headers::AccessControlAllowMethods>());
        },
        _ => assert!(false)
    }
}

#[test]
fn test_users_router_not_implemented_endpoints() {
    use iron::middleware::Handler;
    use iron::status::Status;
    use super::stubs::*;

    let router = UsersRouter::new();

    const ENDPOINTS: &'static[Endpoint] = &[
        (Method::Post,      &["invitations"]),
        (Method::Get,       &["invitations"]),
        (Method::Delete,    &["invitations"]),
        (Method::Post,      &["users"]),
        (Method::Get,       &["users"]),
        (Method::Put,       &["users", "*"]),
        (Method::Post,      &["users", "*"]),
        (Method::Post,      &["recoveries", "*"]),
        (Method::Get,       &["recoveries", "*", "*"]),
        (Method::Get,       &["permissions"]),
        (Method::Get,       &["permissions", "*"]),
        (Method::Get,       &["permissions", "*", "*"]),
        (Method::Get,       &["permissions", "_", "*"]),
        (Method::Put,       &["permissions", "*", "*"]),
    ];

    for endpoint in ENDPOINTS {
        let (ref method, path) = *endpoint;
        let path = path.join("/").replace("*", "foo");
        let res = Handler::handle(&router, &mut request(method, &path));
        assert_eq!(res.unwrap().status.unwrap(), Status::NotImplemented);
    }
}

#[test]
fn test_setup_endpoint() {
    assert!(true);
}
