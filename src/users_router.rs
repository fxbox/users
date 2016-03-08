/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//! Contains the Iron router for user managing.
//!
//! # User Management Router
//!
//! The module contains the `UsersRouter` middleware in charge of managing
//! user-related REST operations. Exhaustive
//! [REST documentation](https://github.com/fxbox/users/blob/master/doc/API.md)
//! can be found in the GitHub repository.

use super::auth_middleware::SessionToken;
use super::users_db::{User, UserBuilder, UsersDb, ReadFilter};
use super::errors::*;

use iron::{AfterMiddleware, headers, status};
use iron::headers::{Authorization, Basic};
use iron::method::Method;
use iron::method::Method::*;
use iron::prelude::*;
use router::Router;
use rustc_serialize::json;
use unicase::UniCase;

use std::io::Read;

type Endpoint = (Method, &'static[&'static str]);

struct CORS;

impl CORS {
    // Only endpoints listed here will allow CORS.
    // Endpoints containing a variable path part can use '*' like in:
    // &["bar", "*"] for a URL like https://foo.com/bar/123
    pub const ENDPOINTS: &'static[Endpoint] = &[
        (Method::Post, &["login"])
    ];
}

impl AfterMiddleware for CORS {
    fn after(&self, req: &mut Request, mut res: Response)
        -> IronResult<Response> {

        let mut is_cors_endpoint = false;
        for endpoint in CORS::ENDPOINTS {
            let (ref method, path) = *endpoint;
            if req.method != *method &&
               req.method != Method::Options {
                continue;
            }
            if path.len() != req.url.path.len() {
                continue;
            }
            for (i, path) in path.iter().enumerate() {
                is_cors_endpoint = false;
                if req.url.path[i] != path.to_owned() &&
                   "*" != path.to_owned() {
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
            vec![
                UniCase(String::from("accept")),
                UniCase(String::from("authorization")),
                UniCase(String::from("content-type"))
            ]
        ));
        res.headers.set(headers::AccessControlAllowMethods(
            vec![Get,Head,Post,Delete,Options,Put,Patch]
        ));
        Ok(res)
    }
}

type Credentials = (String, String);

#[derive(Debug, RustcDecodable, RustcEncodable)]
struct LoginResponse {
    session_token: String
}

impl LoginResponse {
    fn with_user(user: &User) -> IronResult<Response> {
        let session_token = match SessionToken::for_user(&user) {
            Ok(token) => token,
            Err(_) => return EndpointError::with(
                status::InternalServerError, 500
            )
        };
        let body_obj = LoginResponse{
           session_token: session_token
        };
        let body = match json::encode(&body_obj) {
            Ok(body) => body,
            Err(_) => return EndpointError::with(
                status::InternalServerError, 500
            )
        };
        Ok(Response::with((status::Created, body)))
    }
}

/// Manages user-related REST operations.
///
/// # Examples
///
/// To install the router, you use:
///
/// ```
/// extern crate iron;
/// extern crate foxbox_users;
///
/// fn main() {
///     use foxbox_users::users_router::UsersRouter;
///     use iron::prelude::{Chain, Iron};
///
///     let router = UsersRouter::init();
///     let mut chain = Chain::new(router);
/// # if false {
///     Iron::new(chain).http("localhost:3000").unwrap();
/// # }
/// }
/// ```
pub struct UsersRouter;

impl UsersRouter {
    fn setup(req: &mut Request) -> IronResult<Response> {
        #[derive(RustcDecodable, Debug)]
        struct SetupBody {
            username: String,
            email: String,
            password: String
        }

        // This endpoint should be disabled and return error 410 (Gone)
        // if there is any admin user already configured.
        let db = UsersDb::new(None);
        let admins = db.read(ReadFilter::IsAdmin(true)).unwrap();
        if !admins.is_empty() {
            return EndpointError::with(status::Gone, 410);
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
            .name(body.username)
            .email(body.email)
            .password(body.password)
            .set_admin(true)
            .finalize() {
                Ok(user) => user,
                Err(error) => {
                    println!("{:?}", error);
                    return EndpointError::with(
                        status::BadRequest, 400
                    );
                }
            };

        match db.create(&admin) {
            Ok(admin) => {
                LoginResponse::with_user(&admin)
            },
            Err(error) => {
                println!("{:?}", error);
                from_sqlite_error(error)
            }
        }
    }

    fn login(req: &mut Request) -> IronResult<Response> {

        // Return Some pair of valid credentials if both username and password
        // are provided or None elsewhere.
        fn credentials_from_header(auth: &Authorization<Basic>)
            -> Option<Credentials> {
            let &Authorization(Basic {
                ref username,
                password: ref maybe_password
            }) = auth;
            let something_is_missed =
                username.is_empty() || match *maybe_password {
                    None => true,
                    Some(ref psw) => psw.is_empty()
                };
            if something_is_missed {
                None
            } else {
                Some((
                    username.to_owned(),
                    maybe_password.as_ref().unwrap().to_owned()
                ))
            }
        }

        let error103 = EndpointError::with(status::BadRequest, 103);
        let header: Option<&Authorization<Basic>> = req.headers.get();
        if let Some(auth) = header {
            if let Some((username, password)) = credentials_from_header(auth) {
                let users_db = UsersDb::new(None);
                let users = match users_db.read(
                    ReadFilter::Credentials(username, password)) {
                    Ok(users) => users,
                    Err(_) => return EndpointError::with(
                        status::InternalServerError, 500
                    )
                };
                if users.len() != 1 {
                    return EndpointError::with(status::Unauthorized, 401);
                }
                LoginResponse::with_user(&users[0])
            } else {
                error103
            }
        } else {
            error103
        }
    }

    /// Creates the Iron user router middleware.
    pub fn init() -> super::iron::middleware::Chain {
        let mut router = Router::new();

        router.post("/setup", UsersRouter::setup);
        router.post("/login", UsersRouter::login);

        let mut chain = Chain::new(router);
        chain.link_after(CORS);

        chain
    }
}

#[cfg(test)]
describe! cors_tests {
    before_each {
        use iron::{headers, Headers};
        use iron_test::request;

        let router = UsersRouter::init();
    }

    it "should get the appropriate CORS headers" {
        use super::CORS;

        for endpoint in CORS::ENDPOINTS {
            let (_, path) = *endpoint;
            let path = "http://localhost:3000/".to_owned() +
                       &(path.join("/").replace("*", "foo"));
            match request::options(&path, Headers::new(), &router) {
                Ok(res) => {
                    let headers = &res.headers;
                    assert!(headers.has::<headers::AccessControlAllowOrigin>());
                    assert!(headers.has::<headers::AccessControlAllowHeaders>());
                    assert!(headers.has::<headers::AccessControlAllowMethods>());
                },
                _ => {
                    assert!(false)
                }
            }
        }
    }

    it "should not get CORS headers" {
        match request::options("http://localhost:3000/setup", Headers::new(),
                               &router) {
            Ok(res) => {
                let headers = &res.headers;
                assert!(!headers.has::<headers::AccessControlAllowOrigin>());
                assert!(!headers.has::<headers::AccessControlAllowHeaders>());
                assert!(!headers.has::<headers::AccessControlAllowMethods>());
            },
            _ => {
                assert!(false)
            }
        }
    }
}

#[cfg(test)]
describe! setup_tests {
    before_each {
        use iron::Headers;
        use iron::status::Status;
        use iron_test::request;
        use super::super::users_db::UsersDb;

        let router = UsersRouter::init();
        let usersDb = UsersDb::new(Some("./users_db.sqlite".to_owned()));
        usersDb.clear().ok();

        let endpoint = "http://localhost:3000/setup";
    }

    it "should respond 201 Created for a proper POST /setup" {
        use super::LoginResponse;
        use super::super::auth_middleware::SessionClaims;
        use iron::prelude::Response;
        use iron_test::response::extract_body_to_string;
        use jwt;
        use rustc_serialize::Decodable;
        use rustc_serialize::json::{self, DecodeResult};

        fn extract_body_to<T: Decodable>(response: Response) -> DecodeResult<T> {
            json::decode(&extract_body_to_string(response))
        }

        match request::post(endpoint, Headers::new(),
                            "{\"username\": \"username\",
                              \"email\": \"username@domain.com\",
                              \"password\": \"password\"}",
                            &router) {
            Ok(res) => {
                assert_eq!(res.status.unwrap(), Status::Created);
                let body_obj = extract_body_to::<LoginResponse>(res).unwrap();
                let token = body_obj.session_token;
                let claims = jwt::Token::<jwt::Header, SessionClaims>::parse(&token)
                    .ok().unwrap().claims;
                assert_eq!(claims.name, "username");
            },
            Err(err) => {
                println!("{:?}", err);
                assert!(false);
            }
        };
    }

    it "should create one admin user" {
        use super::super::users_db::ReadFilter;

        let body = "{\"username\": \"username\",\
                    \"email\": \"username@domain.com\",\
                    \"password\": \"password\"}";

        if let Ok(res) = request::post(endpoint, Headers::new(), body, &router) {
            assert_eq!(res.status.unwrap(), Status::Created);
            let admins = usersDb.read(ReadFilter::IsAdmin(true)).unwrap();
            assert_eq!(admins.len(), 1);
            assert_eq!(admins[0].email, "username@domain.com");
        } else {
            assert!(false);
        }
    }

    it "should respond 410 Gone if an admin account exists" {
        use iron::prelude::Response;
        use rustc_serialize::Decodable;
        use rustc_serialize::json::{self, DecodeResult};
        fn extract_body_to<T: Decodable>(response: Response) -> DecodeResult<T> {
            use iron_test::response::extract_body_to_string;
            json::decode(&extract_body_to_string(response))
        }

        use super::super::errors::{ErrorBody};

        // Be sure we have an admin
        use super::super::users_db::UserBuilder;
        usersDb.create(&UserBuilder::new()
                   .id(1).name(String::from("admin"))
                   .password(String::from("password!!"))
                   .email(String::from("admin@example.com"))
                   .set_admin(true)
                   .finalize().unwrap()).ok();
        match request::post(endpoint, Headers::new(),
                            "{\"username\": \"u\",
                              \"email\": \"u@d\",
                              \"password\": \"12345678\"}",
                            &router) {
            Ok(_) => {
                assert!(false);
            },
            Err(error) => {
                let response = error.response;
                assert!(response.status.is_some());
                assert_eq!(response.status.unwrap(), Status::Gone);
                let json = extract_body_to::<ErrorBody>(response).unwrap();
                assert_eq!(json.errno, 410);
            }
        }
    }

    it "should respond 400 BadRequest, errno 100 if username is missing" {
        use iron::prelude::Response;
        use rustc_serialize::Decodable;
        use rustc_serialize::json::{self, DecodeResult};
        fn extract_body_to<T: Decodable>(response: Response) -> DecodeResult<T> {
            use iron_test::response::extract_body_to_string;
            json::decode(&extract_body_to_string(response))
        }

        use super::super::errors::{ErrorBody};

        match request::post(endpoint, Headers::new(),
                            "{\"email\": \"u@d\",
                              \"password\": \"12345678\"}",
                            &router) {
            Ok(_) => {
                assert!(false);
            },
            Err(error) => {
                let response = error.response;
                assert!(response.status.is_some());
                assert_eq!(response.status.unwrap(), Status::BadRequest);
                let json = extract_body_to::<ErrorBody>(response).unwrap();
                assert_eq!(json.errno, 100);
            }
        };
    }

    it "should respond 400 BadRequest, errno 101 if email is missing" {
        use iron::prelude::Response;
        use rustc_serialize::Decodable;
        use rustc_serialize::json::{self, DecodeResult};
        fn extract_body_to<T: Decodable>(response: Response) -> DecodeResult<T> {
            use iron_test::response::extract_body_to_string;
            json::decode(&extract_body_to_string(response))
        }

        use super::super::errors::{ErrorBody};

        match request::post(endpoint, Headers::new(),
                            "{\"username\": \"u\",
                              \"password\": \"12345678\"}",
                            &router) {
            Ok(_) => {
                assert!(false);
            },
            Err(error) => {
                let response = error.response;
                assert!(response.status.is_some());
                assert_eq!(response.status.unwrap(), Status::BadRequest);
                let json = extract_body_to::<ErrorBody>(response).unwrap();
                assert_eq!(json.errno, 101);
            }
        };
    }

    it "should respond 400 BadRequest, errno 102 if password is missing" {
        use iron::prelude::Response;
        use rustc_serialize::Decodable;
        use rustc_serialize::json::{self, DecodeResult};
        fn extract_body_to<T: Decodable>(response: Response) -> DecodeResult<T> {
            use iron_test::response::extract_body_to_string;
            json::decode(&extract_body_to_string(response))
        }

        use super::super::errors::{ErrorBody};

        match request::post(endpoint, Headers::new(),
                            "{\"username\": \"u\",
                              \"email\": \"u@d\"}",
                            &router) {
            Ok(_) => {
                assert!(false);
            },
            Err(error) => {
                let response = error.response;
                assert!(response.status.is_some());
                assert_eq!(response.status.unwrap(), Status::BadRequest);
                let json = extract_body_to::<ErrorBody>(response).unwrap();
                assert_eq!(json.errno, 102);
            }
        };
    }
}

#[cfg(test)]
describe! login_tests {
    before_each {
        use super::super::users_db::{UsersDb, UserBuilder};
        use iron::prelude::Response;
        use iron::Headers;
        #[allow(unused_imports)]
        use iron::headers::{Authorization, Basic};
        use iron::status::Status;
        use iron_test::request;
        use iron_test::response::extract_body_to_string;
        use rustc_serialize::Decodable;
        use rustc_serialize::json::{self, DecodeResult};
        #[allow(unused_imports)]
        use super::super::errors::{ErrorBody};

        #[allow(dead_code)]
        fn extract_body_to<T: Decodable>(response: Response) -> DecodeResult<T> {
            json::decode(&extract_body_to_string(response))
        }

        let router = UsersRouter::init();
        let usersDb = UsersDb::new(Some("./users_db.sqlite".to_owned()));
        usersDb.clear().ok();
        usersDb.create(&UserBuilder::new()
                   .id(1).name(String::from("username"))
                   .password(String::from("password"))
                   .email(String::from("username@example.com"))
                   .secret(String::from("secret"))
                   .finalize().unwrap()).ok();
        let endpoint = "http://localhost:3000/login";
    }

    it "should respond with a generic 400 Bad Request for requests missing username" {
        let invalid_credentials = Authorization(Basic {
            username: "".to_owned(),
            password: Some("password".to_owned())
        });
        let mut headers = Headers::new();
        headers.set(invalid_credentials);

        if let Err(error) = request::post(endpoint, headers, "", &router) {
            let response = error.response;
            assert!(response.status.is_some());
            assert_eq!(response.status.unwrap(), Status::BadRequest);
            let json = extract_body_to::<ErrorBody>(response).unwrap();
            assert_eq!(json.errno, 103);
        } else {
            assert!(false);
        }
    }

    it "should respond with a generic 400 Bad Request for requests missing password" {
        let invalid_credentials = Authorization(Basic {
            username: "username".to_owned(),
            password: Some("".to_owned())
        });
        let mut headers = Headers::new();
        headers.set(invalid_credentials);

        if let Err(error) = request::post(endpoint, headers, "", &router) {
            let response = error.response;
            assert!(response.status.is_some());
            assert_eq!(response.status.unwrap(), Status::BadRequest);
            let json = extract_body_to::<ErrorBody>(response).unwrap();
            assert_eq!(json.errno, 103);
        } else {
            assert!(false);
        }
    }

    it "should respond with a 400 Bad Request for requests missing the authorization password" {
        let headers = Headers::new();

        if let Err(error) = request::post(endpoint, headers, "", &router) {
            let response = error.response;
            assert!(response.status.is_some());
            assert_eq!(response.status.unwrap(), Status::BadRequest);
            let json = extract_body_to::<ErrorBody>(response).unwrap();
            assert_eq!(json.errno, 103);
        } else {
            assert!(false);
        }
    }

    it "should respond with a 401 Unauthorized for invalid credentials" {
        let invalid_credentials = Authorization(Basic {
            username: "johndoe".to_owned(),
            password: Some("password".to_owned())
        });
        let mut headers = Headers::new();
        headers.set(invalid_credentials);

        if let Err(error) = request::post(endpoint, headers, "", &router) {
            let response = error.response;
            assert!(response.status.is_some());
            assert_eq!(response.status.unwrap(), Status::Unauthorized);
        } else {
            assert!(false);
        }
    }

    it "should respond with a 201 Created and a valid JWT token in body for valid credentials" {
        use jwt;
        use super::LoginResponse;
        use super::super::auth_middleware::SessionClaims;

        let valid_credentials = Authorization(Basic {
            username: "username".to_owned(),
            password: Some("password".to_owned())
        });
        let mut headers = Headers::new();
        headers.set(valid_credentials);

        if let Ok(response) = request::post(endpoint, headers, "", &router) {
            assert!(response.status.is_some());
            assert_eq!(response.status.unwrap(), Status::Created);
            let body_obj = extract_body_to::<LoginResponse>(response).unwrap();
            let token = body_obj.session_token;
            let claims = jwt::Token::<jwt::Header, SessionClaims>::parse(&token).ok().unwrap().claims;
            assert_eq!(claims.id, 1);
            assert_eq!(claims.name, "username");
        } else {
            assert!(false);
        }
    }
}
