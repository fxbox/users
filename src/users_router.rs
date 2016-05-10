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

use super::auth_middleware::{ AuthEndpoint, AuthMiddleware, SessionToken };
use super::users_db::{ User, UserBuilder, UsersDb, ReadFilter };
use super::errors::*;

use iron::status;
use iron::headers::{ Authorization, Basic };
use iron::method::Method;
use iron::prelude::*;
use iron_cors::CORS;
use router::Router;
use rustc_serialize::json;

use std::io::Read;

type Credentials = (String, String);

pub static API_VERSION: &'static str = "v1";

#[derive(Debug, RustcDecodable, RustcEncodable)]
struct SessionTokenResponse {
    session_token: String
}

impl SessionTokenResponse {
    fn with_user(user: &User) -> IronResult<Response> {
        let session_token = match SessionToken::from_user(&user) {
            Ok(token) => token,
            Err(_) => return EndpointError::with(
                status::InternalServerError, 501, None
            )
        };
        let body_obj = SessionTokenResponse{
           session_token: session_token
        };
        let body = match json::encode(&body_obj) {
            Ok(body) => body,
            Err(_) => return EndpointError::with(
                status::InternalServerError, 501, None
            )
        };
        Ok(Response::with((status::Created, body)))
    }
}

#[derive(Debug, RustcDecodable, RustcEncodable)]
struct CreateUserResponse {
    activation_url: String
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
///     use foxbox_users::UsersManager;
///     use iron::prelude::{Chain, Iron};
///
///     let manager = UsersManager::new("UsersRouter_0.sqlite");
///     let router = manager.get_router_chain();
///     let mut chain = Chain::new(router);
/// # if false {
///     Iron::new(chain).http("localhost:3000").unwrap();
/// # }
/// }
/// ```
pub struct UsersRouter;

impl UsersRouter {
    fn setup(req: &mut Request, db_path: &str) -> IronResult<Response> {
        #[derive(RustcDecodable, Debug)]
        struct SetupBody {
            username: String,
            email: String,
            password: String
        }

        // This endpoint should be disabled and return error 410 (Gone)
        // if there is any admin user already configured.
        let db = UsersDb::new(db_path);
        let admins = db.read(ReadFilter::IsAdmin(true)).unwrap();
        if !admins.is_empty() {
            return EndpointError::with(status::Gone, 410,
                Some("There is already an admin account".to_owned()));
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
            .admin(true)
            .active(true)
            .finalize() {
                Ok(user) => user,
                Err(user_with_error) => {
                    println!("{:?}", user_with_error);
                    return from_user_builder_error(user_with_error.error);
                }
            };

        match db.create(&admin) {
            Ok(admin) => {
                SessionTokenResponse::with_user(&admin)
            },
            Err(error) => {
                println!("{:?}", error);
                from_sqlite_error(error)
            }
        }
    }

    fn login(req: &mut Request, db_path: &str) -> IronResult<Response> {
        // Return Some pair of valid credentials if both email and password
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

        let error103 = EndpointError::with(status::BadRequest, 103,
            Some("Missing or malformed authentication header".to_owned()));
        let header: Option<&Authorization<Basic>> = req.headers.get();
        if let Some(auth) = header {
            if let Some((email, password)) = credentials_from_header(auth) {
                let users_db = UsersDb::new(db_path);
                let users = match users_db.read(
                    ReadFilter::Credentials(email, password)) {
                    Ok(users) => users,
                    Err(_) => return EndpointError::with(
                        status::InternalServerError, 501, None
                    )
                };
                if users.len() != 1 || !users[0].is_active {
                    return EndpointError::with(status::Unauthorized, 401, None);
                }
                SessionTokenResponse::with_user(&users[0])
            } else {
                error103
            }
        } else {
            error103
        }
    }

    /// Create a new user registration. By default the user is added to the DB
    /// but it remains inactive until the owner sets a user name and a password.
    ///
    /// XXX Once we have a permissions system, this functionality will require
    /// admin permissions.
    pub fn create_user(req: &mut Request, db_path: &str)
        -> IronResult<Response> {
        #[derive(RustcDecodable, Debug)]
        struct CreateUserBody {
            email: String
        }

        let mut payload = String::new();
        req.body.read_to_string(&mut payload).unwrap();
        let body: CreateUserBody = match json::decode(&payload) {
            Ok(body) => body,
            Err(error) => {
                println!("{:?}", error);
                return from_decoder_error(error);
            }
        };

        let user = match UserBuilder::new()
            .email(body.email)
            .finalize() {
                Ok(user) => user,
                Err(user_with_error) => {
                    println!("{:?}", user_with_error);
                    return from_user_builder_error(user_with_error.error);
                }
            };

        let db = UsersDb::new(db_path);
        match db.create(&user) {
            Ok(user) => {
                let activation_url = format!("/{}/users/{}", API_VERSION,
                                             user.id.unwrap());

                let body = match json::encode(&CreateUserResponse{
                    activation_url: activation_url
                }) {
                    Ok(body) => body,
                    Err(_) => return EndpointError::with(
                        status::InternalServerError, 501,
                        Some("CreateUserBody encoding error".to_owned())
                    )
                };
                Ok(Response::with((status::Created, body)))
            },
            Err(error) => {
                println!("{:?}", error);
                from_sqlite_error(error)
            }
        }
    }

    /// Provide the necessary information and a temporary session token to
    /// complete a user registration.
    pub fn get_user_activation_info(req: &mut Request, db_path: &str)
        -> IronResult<Response> {
        let user_id = req.extensions.get::<Router>().unwrap()
            .find("id").unwrap_or("").to_owned();

        if user_id.is_empty() {
            return EndpointError::with(status::InternalServerError, 501,
                                       Some("Missing user id".to_owned()));
        }

        // XXX Move from i32 to string ids
        let user_id: i32 = match user_id.parse() {
            Ok(user_id) => user_id,
            Err(_) => return EndpointError::with(
                status::BadRequest, 400, Some("Invalid user id".to_owned())
            )
        };

        let user: User;

        let db = UsersDb::new(db_path);
        if let Ok(users) = db.read(ReadFilter::All) {
            println!("{:?} {}", users, user_id)
        };


        match db.read(ReadFilter::Id(user_id)) {
            Ok(users) => {
                if users.is_empty() {
                    return EndpointError::with(status::NotFound, 404, None);
                }

                if users.len() > 1 {
                    return EndpointError::with(status::InternalServerError, 501,
                        Some("Duplicated user".to_owned()));
                }

                user = users[0].clone();
                println!("{:?}", user);
                if user.is_active {
                    return EndpointError::with(status::Gone, 410,
                        Some("User already activated".to_owned()));
                }
            },
            Err(_) => {
                return EndpointError::with(status::NotFound, 404, None);
            }
        }

        // XXX Add short ttl to session token.
        // XXX Once we have a permissions system we'll need to add a user
        //     edition scope to the session token.
        let session_token = match SessionToken::from_user(&user) {
            Ok(token) => token,
            Err(_) => return EndpointError::with(
                status::InternalServerError, 501, None
            )
        };

        let body = match json::encode(&SessionTokenResponse {
            session_token: session_token,
        }) {
            Ok(body) => body,
            Err(_) => return EndpointError::with(
                status::InternalServerError, 501, None
            )
        };

        Ok(Response::with((status::Ok, body)))
    }

    pub fn get_all_users(req: &mut Request, db_path: &str)
        -> IronResult<Response> {
        EndpointError::with(status::NotFound, 404, None)
    }

    pub fn edit_user(req: &mut Request, db_path: &str)
        -> IronResult<Response> {
        EndpointError::with(status::NotFound, 404, None)
    }

    pub fn delete_user(req: &mut Request, db_path: &str)
        -> IronResult<Response> {
        EndpointError::with(status::NotFound, 404, None)
    }

    /// Creates the Iron user router middleware.
    pub fn init(db_path: &str) -> super::iron::middleware::Chain {
        let mut router = Router::new();

        // Setup.
        let data = String::from(db_path);
        router.post(format!("/{}/setup", API_VERSION),
                    move |req: &mut Request| -> IronResult<Response> {
            UsersRouter::setup(req, &data)
        });

        // Login.
        let data = String::from(db_path);
        router.post(format!("/{}/login", API_VERSION),
                    move |req: &mut Request| -> IronResult<Response> {
            UsersRouter::login(req, &data)
        });

        // User management.
        let data = String::from(db_path);
        router.post(format!("/{}/users", API_VERSION),
                    move |req: &mut Request| -> IronResult<Response> {
            UsersRouter::create_user(req, &data)
        });

        let data = String::from(db_path);
        router.get(format!("/{}/users/:id", API_VERSION),
                   move |req: &mut Request| -> IronResult<Response> {
            UsersRouter::get_user_activation_info(req, &data)
        });

        let data = String::from(db_path);
        router.get(format!("/{}/users", API_VERSION),
                   move |req: &mut Request| -> IronResult<Response> {
            UsersRouter::get_all_users(req, &data)
        });

        let data = String::from(db_path);
        router.put(format!("/{}/users/:id", API_VERSION),
                   move |req: &mut Request| -> IronResult<Response> {
            UsersRouter::edit_user(req, &data)
        });

        let data = String::from(db_path);
        router.delete(format!("/{}/users/:id", API_VERSION),
                      move |req: &mut Request| -> IronResult<Response> {
            UsersRouter::delete_user(req, &data)
        });

        let cors = CORS::new(vec![
            (vec![Method::Post],
             format!("/{}/login", API_VERSION)),
            (vec![Method::Post, Method::Get],
             format!("/{}/users", API_VERSION)),
            (vec![Method::Get, Method::Put, Method::Delete],
             format!("/{}/users/:id", API_VERSION))
        ]);

        let data = String::from(db_path);
        let auth_middleware = AuthMiddleware::new(vec![
            AuthEndpoint(vec![Method::Post, Method::Get],
                         format!("/{}/users", API_VERSION)),
            AuthEndpoint(vec![Method::Put, Method::Delete],
                         format!("/{}/users/:id", API_VERSION))
        ], data);

        let mut chain = Chain::new(router);
        chain.link_after(cors);
        chain.link_around(auth_middleware);

        chain
    }
}

#[cfg(test)]
describe! users_router_tests {
    before_each {
        use super::API_VERSION;
        #[allow(unused_imports)]
        use super::super::{ CreateUserResponse, SessionTokenResponse };

        #[allow(unused_imports)]
        use auth_middleware::SessionClaims;
        #[allow(unused_imports)]
        use crypto::sha2::Sha256;
        #[allow(unused_imports)]
        use errors::ErrorBody;
        #[allow(unused_imports)]
        use iron::{ headers, Headers };
        #[allow(unused_imports)]
        use iron::headers::{ Authorization, Basic, Bearer };
        #[allow(unused_imports)]
        use iron::prelude::Response;
        #[allow(unused_imports)]
        use iron::status::Status;
        use iron_test::request;
        use iron_test::response::extract_body_to_string;
        #[allow(unused_imports)]
        use jwt;
        use rustc_serialize::Decodable;
        use rustc_serialize::json::{ self, DecodeResult };
        #[allow(unused_imports)]
        use users_db::{ UserBuilder, remove_test_db, get_db_environment,
                        ReadFilter };
        use UsersManager;

        #[allow(dead_code)]
        fn extract_body_to<T: Decodable>(response: Response)
            -> DecodeResult<T> {
            json::decode(&extract_body_to_string(response))
        }

        let manager = UsersManager::new(&get_db_environment());
        let router = manager.get_router_chain();
    }

    describe! cors_tests {
        it "should get the appropriate CORS headers" {
            use iron::method::Method;

            let endpoints = vec![
                (vec![Method::Post], format!("{}/login", API_VERSION))
            ];
            for endpoint in endpoints {
                let (_, path) = endpoint;
                let path = format!("http://localhost:3000/{}",
                                   &(path.replace(":", "foo")));
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

        it "should get the appropriate CORS headers even in case of error" {
            match request::post(&format!("http://localhost:3000/{}/login",
                                         API_VERSION),
                                Headers::new(),
                                "{}",
                                &router) {
                Ok(_) => {
                    assert!(false)
                },
                Err(err) => {
                    let headers = &err.response.headers;
                    assert!(headers.has::<headers::AccessControlAllowOrigin>());
                    assert!(headers.has::<headers::AccessControlAllowHeaders>());
                    assert!(headers.has::<headers::AccessControlAllowMethods>());
                }

            }
        }

        it "should not get CORS headers" {
            match request::options(&format!("http://localhost:3000/{}/setup",
                                            API_VERSION),
                                   Headers::new(),
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
    } // cors_tests

    describe! setup_tests {
        before_each {
            let usersDb = manager.get_db();
            usersDb.clear().ok();

            let endpoint = &format!("http://localhost:3000/{}/setup",
                                    API_VERSION);
        }

        it "should respond 201 Created for a proper POST /setup" {
            match request::post(endpoint, Headers::new(),
                                "{\"username\": \"username\",
                                  \"email\": \"username@domain.com\",
                                  \"password\": \"password\"}",
                                &router) {
                Ok(res) => {
                    assert_eq!(res.status.unwrap(), Status::Created);
                    let body_obj = extract_body_to::<SessionTokenResponse>(res).unwrap();
                    let token = body_obj.session_token;
                    let claims = jwt::Token::<jwt::Header, SessionClaims>::parse(&token)
                        .ok().unwrap().claims;
                    assert_eq!(claims.email, "username@domain.com");
                },
                Err(err) => {
                    println!("{:?}", err);
                    assert!(false);
                }
            };
        }

        it "should create one admin user" {
            let body = "{\"username\": \"username\",\
                        \"email\": \"username@domain.com\",\
                        \"password\": \"password\"}";

            if let Ok(res) = request::post(endpoint, Headers::new(), body,
                                           &router) {
                assert_eq!(res.status.unwrap(), Status::Created);
                let admins = usersDb.read(ReadFilter::IsAdmin(true)).unwrap();
                assert_eq!(admins.len(), 1);
                assert_eq!(admins[0].email, "username@domain.com");
            } else {
                assert!(false);
            };
        }

        it "should respond 410 Gone if an admin account exists" {
            // Be sure we have an admin
            usersDb.create(&UserBuilder::new()
                       .id(1).name(String::from("admin"))
                       .password(String::from("password!!"))
                       .email(String::from("admin@example.com"))
                       .admin(true)
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
                    assert_eq!(json.message,
                               Some("There is already an admin account".to_owned()));
                }
            };
        }

        it "should respond 400 BadRequest, errno 100 if username is missing" {
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
                    assert_eq!(json.message, Some("Invalid user name".to_owned()));
                }
            };
        }

        it "should respond 400 BadRequest, errno 101 if email is missing" {
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
                    assert_eq!(json.message, Some("Invalid email".to_owned()));
                }
            };
        }

        it "should respond 400 BadRequest, errno 102 if password is missing" {
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
                    assert_eq!(json.message,
                        Some("Invalid password. Passwords must have a minimum of 8 chars"
                             .to_owned()));
                }
            };
        }

        after_each {
            remove_test_db();
        }
    } // setup_tests

    describe! login_tests {
        before_each {
            let usersDb = manager.get_db();
            usersDb.clear().ok();
            // Create active user.
            usersDb.create(&UserBuilder::new()
                       .id(1).name(String::from("username"))
                       .password(String::from("password"))
                       .email(String::from("username@example.com"))
                       .secret(String::from("secret"))
                       .active(true)
                       .finalize().unwrap()).ok();
            // Create inactive user.
            usersDb.create(&UserBuilder::new()
                       .id(2).name(String::from("inactive_user"))
                       .password(String::from("password"))
                       .email(String::from("inactive_user@example.com"))
                       .secret(String::from("secret"))
                       .active(false)
                       .finalize().unwrap()).ok();
            let endpoint = &format!("http://localhost:3000/{}/login",
                                    API_VERSION);
        }

        it "should respond with a generic 400 Bad Request for requests missing
            username" {
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
            };
        }

        it "should respond with a generic 400 Bad Request for requests missing
            password" {
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
            };
        }

        it "should respond with a 400 Bad Request for requests missing the
            authorization password" {
            let headers = Headers::new();

            if let Err(error) = request::post(endpoint, headers, "", &router) {
                let response = error.response;
                assert!(response.status.is_some());
                assert_eq!(response.status.unwrap(), Status::BadRequest);
                let json = extract_body_to::<ErrorBody>(response).unwrap();
                assert_eq!(json.errno, 103);
            } else {
                assert!(false);
            };
        }

        it "should respond with a 401 Unauthorized for invalid credentials" {
            let invalid_credentials = Authorization(Basic {
                username: "johndoe@example.com".to_owned(),
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
            };
        }

        it "should respond with a 401 Unauthorized for inactive user" {
            let invalid_credentials = Authorization(Basic {
                username: "inactive_user@example.com".to_owned(),
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
            };
        }

        it "should respond with a 201 Created and a valid JWT token in body for
            valid credentials" {
            let valid_credentials = Authorization(Basic {
                username: "username@example.com".to_owned(),
                password: Some("password".to_owned())
            });
            let mut headers = Headers::new();
            headers.set(valid_credentials);
            match request::post(endpoint, headers, "", &router) {
                Ok(response) => {
                    assert!(response.status.is_some());
                    assert_eq!(response.status.unwrap(), Status::Created);
                    let body_obj = extract_body_to::<SessionTokenResponse>(response).unwrap();
                    let token = body_obj.session_token;
                    let claims = jwt::Token::<jwt::Header, SessionClaims>::parse(&token)
                                .ok().unwrap().claims;
                    assert_eq!(claims.id, 1);
                    assert_eq!(claims.email, "username@example.com");
                },
                Err(_) => assert!(false)
            };
        }

        after_each {
            remove_test_db();
        }
    } // login_tests

    describe! create_user_tests {
        before_each {
            let usersDb = manager.get_db();
            usersDb.clear().ok();
            let user = UserBuilder::new()
                       .id(1).name(String::from("username"))
                       .password(String::from("password"))
                       .email(String::from("username@example.com"))
                       .admin(true)
                       .active(true)
                       .finalize().unwrap();
            usersDb.create(&user).ok();

            let create_user_endpoint = &format!("http://localhost:3000/{}/users",
                                                API_VERSION);

            let jwt_header: jwt::Header = Default::default();
            let claims = SessionClaims {
                id: user.id.unwrap(),
                email: user.email.to_owned()
            };
            let token = jwt::Token::new(jwt_header, claims);
            let signed = token.signed(
                user.secret.to_owned().as_bytes(),
                Sha256::new()
            ).ok().unwrap();

            // With Authorization header.
            let mut headers = Headers::new();
            headers.set(Authorization(Bearer { token: signed.to_owned() }));
        }

        it "should not allow the creation of a new user to non authenticated
            requests" {
            match request::post(create_user_endpoint, Headers::new(), "",
                                &router) {
                Ok(_) => assert!(false),
                Err(error) => {
                    let response = error.response;
                    assert!(response.status.is_some());
                    assert_eq!(response.status.unwrap(), Status::Unauthorized);
                }
            };
        }

        it "should not allow the creation of a new user without email" {
            match request::post(create_user_endpoint, headers, "{}",
                                &router) {
                Ok(_) => assert!(false),
                Err(error) => {
                    let response = error.response;
                    assert!(response.status.is_some());
                    assert_eq!(response.status.unwrap(), Status::BadRequest);
                    let json = extract_body_to::<ErrorBody>(response).unwrap();
                    assert_eq!(json.errno, 101);
                }
            }
        }

        it "should allow the creation of a new user" {
            match request::post(create_user_endpoint, headers,
                                "{\"email\": \"user@domain.org\"}",
                                &router) {
                Ok(response) => {
                    assert!(response.status.is_some());
                    assert_eq!(response.status.unwrap(), Status::Created);
                    let body_obj =
                        extract_body_to::<CreateUserResponse>(response).unwrap();
                    assert!(!body_obj.activation_url.is_empty());
                    match usersDb.read(
                        ReadFilter::Email("user@domain.org".to_owned())
                    ) {
                        Ok(users) => {
                            assert_eq!(users.len(), 1);
                            assert_eq!(users[0].is_active, false);
                        },
                        Err(_) => assert!(false)
                    };
                },
                Err(error) => {
                    println!("{:?}", error);
                    assert!(false);
                }
              }
        }

        after {
            remove_test_db();
        }
    } // create_user_tests

    describe! get_user_activation_info_tests {
        before_each {
            let usersDb = manager.get_db();
            usersDb.clear().ok();
       }

        it "should return 404 NotFound for unknown user id" {
            let unknown_id = 111;
            let endpoint = &format!("http://localhost:3000/{}/users/{}",
                                    API_VERSION, unknown_id);
            match request::get(endpoint, Headers::new(), &router) {
                Ok(_) => assert!(false),
                Err(error) => {
                    let response = error.response;
                    assert_eq!(response.status.unwrap(), Status::NotFound);
                }
            };
        }

        it "should return 410 Gone for already active user id" {
            let active_user = UserBuilder::new()
                .name(String::from("username"))
                .password(String::from("password"))
                .email(String::from("active_user@example.com"))
                .active(true)
                .finalize().unwrap();
            let user = usersDb.create(&active_user).unwrap();
            let endpoint = &format!("http://localhost:3000/{}/users/{}",
                                    API_VERSION, user.id.unwrap());
            match request::get(endpoint, Headers::new(), &router) {
                Ok(_) => assert!(false),
                Err(error) => {
                    let response = error.response;
                    assert_eq!(response.status.unwrap(), Status::Gone);
                }
            };
        }

        it "should return 200 OK with a session token inactive user id" {
            let inactive_user = UserBuilder::new()
                .name(String::from("username"))
                .password(String::from("password"))
                .email(String::from("inactive_user@example.com"))
                .finalize().unwrap();
            let user = usersDb.create(&inactive_user).unwrap();
            let endpoint = &format!("http://localhost:3000/{}/users/{}",
                                    API_VERSION, user.id.unwrap());
            match request::get(endpoint, Headers::new(), &router) {
                Ok(response) => {
                    assert!(response.status.is_some());
                    assert_eq!(response.status.unwrap(), Status::Ok);
                    let body_obj = extract_body_to::<SessionTokenResponse>
                                   (response).unwrap();
                    let token = body_obj.session_token;
                    let claims = jwt::Token::<jwt::Header, SessionClaims>
                                    ::parse(&token).ok().unwrap().claims;
                    assert_eq!(claims.id, user.id.unwrap());
                    assert_eq!(claims.email, user.email);
                },
                Err(error) => {
                    println!("{:?}", error);
                    assert!(false)
                }
            };
        }

        after {
            remove_test_db();
        }
    } // get_user_activation_info_tests
} // users_router_tests
