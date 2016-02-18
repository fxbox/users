/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

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
            if req.method != *method &&
               req.method != Method::Options {
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

type Credentials = (String, String);

#[derive(Default, RustcDecodable, RustcEncodable)]
pub struct SessionClaims{
    id: i32,
    name: String
}

#[derive(Debug, RustcDecodable, RustcEncodable)]
struct LoginResponse {
    session_token: String
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
            Ok(_) => {
                Ok(Response::with(status::Ok))
            },
            Err(error) => {
                println!("{:?}", error);
                from_sqlite_error(error)
            }
        }
    }

    /// Returns Some pair of valid credentials if both username and password are provided or None elsewhere.
    fn credentials_from_header(auth: &Authorization<Basic>) -> Option<Credentials> {
        let &Authorization(Basic { ref username, password: ref maybe_password }) = auth;
        let something_is_missed = username.is_empty() || match *maybe_password {
            None => true,
            Some(ref psw) => psw.is_empty()
        };
        if something_is_missed {
            None
        } else {
            Some((username.to_owned(), maybe_password.as_ref().unwrap().to_owned()))
        }
    }

    fn login(req: &mut Request) -> IronResult<Response> {
        use std::default::Default;
        use crypto::sha2::Sha256;
        use jwt;

        let error103 = EndpointError::new(status::BadRequest, 103);
        let header: Option<&Authorization<Basic>> = req.headers.get();
        if let Some(authorization) = header {
            if let Some((username, password)) = UsersRouter::credentials_from_header(authorization) {
                let users_db = UsersDb::new();
                let users = users_db.read(ReadFilter::Credentials(username, password)).unwrap();
                if users.len() != 1 {
                    return EndpointError::new(status::Unauthorized, 401);
                }

                let User{ id, ref name, ref secret, .. } = users[0];
                let jwt_header: jwt::Header = Default::default();
                let claims = SessionClaims {
                    id: id.unwrap(),
                    name: name.to_owned(),
                    ..Default::default()
                };
                let token = jwt::Token::new(jwt_header, claims);
                let signed = token.signed(secret.to_owned().as_bytes(), Sha256::new()).ok().unwrap();
                let body_obj = LoginResponse{
                   session_token: signed
                };
                Ok(Response::with((status::Created, json::encode(&body_obj).unwrap())))
            } else {
                error103
            }
        } else {
            error103
        }
    }

    pub fn new() -> super::iron::middleware::Chain {
        let mut router = Router::new();

        router.post("/setup", UsersRouter::setup);
        router.post("/login", UsersRouter::login);

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

describe! cors_tests {
    before_each {
        use iron::{headers, Headers};
        use iron_test::request;

        let router = UsersRouter::new();
    }

    it "should get the appropriate CORS headers" {
        use super::CORS;

        for endpoint in CORS::ENDPOINTS {
            let (_, path) = *endpoint;
            let path = "http://localhost:3000/".to_string() +
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

describe! routes_tests {
    before_each {
        use iron::Headers;
        use iron::method::Method;
        use iron::status::Status;
        use iron_test::request;

        use super::Endpoint;

        let router = UsersRouter::new();

    }

    it "should respond with 501 not implemented" {
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
            let path = "http://localhost:3000/".to_string() +
                       &(path.join("/").replace("*", "foo"));

            let res = match *method {
                Method::Get => {
                    request::get(&path, Headers::new(), &router)
                },
                Method::Post => {
                    request::post(&path, Headers::new(), "", &router)
                },
                Method::Delete => {
                    request::delete(&path, Headers::new(), &router)
                },
                Method::Put => {
                    request::put(&path, Headers::new(), "", &router)
                },
                _ => {
                    assert!(false);
                    request::get(&path, Headers::new(), &router)
                }
            };
            assert_eq!(res.unwrap().status.unwrap(), Status::NotImplemented);
        }
    }
}

describe! setup_tests {
    before_each {
        use iron::Headers;
        use iron::status::Status;
        use iron_test::request;

        let router = UsersRouter::new();
    }

    it "should respond 200 OK for a proper POST /setup" {
        match request::post("http://localhost:3000/setup", Headers::new(),
                            "{\"username\": \"u\",
                              \"email\": \"u@d\",
                              \"password\": \"12345678\"}",
                            &router) {
            Ok(res) => {
                assert_eq!(res.status.unwrap(), Status::Ok);
            },
            Err(err) => {
                println!("{:?}", err);
                assert!(false);
            }
        };
    }

    it "should respond 400 BadRequest if username is missing" {
        match request::post("http://localhost:3000/setup", Headers::new(),
                            "{\"email\": \"u@d\",
                              \"password\": \"12345678\"}",
                            &router) {
            Ok(_) => {
                assert!(false);
            },
            Err(err) => {
                assert_eq!(err.response.status.unwrap(), Status::BadRequest);
            }
        };
    }

    it "should respond 400 BadRequest if email is missing" {
        match request::post("http://localhost:3000/setup", Headers::new(),
                            "{\"username\": \"u\",
                              \"password\": \"12345678\"}",
                            &router) {
            Ok(_) => {
                assert!(false);
            },
            Err(err) => {
                assert_eq!(err.response.status.unwrap(), Status::BadRequest);
            }
        };
    }

    it "should respond 400 BadRequest if password is missing" {
        match request::post("http://localhost:3000/setup", Headers::new(),
                            "{\"username\": \"u\",
                              \"email\": \"u@d\"}",
                            &router) {
            Ok(_) => {
                assert!(false);
            },
            Err(err) => {
                assert_eq!(err.response.status.unwrap(), Status::BadRequest);
            }
        };
    }
}


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

        let router = UsersRouter::new();
        let usersDb = UsersDb::new();
        usersDb.clear().ok();
        usersDb.create(&UserBuilder::new()
                   .id(1).name("username")
                   .password("password")
                   .email("username@example.com")
                   .secret("secret")
                   .finalize().unwrap()
        ).ok();
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
        use super::{LoginResponse, SessionClaims};

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
