/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//! A middleware for authenticating requests based on
//! [JWT](https://jwt.io/introduction/).
//!
//! # The Auth Middleware
//!
//! Here _auth_ stands for _authentication_. A
//! [POST `/login`](https://github.com/fxbox/users/blob/master/doc/API.md#post-login)
//! request will authenticate a user. If so, a session JWT is returned
//! in the body of the response. This token must be sent with any further request to
//! keep track of the session.

use super::users_db::{ReadFilter, User, UsersDb};
use super::errors::*;

use crypto::sha2::Sha256;
use iron::{AroundMiddleware, Handler, headers, status};
use iron::method::Method;
use iron::prelude::*;
use jwt::{self, Error, Header, Token};
use urlencoded::UrlEncodedQuery;

/// Structure representing [JWT claims section](https://jwt.io/introduction/).
///
/// Claims made by the authentication protocol includes `id` and `name` with
/// database unique id and username respectively.
#[derive(Default, RustcDecodable, RustcEncodable)]
pub struct SessionClaims{
    pub id: i32,
    pub name: String
}

/// Factory to create a session token `String` for a user in the database.
pub struct SessionToken;

impl SessionToken {
    pub fn for_user(user: &User) -> Result<String, Error> {
        let jwt_header: jwt::Header = Default::default();
        let claims = SessionClaims {
            id: user.id.unwrap(),
            name: user.name.to_owned()
        };
        let token = jwt::Token::new(jwt_header, claims);
        token.signed(
            user.secret.to_owned().as_bytes(),
            Sha256::new()
        )
    }
}

/// Represents an authorized endpoint.
///
/// When initializing [AuthMiddleware](./struct.AuthMiddleware.html) you need to
/// pass some routes to be authenticated, these are instances of `AuthEndpoint`.
///
/// `AuthEndpoints` take a vector of methods and a string representing the path
/// of the endpoint to be authenticated. This path can contain wildcard
/// parts. For example:
///
/// AuthEndpoint(vec![Method::Get, Method::Post], "/a/path/:foo/bar/:baz")
///
/// would match with a GET or POST request to /a/path/whatever/bar/whatever
#[derive(Debug)]
pub struct AuthEndpoint(pub Vec<Method>, pub String);

impl PartialEq for AuthEndpoint {
    fn eq(&self, other: &AuthEndpoint) -> bool {
        let AuthEndpoint(ref self_method, ref self_path) = *self;
        let AuthEndpoint(ref other_method, ref other_path) = *other;

        let self_path: Vec<&str> = if self_path.starts_with('/') {
            self_path[1..].split('/').collect()
        } else {
            self_path[0..].split('/').collect()
        };
        let other_path: Vec<&str> = if other_path.starts_with('/') {
            other_path[1..].split('/').collect()
        } else {
            other_path[0..].split('/').collect()
        };

        if self_path.len() != other_path.len() {
            return false;
        }

        let mut contains_method = false;
        for (_, method) in self_method.iter().enumerate() {
            if other_method.contains(method) {
                contains_method = true;
            }
        }

        if !contains_method {
            return false;
        }

        for (i, path) in self_path.iter().enumerate() {
            if &other_path[i] != path && !other_path[i].starts_with(':') {
                return false;
            }
        }
        true
    }
}

struct AuthHandler<H: Handler> {
    handler: H,
    auth_endpoints: Vec<AuthEndpoint>
}

impl<H: Handler> Handler for AuthHandler<H> {
    fn handle(&self, req: &mut Request) -> IronResult<Response> {
        {
            let endpoint = AuthEndpoint(vec![req.method.clone()],
                                        req.url.path.join("/"));
            // If this is not an authenticated endpoint, just proceed with the
            // original request.
            if !self.auth_endpoints.contains(&endpoint) {
                return self.handler.handle(req);
            }
        }

        // Otherwise, we need to verify the authorization token that can
        // come within the Authorization header or as a query parameter.
        match req.headers.clone().get::<headers::Authorization<headers::Bearer>>() {
            Some(&headers::Authorization(headers::Bearer { ref token })) => {
                if let Err(_) = AuthMiddleware::verify(token) {
                    return EndpointError::with(status::Unauthorized, 401)
                }
            },
            _ => {
                match req.get_ref::<UrlEncodedQuery>() {
                    Ok(ref params) => {
                        match params.get("auth") {
                            Some(token) => {
                                if let Err(_) = AuthMiddleware::verify(&token[0]) {
                                    return EndpointError::with(status::Unauthorized, 401)
                                }
                            },
                            _ => {
                                return EndpointError::with(status::Unauthorized, 401)
                            }
                        }
                    },
                    _ => return EndpointError::with(status::Unauthorized, 401)
                }
            }
        };

        self.handler.handle(req)
    }
}

/// Handle JWT authentication on specified endpoints.
///
/// # Examples
///
/// Before passing it as middleware, you should specify the authenticated
/// endpoints:
///
/// ```
/// extern crate iron;
/// extern crate foxbox_users;
///
/// fn main() {
///     use foxbox_users::users_router::UsersRouter;
///     use foxbox_users::auth_middleware::AuthMiddleware;
///     use iron::prelude::{Chain, Iron};
///
///     let router = UsersRouter::init();
///     let mut chain = Chain::new(router);
///     chain.around(AuthMiddleware{
///         auth_endpoints: vec![]
///     });
/// # if false {
///     Iron::new(chain).http("localhost:3000").unwrap();
/// # }
/// }
/// ```
pub struct AuthMiddleware {
    /// `Vec<AuthEndpoint>` containing the set of endpoints to be authenticated.
    pub auth_endpoints: Vec<AuthEndpoint>
}

impl AroundMiddleware for AuthMiddleware {
    fn around(self, handler: Box<Handler>) -> Box<Handler> {
        Box::new(AuthHandler {
            handler: handler,
            auth_endpoints: self.auth_endpoints
        }) as Box<Handler>
    }
}

impl AuthMiddleware {
    pub fn verify(token: &str) -> Result<(), ()> {
        if token.is_empty() {
            return Err(());
        }

        let token = match Token::<Header, SessionClaims>::parse(token) {
            Ok(token) => token,
            Err(_) => return Err(())
        };

        // To verify the token we need to get the secret associated to
        // user id contained in the token claim.
        let db = UsersDb::new();
        match db.read(ReadFilter::Id(token.claims.id)) {
            Ok(users) => {
                if users.len() != 1 {
                    return Err(());
                }
                if !token.verify(users[0].secret.to_owned().as_bytes(),
                                 Sha256::new()) {
                    return Err(());
                }
            },
            Err(_) => {
                return Err(());
            }
        };

        Ok(())
    }
}

#[cfg(test)]
describe! auth_middleware_tests {
    before_each {
        use iron::headers::Headers;
        use iron::prelude::*;
        use iron::method::Method;
        use iron::status::Status;
        use iron_test::request;
        use router::Router;

        fn not_implemented(_: &mut Request) -> IronResult<Response> {
            Ok(Response::with(Status::NotImplemented))
        }

        let mut router = Router::new();
        router.get("/authenticated", not_implemented);
        router.get("/authenticated/:foo/bar/:baz", not_implemented);
        router.delete("/authenticated", not_implemented);
        router.get("/not_authenticated", not_implemented);

        let mut chain = Chain::new(router);
        chain.around(AuthMiddleware {
            auth_endpoints: vec![
                AuthEndpoint(vec![Method::Get, Method::Delete],
                             "/authenticated".to_owned()),
                AuthEndpoint(vec![Method::Get],
                             "/authenticated/:foo/bar/:baz".to_owned())
            ]
        });
    }

    it "should allow request to not authenticated endpoint" {
        match request::get("http://localhost:3000/not_authenticated",
                           Headers::new(), &chain) {
            Ok(res) => {
                assert_eq!(res.status.unwrap(), Status::NotImplemented)
            },
            Err(_) => assert!(false)
        }
    }

    it "should reject request to authenticated endpoint" {
        match request::get("http://localhost:3000/authenticated",
                           Headers::new(), &chain) {
            Ok(_) => assert!(false),
            Err(err) => {
                assert_eq!(err.response.status.unwrap(), Status::Unauthorized)
            }
        };
        match request::get("http://localhost:3000/authenticated/afoo/bar/abaz",
                           Headers::new(), &chain) {
            Ok(_) => assert!(false),
            Err(err) => {
                assert_eq!(err.response.status.unwrap(), Status::Unauthorized)
            }
        };
        match request::delete("http://localhost:3000/authenticated",
                              Headers::new(), &chain) {
            Ok(_) => assert!(false),
            Err(err) => {
                assert_eq!(err.response.status.unwrap(), Status::Unauthorized)
            }
        }
    }

    it "should allow request to authenticated endpoint" {
        use super::super::users_db::{UserBuilder, UsersDb, remove_test_db};

        use iron::headers::{Authorization, Bearer};
        use crypto::sha2::Sha256;
        use jwt;

        let db = UsersDb::new();
        db.clear().ok();
        let user = UserBuilder::new()
            .id(1).name(String::from("username"))
            .password(String::from("password"))
            .email(String::from("username@example.com"))
            .secret(String::from("secret"))
            .finalize().unwrap();
        db.create(&user).ok();
        let jwt_header: jwt::Header = Default::default();
        let claims = SessionClaims {
            id: user.id.unwrap(),
            name: user.name.to_owned()
        };
        let token = jwt::Token::new(jwt_header, claims);
        let signed = token.signed(
            user.secret.to_owned().as_bytes(),
            Sha256::new()
        ).ok().unwrap();

        // With Authorization header.
        let mut headers = Headers::new();
        headers.set(Authorization(Bearer { token: signed.to_owned() }));
        match request::get("http://localhost:3000/authenticated",
                           headers.clone(), &chain) {
            Ok(res) => {
                assert_eq!(res.status.unwrap(), Status::NotImplemented)
            },
            Err(_) => assert!(false)
        };
        match request::get("http://localhost:3000/authenticated/afoo/bar/abaz",
                           headers.clone(), &chain) {
            Ok(res) => {
                assert_eq!(res.status.unwrap(), Status::NotImplemented)
            },
            Err(_) => assert!(false)
        };
        match request::delete("http://localhost:3000/authenticated",
                              headers, &chain) {
            Ok(res) => {
                assert_eq!(res.status.unwrap(), Status::NotImplemented)
            },
            Err(_) => assert!(false)
        }

        // With ?auth=<token>
        match request::get(
            &format!("http://localhost:3000/authenticated?auth={}", signed),
            Headers::new(), &chain
        ) {
            Ok(res) => {
                assert_eq!(res.status.unwrap(), Status::NotImplemented)
            },
            Err(_) => assert!(false)
        };

        match request::get(
            &format!("http://localhost:3000/authenticated/afoo/bar/abaz?auth={}", signed),
            Headers::new(), &chain
        ) {
            Ok(res) => {
                assert_eq!(res.status.unwrap(), Status::NotImplemented)
            },
            Err(_) => assert!(false)
        };

        match request::delete(
            &format!("http://localhost:3000/authenticated?auth={}", signed),
            Headers::new(), &chain
        ) {
            Ok(res) => {
                assert_eq!(res.status.unwrap(), Status::NotImplemented)
            },
            Err(_) => assert!(false)
        }

        remove_test_db();
    }
}
