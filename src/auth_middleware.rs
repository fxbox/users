/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use super::users_db::{ReadFilter, UsersDb};
use super::errors::*;

use crypto::sha2::Sha256;
use iron::{AroundMiddleware, Handler, headers, status};
use iron::method::Method;
use iron::prelude::*;
use jwt::{Header, Token};

#[derive(Default, RustcDecodable, RustcEncodable)]
pub struct SessionClaims{
    pub id: i32,
    pub name: String
}

#[derive(Debug)]
pub struct AuthEndpoint(pub Method, pub Vec<String>);

impl PartialEq for AuthEndpoint {
    fn eq(&self, other: &AuthEndpoint) -> bool {
        let AuthEndpoint(ref self_method, ref self_path) = *self;
        let AuthEndpoint(ref other_method, ref other_path) = *other;

        if self_method != other_method {
            return false;
        }

        for (i, path) in self_path.iter().enumerate() {
            if other_path[i] != path.to_string() &&
               "*".to_string() != path.to_string() {
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
            let endpoint = AuthEndpoint(req.method.clone(), req.url.path.clone());
            // If this is not an authenticated endpoint, just proceed with the
            // original request.
            if !self.auth_endpoints.contains(&endpoint) {
                return self.handler.handle(req);
            }
        }
        // Otherwise, we need to verify the authorization header.
        match req.headers.get::<headers::Authorization<headers::Bearer>>() {
            Some(&headers::Authorization(headers::Bearer { ref token })) => {
                let token = match Token::<Header, SessionClaims>::parse(token) {
                    Ok(token) => token,
                    Err(_) => return EndpointError::new(status::Unauthorized, 401)
                };

                // To verify the token we need to get the secret associated to
                // user id contained in the token claim.
                let db = UsersDb::new();
                match db.read(ReadFilter::Id(token.claims.id)) {
                    Ok(users) => {
                        if users.len() != 1 {
                            return EndpointError::new(status::Unauthorized, 401)
                        }
                        if !token.verify(users[0].secret.to_owned().as_bytes(),
                                         Sha256::new()) {
                            return EndpointError::new(status::Unauthorized, 401)
                        }
                    },
                    Err(_) => return EndpointError::new(status::Unauthorized, 401)
                }
            },
            _ => return EndpointError::new(status::Unauthorized, 401)
        };

        self.handler.handle(req)
    }
}

pub struct AuthMiddleware {
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
