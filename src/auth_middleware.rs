/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use super::errors::*;

use iron::{AroundMiddleware, Handler, headers, status};
use iron::method::Method;
use iron::prelude::*;

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
                // XXX validate token once /login flow and JWT module are done.
                println!("{}", token);
            },
            _ => {
                return EndpointError::new(status::Unauthorized, 401)
            }
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
