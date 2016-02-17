/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use super::errors::*;

use iron::{AroundMiddleware, Handler, headers, status};
use iron::prelude::*;

struct AuthHandler<H: Handler> { handler: H }

impl<H: Handler> Handler for AuthHandler<H> {
    fn handle(&self, req: &mut Request) -> IronResult<Response> {
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

pub struct AuthMiddleware;

impl AroundMiddleware for AuthMiddleware {
    fn around(self, handler: Box<Handler>) -> Box<Handler> {
        Box::new(AuthHandler {
            handler: handler
        }) as Box<Handler>
    }
}
