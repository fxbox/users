/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use super::errors::*;

use iron::{BeforeMiddleware, headers, status};
use iron::prelude::*;

pub struct AuthMiddleware;

impl BeforeMiddleware for AuthMiddleware {
    fn before(&self, req: &mut Request) -> IronResult<()> {
        match req.headers.get::<headers::Authorization<headers::Bearer>>() {
            Some(&headers::Authorization(headers::Bearer { ref token })) => {
                // XXX validate token once /login flow and JWT module are done.
                println!("{}", token);
                Ok(())
            },
            _ => {
                EndpointError::new(status::Unauthorized, 401)
            }
        }
    }
}
