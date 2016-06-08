/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use super::users_router::CreateUserResponse;

use iron::AfterMiddleware;
use iron::method::Method;
use iron::prelude::*;
use iron::response::ResponseBody;
use rustc_serialize::json::{ self, DecodeResult };
use std::sync::{ Arc, RwLock };

/// Pointer to a function responsible for sending a invitation email.
/// The function will be given the user's email address and a string
/// containing the endpoint path required to activate a new user
/// (i.e.: "/v1/users/12312313/activate?auth=avalidauthtoken")
pub type InvitationDispatcher =
    fn(user_email: String, user_activation_endpoint: String) -> ();

#[derive(Clone)]
pub struct InvitationMiddleware {
    invitation_dispatcher: Arc<RwLock<Option<InvitationDispatcher>>>,
    version: String
}

impl InvitationMiddleware {
    pub fn new(version: String) -> Self {
        InvitationMiddleware {
            invitation_dispatcher: Arc::new(RwLock::new(None)),
            version: version
        }
    }

    pub fn set_invitation_dispatcher(&mut self,
                                     dispatcher: InvitationDispatcher) {
        let mut guard = self.invitation_dispatcher.write().unwrap();
        *guard = Some(dispatcher);
    }
}

impl AfterMiddleware for InvitationMiddleware {
    fn after(&self, req: &mut Request, mut res: Response)
        -> IronResult<Response> {
        if req.method != Method::Post ||
           req.url.path != vec![self.version.clone(), "users".to_owned()] {
            return Ok(res);
        }

        let mut payload = Vec::new();
        {
            let mut response_body = ResponseBody::new(&mut payload);
            match res.body {
                Some(ref mut body) => body.write_body(&mut response_body).ok(),
                None => None,
            };
        }
        let payload = String::from_utf8(payload).unwrap();
        let payload: DecodeResult<CreateUserResponse> = json::decode(&payload);
        match payload {
            Ok(payload) => {
                let guard = self.invitation_dispatcher.read().unwrap();
                if let Some(dispatcher) = *guard {
                    dispatcher(payload.email, payload.activation_url);
                };
                Ok(res)
            },
            Err(_) => Ok(res)
        }
    }
}
