/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use super::users_router::CreateUserResponse;

use hyper::Client;
use hyper::header::{ Connection, ContentType, Headers };
use hyper::mime::{ Attr, Mime, TopLevel, SubLevel, Value };
use iron::AfterMiddleware;
use iron::method::Method;
use iron::prelude::*;
use iron::response::ResponseBody;
use rustc_serialize::json::{ self, DecodeResult };

#[derive(Debug, RustcEncodable)]
struct InvitationRequest {
    email: String,
    url: String
}

#[derive(Clone, Debug)]
pub struct InvitationMiddleware{
    email_server: Option<String>,
    invitation_url_prepath: Option<String>,
    version: String
}

impl InvitationMiddleware {
    pub fn new(version: String) -> Self {
        InvitationMiddleware {
            email_server: None,
            invitation_url_prepath: None,
            version: version
        }
    }

    pub fn setup(&mut self, email_server: String,
                 invitation_url_prepath: String) {
        self.email_server = Some(email_server);
        self.invitation_url_prepath = Some(invitation_url_prepath);
    }

    pub fn send(&self, user_email: String, activation_url: String) {
        let invitation_url_prepath = match self.invitation_url_prepath {
            Some(ref prepath) => prepath,
            None => {
                println!("Invitation middleware needs setup");
                return;
            }
        };

        let email_server = match self.email_server {
            Some(ref url) => url,
            None => {
                println!("Invitation middleware needs setup");
                return;
            }
        };

        let body = match json::encode(&InvitationRequest {
            email: user_email.clone(),
            url: format!("{}{}", invitation_url_prepath, activation_url)
        }) {
            Ok(body) => body,
            Err(_) => {
                println!("Could not send invitation email.");
                return;
            }
        };

        let client = Client::new();
        let endpoint = format!("{}/v1/invitation", email_server);
        let mut headers = Headers::new();
        headers.set(
            ContentType(Mime(TopLevel::Application, SubLevel::Json,
                             vec![(Attr::Charset, Value::Utf8)]))
        );
        headers.set(Connection::close());
        let res = client.post(&endpoint)
              .headers(headers)
              .body(&body)
              .send();

        if let Err(_) = res {
            println!("Unable to send invitation to {}", user_email);
        }
    }
}

impl AfterMiddleware for InvitationMiddleware {
    fn after(&self, req: &mut Request, mut res: Response)
        -> IronResult<Response> {
        if req.method != Method::Post ||
           req.url.path != vec![self.version.clone(), "users".to_owned()] {
            return Ok(res);
        }

        if self.email_server == None || self.invitation_url_prepath == None {
            println!("Invitation middleware requires previous setup");
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
                self.send(payload.email, payload.activation_url);
                Ok(res)
            },
            Err(_) => Ok(res)
        }
    }
}
