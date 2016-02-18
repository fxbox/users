/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use iron::status;
use iron::prelude::*;
use rusqlite::Error as rusqlite_error;
use rustc_serialize::json;

use std::error::Error;
use std::fmt::{self, Debug};

#[derive(Debug)]
struct StringError(pub String);

impl fmt::Display for StringError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Debug::fmt(self, f)
    }
}

impl Error for StringError {
    fn description(&self) -> &str {
        &*self.0
    }
}

#[derive(Debug, RustcDecodable, RustcEncodable)]
pub struct ErrorBody {
    pub code: u16,
    pub errno: u16,
    pub error: String
}

pub struct EndpointError;

impl EndpointError {
    pub fn new(status: status::Status, errno: u16) -> IronResult<Response> {
        let error = status.canonical_reason().unwrap().to_string();
        let body = ErrorBody {
            code: status.to_u16(),
            errno: errno,
            error: error.clone()
        };

        Err(
            IronError::new(StringError(error),
            (status, json::encode(&body).unwrap()))
        )
    }
}

pub fn from_decoder_error(error: json::DecoderError) -> IronResult<Response> {
    match error {
        json::DecoderError::MissingFieldError(field) => {
            let errno = match field.as_ref() {
                "username" => 100,
                "email" => 101,
                "password" => 102,
                _ => 400
            };
            EndpointError::new(status::BadRequest, errno)
        },
        _ => EndpointError::new(status::BadRequest, 400)
    }
}

pub fn from_sqlite_error(error: rusqlite_error) -> IronResult<Response> {
    match error {
        rusqlite_error::SqliteFailure(_, error) => {
            match error.unwrap().as_ref() {
                "UNIQUE constraint failed: users.email" |
                "UNIQUE constraint failed: users.username" =>
                    EndpointError::new(status::Conflict, 409),
                _ => EndpointError::new(status::InternalServerError, 501)
            }
        }
        _ => EndpointError::new(status::InternalServerError, 501)
    }
}
