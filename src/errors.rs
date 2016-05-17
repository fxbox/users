/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use super::users_db::UserBuilderError;

use iron::status;
use iron::prelude::*;
use rusqlite::Error as rusqlite_error;
use rustc_serialize::json;

use std::error::Error;
use std::fmt::{ self, Debug };

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
    pub error: String,
    pub message: Option<String>
}

pub struct EndpointError;

impl EndpointError {
    pub fn with(status: status::Status, errno: u16, message: Option<String>)
        -> IronResult<Response> {
        let error = status.canonical_reason().unwrap().to_owned();
        let body = ErrorBody {
            code: status.to_u16(),
            errno: errno,
            error: error.clone(),
            message: message
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
            match field.as_ref() {
                "name" => from_user_builder_error(UserBuilderError::Name),
                "email" => from_user_builder_error(UserBuilderError::Email),
                "password" => from_user_builder_error(UserBuilderError::Password),
                _ => EndpointError::with(status::BadRequest, 400,
                                         Some("Missing field".to_owned()))

            }
        },
        _ => EndpointError::with(status::BadRequest, 400,
                                 Some("Body parser error".to_owned()))
    }
}

pub fn from_sqlite_error(error: rusqlite_error) -> IronResult<Response> {
    match error {
        rusqlite_error::SqliteFailure(_, error) => {
            match error.unwrap().as_ref() {
                "UNIQUE constraint failed: users.email" |
                "UNIQUE constraint failed: users.username" =>
                    EndpointError::with(status::Conflict, 409,
                                        Some("User already exists".to_owned())),
                _ => EndpointError::with(
                    status::InternalServerError, 501,
                    Some("Database error".to_owned())
                )
            }
        }
        _ => EndpointError::with(status::InternalServerError, 501,
                                 Some("Database error".to_owned()))
    }
}

pub fn from_user_builder_error(error: UserBuilderError)
    -> IronResult<Response> {
    let (errno, message) = match error {
        UserBuilderError::Name => {
            (100, Some("Invalid user name".to_owned()))
        },
        UserBuilderError::Email => {
            (101, Some("Invalid email".to_owned()))
        },
        UserBuilderError::Password => {
            (102, Some("Invalid password. Passwords must have a minimum of 8 chars".to_owned()))
        },
        UserBuilderError::Secret => {
            // HTTP API consumers are not supposed to set the secret, so a
            // invalid one means that there's something wrong with the server.
            return EndpointError::with(status::InternalServerError, 501,
                                       Some("Invalid secret".to_owned()));
        }
    };
    EndpointError::with(status::BadRequest, errno, message)
}
