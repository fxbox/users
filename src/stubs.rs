/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

extern crate iron;

use std::net::ToSocketAddrs;
use self::iron::{headers, TypeMap, Url};
use self::iron::method::Method;
use self::iron::prelude::*;

// Stub request
pub fn request<'a, 'b>(method: &Method, path: &str) -> Request<'a, 'b> {
    let path = "http://localhost:3000/".to_string() + path;
    Request {
        url: Url::parse(&path).unwrap(),
        remote_addr:
            "localhost:3000".to_socket_addrs().unwrap().next().unwrap(),
        local_addr:
            "localhost:3000".to_socket_addrs().unwrap().next().unwrap(),
        headers: headers::Headers::new(),
        body: unsafe { ::std::mem::uninitialized() },
        method: method.clone(),
        extensions: TypeMap::new()
    }
}
