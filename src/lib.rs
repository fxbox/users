/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#![feature(associated_consts, plugin)]

#![feature(const_fn)] // Dependency of stainless
#![plugin(stainless)] // Test runner

extern crate crypto;
extern crate iron;
extern crate libc;
extern crate router;
extern crate rustc_serialize;
extern crate rusqlite;
extern crate unicase;
extern crate rand;

pub mod users_db;
pub mod users_router;

mod errors;

#[cfg(test)]
extern crate iron_test;
