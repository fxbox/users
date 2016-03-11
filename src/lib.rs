/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#![feature(associated_consts, plugin)]

#![cfg_attr(test, feature(const_fn))] // Dependency of stainless
#![cfg_attr(test, plugin(stainless))] // Test runner
#![cfg_attr(test, plugin(clippy))]    // Linter

#[cfg(test)]
extern crate iron_test;

extern crate crypto;
extern crate iron;
extern crate jwt;
extern crate libc;
extern crate rand;
extern crate router;
extern crate rustc_serialize;
extern crate rusqlite;
extern crate unicase;
extern crate urlencoded;

pub mod users_db;
pub mod users_router;
pub mod auth_middleware;
mod errors;
