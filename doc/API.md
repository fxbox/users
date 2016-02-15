# FoxBox User Management API

This document provides protocol-level details of the FoxBox User Management API that allows a client with enough privileges to manage the list of users and permissions registered for a FoxBox.

___

# HTTP API

FoxBox exposes an HTTP API to register, modify and remove users.

## URL Structure

All requests will be to URLs of the form:

    https://<box-url>/v1/<api-endpoint>

Note that:

* All API access must be over a properly-validated HTTPS connection.
* The URL embeds a version identifier "v1"; future revisions of this API may introduce new version numbers.

## Request Format

All POST requests must have a content-type of `application/json` with a utf8-encoded JSON body, and must specify the content-length header.

### Authentication

For the first iteration of this project, requests that require authentication must contain a header including a signed [JWT](https://jwt.io/). We may want to use [HAWK](https://github.com/hueniverse/hawk) in the future. These endpoints are marked with :lock: and a scope in the description below.

Use the JWT with this header:

```js
{
    "Authorization": "Bearer <jwt>"
}
```

## Response Format

All successful requests will produce a response with HTTP status code of "200" and content-type of "application/json".  The structure of the response body will depend on the endpoint in question.

Failures due to invalid behavior from the client will produce a response with HTTP status code in the "4XX" range and content-type of "application/json".  Failures due to an unexpected situation on the box side will produce a response with HTTP status code in the "5XX" range and content-type of "application/json".

To simplify error handling for the client, the type of error is indicated both by a particular HTTP status code, and by an application-specific error code in the JSON response body.  For example:

```js
{
  "code": 400, // matches the HTTP status code
  "errno": 777, // stable application-level error number
  "error": "Bad Request", // string description of the error type
  "message": "the value of salt is not allowed to be undefined",
  "info": "https://docs.endpoint/errors/1234" // link to more info on the error
}
```

Responses for particular types of error may include additional parameters.

The currently-defined error responses are:
* status code 400, errno 400: Bad request.
* status code 400, errno 100: Invalid user name. Missing or malformed user name.
* status code 400, errno 101: Invalid email. Missing or malformed email.
* status code 400, errno 102: Invalid password. The password should have a minimum of 8 chars.
* status code 409, errno 409: Conflict. The user is already registered.
* status code 501, errno 501: Internal server error.
* any status code, errno 999: Unknown error

# API Endpoints

* Setup
    * [POST /setup](#post-setup)

## POST /setup
Allow to initiate the box by registering an admin user. **Once the admin user is created, this route will be removed**.
### Request
___Parameters___
* email - Admin email.
* username - User name. Defaults to "admin".
* password - Admin password.
```ssh
POST /setup/ HTTP/1.1
Content-Type: application/json
{
  "email": "user@domain.org",
  "username": "Pepe",
  "password": "whatever"
}
```
### Response
Successful requests will produce a "204 OK" response with an auth token with `admin` scope in the `Session-Token` header.
```ssh
HTTP/1.1 204 OK
Connection: close
Session-Token: eyJhbGciOiJSUzI1NiJ9...i_dQ
Date: Mon, 5 Feb 2016 16:17:50 GMT
```

Failing requests may be due to the following errors:
* status code 400, errno 100: Invalid user name. Missing or malformed user name.
* status code 400, errno 101: Invalid email. Missing or malformed email.
* status code 400, errno 102: Invalid password. The password should have a minimum of 8 chars.
* status code 400, errno 400: Bad request.
* status code 409, errno 409: Already exists.
