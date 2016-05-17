# User Management API

This document provides protocol-level details of the User Management API.

___

# HTTP API

This library exposes an HTTP API to register a single user and obtain session tokens for that user.

In the future, the API will evolve to support multiple users.

## URL Structure

All requests will be to URLs of the form:

    https://<host-url>/v1/<api-endpoint>

Note that:

* All API access must be over a properly-validated HTTPS connection.
* The URL embeds a version identifier "v1"; future revisions of this API may introduce new version numbers.
* The API endpoints may be mounted on a path different than the host root. For instance, for [Project Link](https://github.com/fxbox/foxbox) we are mounting this API at `/users`, so the URLs end up being `https://<host-url>/users/v1/<api-endpoint>`.

## Request Format

All POST requests must have a content-type of `application/json` with a utf8-encoded JSON body.

### Authentication

For the first iteration of this project, requests that require user authentication must contain a header including a signed [JWT](https://jwt.io/). We may want to use [HAWK](https://github.com/hueniverse/hawk) in the future.

Use the JWT with this header:

```js
{
    "Authorization": "Bearer <jwt>"
}
```

For example:

```curl
curl 'http://localhost:3000/api/v1/services' -H 'Accept: application/json' -H 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJraWQiOm51bGwsImFsZyI6IkhTMjU2In0.eyJpZCI6MiwibmFtZSI6ImFkbWluIn0.JNtvokupDl2hdqB+vER15y89qigPc4FviZfJOSR1Vso'
```

## Response Format

All successful requests will produce a response with HTTP status code of "20X" and content-type of "application/json".  The structure of the response body will depend on the endpoint in question.

Failures due to invalid behavior from the client will produce a response with HTTP status code in the "4XX" range and content-type of "application/json".  Failures due to an unexpected situation on the server side will produce a response with HTTP status code in the "5XX" range and content-type of "application/json".

To simplify error handling for the client, the type of error is indicated both by a particular HTTP status code, and by an application-specific error code in the JSON response body.  For example:

```js
{
  "code": 400, // matches the HTTP status code
  "errno": 777, // stable application-level error number
  "error": "Bad Request", // string description of the error type
  "message": "the value of salt is not allowed to be undefined"
}
```

Responses for particular types of error may include additional parameters.

The currently-defined error responses are:
* status code 400, errno 400: Bad request.
* status code 400, errno 100: Invalid name. Missing or malformed name.
* status code 400, errno 101: Invalid email. Missing or malformed email.
* status code 400, errno 102: Invalid password. The password should have a minimum of 8 chars.
* status code 400, errno 103: Missing or malformed authentication header.
* status code 400, errno 104: Invalid user id.
* status code 401, errno 401: Unauthorized. If credentials are not valid.
* status code 409, errno 409: Conflict. The user is already registered.
* status code 410, errno 410: Gone. The resource is no more available. Don't insist.
* status code 423, errno 423: Locked. You are trying to delete the last user with admin privileges. That's forbidden.
* status code 501, errno 501: Internal server error.
* any status code, errno 999: Unknown error

# API Endpoints

* Setup
    * [POST /setup](#post-setup)
* Login
    * [POST /login](#post-login) :lock: (CORS allowed)
* User management
    * [POST /users](#post-users) :lock:
    * [GET /users](#get-users) :lock:
    * [GET /users/:id](#get-usersid) :lock:
    * [PUT /users/:id](#put-usersid) :lock:
    * [PUT /users/:id/activate](#put-usersidactivate)
    * [DELETE /users/:id](#delete-usersid) :lock:

## POST /setup
Allow to initiate the box by registering an admin user.
### Request
___Parameters___
* email - Admin email.
* name - Optional. Display name. Defaults to "admin".
* password - Admin password. It should have a minimum of 8 chars.
```ssh
POST /setup HTTP/1.1
Content-Type: application/json
{
  "email": "user@domain.org",
  "name": "Pepe",
  "password": "whatever"
}
```
### Response
Successful requests will produce a "201 Created" response with a session token in the body.
```ssh
HTTP/1.1 201 Created
Connection: close
{
  "session_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjEiLCJuYW1lIjoidXNlcm5hbWUifQ.IEMuCIdMp53kiUUoBhrxv1GAPQn2L5cqhxNmCc9f_gc"
}
```

**Once the admin user is created, this route will return a 410 error, Gone.**.

Failing requests may be due to the following errors:
* status code 400, errno 100: Invalid name. Missing or malformed name.
* status code 400, errno 101: Invalid email. Missing or malformed email.
* status code 400, errno 102: Invalid password. The password should have a minimum of 8 chars.
* status code 400, errno 400: Bad request.
* status code 409, errno 409: Already exists.
* status code 410, errno 410: Gone. There is already an admin user registered.

## POST /login
Authenticates a user.
### Request
Requests must include a [basic authorization header](https://en.wikipedia.org/wiki/Basic_access_authentication#Client_side) with `email:password` encoded in Base64.
```ssh
POST /setup/ HTTP/1.1
Content-Type: application/json
Authorization: Basic QWxhZGRpbjpPcGVuU2VzYW1l
```
### Response
Successful requests will produce a "201 Created" response with a session token in the form of a [JWT](https://jwt.io/introduction/) with the following data:
```js
{
    "id": 1,
    "email": "user@domain.org"
}
```
The token is provided in the body of the response:
```ssh
HTTP/1.1 201 Created
Connection: close
{
  "session_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjEiLCJuYW1lIjoidXNlcm5hbWUifQ.IEMuCIdMp53kiUUoBhrxv1GAPQn2L5cqhxNmCc9f_gc"
}
```

Failing requests may be due to the following errors:
* status code 400, errno 103: Missing or malformed authentication header.
* status code 400, errno 400: Bad request.
* status code 401, errno 401: Unauthorized. If credentials are not valid.

## POST /users
Create a new inactive user registration and sends an activation email to the user specified email.

Only users with admin privileges are able to access this method.

### Request
Requests must include an authorization header containing a [bearer token](#authentication).

___Parameters___
* email - User email.

```ssh
POST /users HTTP/1.1
Content-Type: application/json
Authorization: Bearer QWxhZGRpbjpPcGVuU2VzYW1l...
{
  "email": "user@domain.org"
}
```
### Response
Successful requests will produce a "201 Created" response with a body containing an activation url:
```ssh
HTTP/1.1 201 Created
Connection: close
{
  "activation_url": "/v1/users/InR5cCI6IkpXVCJ"
}
```

Failing requests may be due to the following errors:
* status code 400, errno 101: Invalid email. Missing or malformed email.
* status code 400, errno 400: Bad request.
* status code 409, errno 409: Already exists.
* status code 401, errno 401: Unauthorized. If credentials are not valid.

## GET /users
Get the list of all registered users.

Only users with admin privileges are able to access this method.

### Request
Requests must include an authorization header containing a [bearer token](#authentication).
```ssh
GET /users HTTP/1.1
Authorization: Bearer QWxhZGRpbjpPcGVuU2VzYW1l...
```

### Response
Successful requests will produce a "200 OK" response with a body containing the list of all registered users:
```ssh
HTTP/1.1 200 OK
Connection: close
[{
  "id": "hfkjsIklksadhs",
  "name": "admin"
  "email": "admin@domain.org",
  "is_admin": true,
  "is_active": true
}, {
  "id": "InR5cCI6IkpXVCJ",
  "name": "pepe"
  "email": "user@domain.org",
  "is_admin": false,
  "is_active": true
}, {
  "id": "kjfIsalj5893213",
  "email": "another_user@domain.org",
  "is_admin": false,
  "is_active": false
}]
```

Failing requests may be due to the following errors:
* status code 400, errno 400: Bad request.
* status code 401, errno 401: Unauthorized. If credentials are not valid.

## GET /users/:id
Get the information of the user matching the given id.

Only the owner or users with admin privileges are able to access this method.

### Request
```ssh
GET /users/InR5cCI6IkpXVCJ HTTP/1.1
```

### Response
Successful requests will produce a "200 Ok" response.
```ssh
HTTP/1.1 200 Ok
Connection: close
{
  "id": "InR5cCI6IkpXVCJ",
  "name": "pepe"
  "email": "user@domain.org",
  "is_admin": false,
  "is_active": true
}
```

Failing requests may be due to the following errors:
* status code 400, errno 400: Bad request.
* status code 401, errno 401: Unauthorized. If credentials are not valid.
* status code 404, errno 404: Not Found. The user does not exist.

## PUT /users/:id
Edit the information of the user matching the given id.

Users with non admin privileges are only able to edit their own information.

### Request
Requests must include an authorization header containing a [bearer token](#authentication).

___Parameters___
* id - User id.
* name - Display name.
* password - User password.
* is_admin - Flag to give or remove admin permissions.

```ssh
PUT /users/:id HTTP/1.1
Content-Type: application/json
Authorization: Bearer QWxhZGRpbjpPcGVuU2VzYW1l...
{
  "name": "pepe",
  "password": "whatever",
  "is_admin": false
}
```

### Response
Successful requests will produce a "204 No Content" response.
```ssh
HTTP/1.1 204 No Content
Connection: close
```

Failing requests may be due to the following errors:
* status code 400, errno 100: Invalid user name. Malformed user name.
* status code 400, errno 102: Invalid password. The password should have a minimum of 8 chars.
* status code 400, errno 104: Invalid user id.
* status code 400, errno 400: Bad request.
* status code 401, errno 401: Unauthorized. If credentials are not valid.

## PUT /users/:id/activate
Activate a user by providing a name and a password.

### Request
___Parameters___
* name - Optional. Display name.
* password - User password.

```ssh
PUT /users/:id HTTP/1.1
Content-Type: application/json
{
  "name": "pepe",
  "password": "whatever"
}
```

### Response
Successful requests will produce a "200 Ok" response with a session token in the form of a [JWT](https://jwt.io/introduction/) with the following data:
```js
{
    "id": 1,
    "email": "user@domain.org"
}
```
The token is provided in the body of the response:

```ssh
HTTP/1.1 200 OK
Connection: close
{
  "session_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjEiLCJuYW1lIjoidXNlcm5hbWUifQ.IEMuCIdMp53kiUUoBhrxv1GAPQn2L5cqhxNmCc9f_gc"
}
```

Failing requests may be due to the following errors:
* status code 400, errno 100: Invalid name. Missing or malformed name.
* status code 400, errno 102: Invalid password. The password should have a minimum of 8 chars.
* status code 400, errno 400: Bad request.
* status code 409, errno 409: Gone. The user was already activated.

## DELETE /users/:id
Delete the user matching the given id.

Only users with admin privileges are able to access this method.

### Request
Requests must include an authorization header containing a [bearer token](#authentication).
```ssh
DELETE /users/:id HTTP/1.1
Authorization: Bearer QWxhZGRpbjpPcGVuU2VzYW1l...
```

### Response
Successful requests will produce a "204 No Content":
```ssh
HTTP/1.1 204 No Content
Connection: close
```

Failing requests may be due to the following errors:
* status code 401, errno 401: Unauthorized. If credentials are not valid.
* status code 404, errno 404: Not Found. The user does not exist.
* status code 423, errno 423: Locked. You are trying to delete the last user with admin privileges. That's forbidden.
