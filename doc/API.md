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
* status code 400, errno 100: Invalid user name.
* status code 400, errno 101: Invalid email. You forgot to give an email or its format is invalid.
* status code 400, errno 102: Invalid permissions. The list of given permissions is not well formed or it contains an unknown or invalid permission.
* status code 401, errno 201:  Unauthorized. The credentials you passed are not valid.
* status code 409, errno 301:  Already registered.
* status code 498, errno 401:  Token expired/invalid.
* status code 501, errno 501:  Database error
* any status code, errno 999:  Unknown error

# API Endpoints

* Setup
    * [POST /setup/](#post-setup)
* Invitations
    * [POST /invitations/](#post-invitations) :lock: (scope: admin)
    * [GET /invitations/](#get-invitations) :lock: (scope: admin)
    * [DELETE /invitations/:id/](#delete-invitations) :lock: (scope: admin)
* Users
    * [POST /users/](#post-users) :lock: (scope: admin)
    * [GET /users/](#get-users) :lock: (scope: admin)
    * [PUT /users/:id/](#put-users) :lock: (scope: owner)
    * [DELETE /users/:id/](#delete-usersid) :lock: (scope: admin, owner)
* Access recovery
    * [POST /recoveries/:user/](#post-recoveriesuser)
    * [GET /recoveries/:user/:id/](#get-recoveriesuserid) :lock: (scope: recovery)
* Permissions
    * [GET /permissions/](#get-permissions) :lock: (scope: admin)
    * [GET /permissions/:user/](#get-permissionsuser) :lock: (scope: admin, owner)
    * [GET /permissions/:user/:taxon/](#get-permissionsusertaxon) :lock: (scope: admin, owner)
    * [GET /permissions/_/:taxon/](#get-permissions_taxon) :lock: (scope: admin)
    * [PUT /permissions/:user/:taxon/](#put-permissionsusertaxon) :lock: (scope: admin)

## POST /setup/
Allow to initiate the box by registering an admin user. **Once the admin user is created, this route will be removed**.
### Request
___Parameters___
* email (optional) - Admin email.
* username (optional) - User name. Defaults to "admin".
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
* status code 400, errno 100: Invalid user name.
* status code 400, errno 101: Invalid email. The email that you gave has the wrong format.

## POST /invitations/
Send an invitation for a user to register with the box.
### Request
___Parameters___
* email - User's email.
* permissions (optional) - List of permissions the user will be given after creating the account.

```ssh
POST /invitations/ HTTP/1.1
Content-Type: application/json
Authorization:"Bearer eyJhbGciOiJSUzI1NiJ9...i_dQ"

{
  "email": "user@domain.org",
  "permissions": {
    "lights": {},
    "climate": { "access": "readonly" },
  }
}
```
### Response
Successful requests will produce a "200 OK" response with the identifier of the invitation.

```ssh
HTTP/1.1 200 OK
Connection: close
Content-Type: application/json; charset=utf-8
Content-Length: 54
Date: Mon, 5 Feb 2016 16:17:50 GMT

{
  "id": "ZmVyam1vcmVub0BnbWFpbC5jb20saG9tZQ0K"
}
```

Failing requests may be due to the following errors:
* status code 400, errno 101: Invalid email. You forgot to give an email or its format is invalid.
* status code 400, errno 102: Invalid permissions list. The list of given permissions is not well formed or it contains an unknown or invalid permission.
* status code 409, errno 301: Already registered. The user you are trying to invite is already registered in the box.
* status code 498, errno 401:  Token expired/invalid.

## GET /invitations/
Give the current list of active invitations.
### Request
```ssh
GET /invitations/ HTTP/1.1
Authorization:"Bearer eyJhbGciOiJSUzI1NiJ9...i_dQ"
```
### Response
Successful requests will produce a "200 OK" response with a JSON containing the list of active invitations.
```ssh
HTTP/1.1 200 OK
Connection: close
Content-Type: application/json; charset=utf-8
Content-Length: 54
Date: Mon, 5 Feb 2016 16:17:50 GMT
{
  "invitations": [{
    "id": "ZmVyam1vcmVub0BnbWFpbC5jb20saG9tZQ0K",
    "email": "user@domain.org",
    "expire": 1454679242488
  }]
}
```
Failing requests may be due to the following errors:
* status code 401, errno 201:  Unauthorized. The credentials you passed are not valid. You need a token with 'admin' scope to access this endpoint.

## DELETE /invitations/:id/
Revoke a invitation.
### Request
___Parameters___
* id - Invitation identifier.
```ssh
DELETE /invitations/ZmVyam1vcmVub0BnbWFpbC5jb20saG9tZQ0K/ HTTP/1.1
Authorization:"Bearer eyJhbGciOiJSUzI1NiJ9...i_dQ"
```
### Response
Successful requests will produce a "204 OK".
```ssh
HTTP/1.1 204 OK
Connection: close
Content-Type: application/json; charset=utf-8
Date: Mon, 5 Feb 2016 16:17:50 GMT
```
Failing requests may be due to the following errors:
* status code 401, errno 201:  Unauthorized. The credentials you passed are not valid. You need a token with 'admin' scope to access this endpoint.

## POST /users/
Register a new FoxBox user.
### Request
The request must be authenticated with a bearer token with scope "user-creation"
___Parameters___
* email - User's email.
* username - User display name.
* password - User password.
```ssh
POST /boxes/ HTTP/1.1
Content-Type: application/json
Authorization:"Bearer eyJhbGciOiJSUzI1NiJ9...i_dQ"
{
  "email": "user@domain.org",
  "username": "someone",
  "password": "whatever"
}
```
### Response
Successful requests will produce a "204 OK" response with an auth token with `user` scope in the `Session-Token` header.
```ssh
HTTP/1.1 204 OK
Connection: close
Session-Token: eyJhbGciOiJSUzI1NiJ9...i_dQ
Date: Mon, 5 Feb 2016 16:17:50 GMT
```
Failing requests may be due to the following errors:
* status code 400, errno 101: Invalid email. You forgot to give an email or its format is invalid.
* status code 401, errno 201:  Unauthorized. The credentials you passed are not valid.
* status code 409, errno 301:  Already registered. The user name or email are already registered with the box.

## GET /users/
Give the list of registered users
### Request
```ssh
GET /users/ HTTP/1.1
Authorization:"Bearer eyJhbGciOiJSUzI1NiJ9...i_dQ"
```
### Response
Successful requests will produce a "200 OK" response with a JSON containing the list of registered users.
```ssh
HTTP/1.1 200 OK
Connection: close
Content-Type: application/json; charset=utf-8
Content-Length: 54
Date: Mon, 5 Feb 2016 16:17:50 GMT
{
  "users": [{
    "id": "ZmVyam1vcmVub0BnbWFpbC5jb20saG9tZQ0K",
    "username": "Pepe",
    "email": "user@domain.org"
  }]
}
```
## PUT /users/:id/
Modifies a registered user.
### Request
___Parameters___
* id - User unique identifier.
* email - User email.
* username - User name.
```ssh
PUT /users/ZmVyam1vcmVub0BnbWFpbC5jb20saG9tZQ0K/ HTTP/1.1
Authorization:"Bearer eyJhbGciOiJSUzI1NiJ9...i_dQ"
Content-Type: application/json; charset=utf-8
Content-Length: 54
Date: Mon, 5 Feb 2016 16:17:50 GMT
{
  "email": "anotheremail@domain.org",
  "username": "anothername"
}
```
### Response
Successful requests will produce a "204 OK" response.
```ssh
HTTP/1.1 204 OK
Connection: close
Date: Mon, 5 Feb 2016 16:17:50 GMT
```
Failing requests may be due to the following errors:
* status code 400, errno 100: Invalid user name
* status code 401, errno 201:  Unauthorized. The credentials you passed are not valid.
* status code 409, errno 301:  Already registered. The user name or email are already registered with the box.

## DELETE /users/:id/
Unregister a box user.
### Request
___Parameters___
* id - User unique identifier.
```ssh
DELETE /users/ZmVyam1vcmVub0BnbWFpbC5jb20saG9tZQ0K/ HTTP/1.1
Authorization:"Bearer eyJhbGciOiJSUzI1NiJ9...i_dQ"
```
### Response
Successful requests will produce a "204 OK".
```ssh
HTTP/1.1 204 OK
Connection: close
Content-Type: application/json; charset=utf-8
Date: Mon, 5 Feb 2016 16:17:50 GMT
```
Failing requests may be due to the following errors:
* status code 401, errno 201:  Unauthorized. The credentials you passed are not valid. You need a token with 'admin' scope to access this endpoint.

## POST /recoveries/:user/
Start the password reset process for a user that lost access to the box.
### Request
___Parameters___
* email - User email.

```ssh
POST /recoveries/ HTTP/1.1
Authorization:"Bearer eyJhbGciOiJSUzI1NiJ9...i_dQ"
{
  "email": "user@domain.org"
}
```
### Response
Successful requests will produce a "204 OK".
```ssh
HTTP/1.1 204 OK
Connection: close
Date: Mon, 5 Feb 2016 16:17:50 GMT
```
Failing requests may be due to the following errors:
* status code 404, errno 404: Resource not found. The user identifier is not valid.

## PUT /recoveries/:id/
Allow an user to change her account password.
### Request
___Parameters___
* password - user account password.
```ssh
POST /recoveries/ HTTP/1.1
Authorization:"Bearer eyJhbGciOiJSUzI1NiJ9...i_dQ"
{
  "password": "whatever"
}
```
### Response
Successful requests will produce a "204 OK".
```ssh
HTTP/1.1 204 OK
Connection: close
Date: Mon, 5 Feb 2016 16:17:50 GMT
```
Failing requests may be due to the following errors:
* status code 404, errno 404: Resource not found. The access recovery identifier is not valid.

## GET /permissions/
### Request
### Response

## GET /permissions/:user/
### Request
### Response

## GET /permissions/:user/:taxon/
### Request
### Response

## GET /permissions/_/:taxon/
### Request
### Response

## PUT /permissions/:user/:taxon/
### Request
### Response

