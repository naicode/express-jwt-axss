# express-jwt-axss

[![Build](https://travis-ci.org/naicode/express-jwt-axss.png)](http://travis-ci.org/naicode/express-jwt-axss)

Middleware that validates JsonWebTokens and sets `req.user`.

This module lets you authenticate HTTP requests using JWT tokens in your Node.js
applications.  JWTs are typically used to protect API endpoints, and are
often issued using OpenID Connect.

## It's forked, whats different?

This module if forked form the  [express-jwt](https://github.com/auth0/express-jwt) Module
made by @auth0. Followings points where changed:

  - deprecated `options.skip` was removed
  - if `credentialsRequired` is set to `false` a error is passed if credentials are passed but expired
  - the `options.getAntiXSSToken` Feature was added

The  `getAntiXSSToken` Option can be switched on by setting it to `true` or a `getToken(req)` function.
If it is set to `true` it will look for a second JWT in the `req.cookies.token` Cookie.
This second JWT is required to have a `refJit` Field containing the same unique identifier as
the first JWT in it's `jit` Field. This can be used to help against *simple* XSS Attacks if, and only
if the second JWT is provided in a way JS cannot reach on the Client. Mainly a Cookie with
the *HTTP-Only* and *Secure* Flag set.

Note that the `req.cookies` Field does only exists if a cookie parser is used.
With there for is a requirement if the `getAntiXSSToken` Feature is used.

## Basic Dokumentation

Pleas visit the original project for examples and documentation of the usage.
(TODO add custom doku).

## Related Modules

- [jsonwebtoken](https://github.com/auth0/node-jsonwebtoken) — JSON Web Token sign and verification
- [express-jwt](https://github.com/auth0/express-jwt) - The original express-jwt Module

## Issue Reporting

If you have found a bug or security vulnerability please check if it is  also contained in the
orginal project.  If so please report it there like described in the orginal github repo.
Else you can use the Issue Tracker

## Tests

    $ npm install
    $ npm test


## License

This project is licensed under the MIT license. See the [LICENSE](LICENSE.txt) file for more info.
