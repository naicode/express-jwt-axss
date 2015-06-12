var jwt = require('jsonwebtoken');
var UnauthorizedError = require('./errors/UnauthorizedError');
var unless = require('express-unless');
var async = require('async');

var DEFAULT_REVOKED_FUNCTION = function(_, __, cb) { return cb(null, false); }

var DEFAULT_GET_ANTI_XSS_TOKEN_FUNCTION = function(req) {
  return req.cookie.token;
};

var getClass = {}.toString;
function isFunction(object) {
  return object && getClass.call(object) == '[object Function]';
}

function wrapStaticSecretInCallback(secret){
  return function(_, __, cb){
    return cb(null, secret);
  };
}

module.exports = function(options) {
  if (!options || !options.secret) throw new Error('secret should be set');

  var secretCallback = options.secret;

  if (!isFunction(secretCallback)){
    secretCallback = wrapStaticSecretInCallback(secretCallback);
  }

  var isRevokedCallback = options.isRevoked || DEFAULT_REVOKED_FUNCTION;

  var _requestProperty = options.userProperty || options.requestProperty || 'user';
  var credentialsRequired = typeof options.credentialsRequired === 'undefined' ? true : options.credentialsRequired;

  var getAntiXSSToken;
  if (options.getAntiXSSToken) {
    console.log("use anti xss token");
    if (typeof options.getAntiXSSToken === 'function') {
      getAntiXSSToken = options.getAntiXSSToken;
    } else {
      getAntiXSSToken = DEFAULT_GET_ANTI_XSS_TOKEN_FUNCTION;
    }
  }

  var middleware = function(req, res, next) {
    var token, antiXSSToken;

    if (req.method === 'OPTIONS' && req.headers.hasOwnProperty('access-control-request-headers')) {
      var hasAuthInAccessControl = !!~req.headers['access-control-request-headers']
                                    .split(',').map(function (header) {
                                      return header.trim();
                                    }).indexOf('authorization');

      if (hasAuthInAccessControl) {
        return next();
      }
    }

    if (typeof options.skip !== 'undefined') {
      console.warn('WARN: express-jwt: options.skip is deprecated');
      console.warn('WARN: use app.use(jwt(options).unless({path: \'/x\'}))');
      if (options.skip.indexOf(req.url) > -1) {
        return next();
      }
    }

    if (options.getToken && typeof options.getToken === 'function') {
      try {
        token = options.getToken(req);
      } catch (e) {
        return next(e);
      }
    } else if (req.headers && req.headers.authorization) {
      var parts = req.headers.authorization.split(' ');
      if (parts.length == 2) {
        var scheme = parts[0];
        var credentials = parts[1];

        if (/^Bearer$/i.test(scheme)) {
          token = credentials;
        } else {
          return next(new UnauthorizedError('credentials_bad_scheme', { message: 'Format is Authorization: Bearer [token]' }));
        }
      } else {
        return next(new UnauthorizedError('credentials_bad_format', { message: 'Format is Authorization: Bearer [token]' }));
      }
    }

    if (!token) {
      if (credentialsRequired) {
        return next(new UnauthorizedError('credentials_required', { message: 'No authorization token was found' }));
      } else {
        return next();
      }
    }

    var expectedJti;
    if (getAntiXSSToken) {
      antiXSSToken = getAntiXSSToken(req);
    }
    var dtoken = jwt.decode(token, { complete: true }) || {};

    async.parallel([
      function(callback){
        var arity = secretCallback.length;
        if (arity == 4) {
          secretCallback(req, dtoken.header, dtoken.payload, callback);
        } else { // arity == 3
          secretCallback(req, dtoken.payload, callback);
        }
      },
      function(callback){
        isRevokedCallback(req, dtoken.payload, callback);
      }
    ], function(err, results){
      if (err) { return next(err); }
      var revoked = results[1];
      if (revoked){
        return next(new UnauthorizedError('revoked_token', { message: 'The token has been revoked.'}));
      }

      var secret = results[0];

      if (!getAntiXSSToken) {
        jwt.verify(token, secret, options, function(err, decoded) {
          if (err) return next(new UnauthorizedError('invalid_token', err));
          req[_requestProperty] = decoded;
          next();
        });
      } else {
        //check both tokens and link between them
        async.parallel([
          function (callback) {
            jwt.verify(token, secret, options, callback);
          },
          function (callback) {
            jwt.verify(antiXSSToken, secret, options, callback);
          }
        ], function(err, results) {
          if (err) return next(new UnauthorizedError('invalid_token', err));
          var decoded = results[0];
          var antiXSSDecoded = results[1];
          if (decoded.jti !== antiXSSToken.refJti) {
            return next(new UnauthorizedError('invalid_anti_xss_token', err));
          } else {
            req[_requestProperty] = decoded;
          }
          next();
        });
      }
    });
  };

  middleware.unless = unless;

  return middleware;
};
