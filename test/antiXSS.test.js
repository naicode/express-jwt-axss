var jwt = require('jsonwebtoken');
var assert = require('assert');

/*author: Philipp Korber*/

var expressjwt = require('../lib');
var UnauthorizedError = require('../lib/errors/UnauthorizedError');

describe('antiXSS', function () {
  var req, res;

  beforeEach( function() {
    req = {};
    res = {};
  });

  it('should err if no token is present', function() {
    var secret = 'shhhhhh';
    var token = jwt.sign({foo: 'bar'}, secret);

    req.headers = {};
    req.headers.authorization = 'Bearer ' + token;
    req.cookies = {};
    expressjwt({secret: secret, getAntiXSSToken: true})(req, res, function(err) {
      assert(typeof err !== undefined);
      assert.equal(err.code, 'xss_token_missing');
    });
  });

  it('should err if antiXSS token is invalide', function() {
    var secret = 'shhhhhh';
    var token = jwt.sign({foo: 'bar'}, secret);
    var token2 = jwt.sign({dum:'dam', exp: 12345}, secret);

    req.headers = {};
    req.headers.authorization = 'Bearer ' + token;
    req.cookies = {token: token2};
    expressjwt({secret: secret, getAntiXSSToken: true})(req, res, function(err) {
      assert(typeof err !== 'undefined');
      assert.equal(err.code, 'invalid_token');
    });
  });

  it('should err if antiXSS token does not match token', function() {
    var secret = 'shhhhhh';
    var token = jwt.sign({foo: 'bar', jti: 123}, secret);
    var token2 = jwt.sign({refJti: 124}, secret);

    req.headers = {};
    req.headers.authorization = 'Bearer ' + token;
    req.cookies = {token: token2};
    expressjwt({secret: secret, getAntiXSSToken: true})(req, res, function(err) {
      assert(typeof err !== undefined);
      assert.equal(err.code, 'invalid_anti_xss_token_ref');
    });
  });

  it('should work if antiXSS token is valide', function() {
    var secret = 'shhhhhh';
    var token = jwt.sign({foo: 'bar', jti: 123}, secret);
    var token2 = jwt.sign({refJti: 123}, secret);

    req.headers = {};
    req.headers.authorization = 'Bearer ' + token;
    req.cookies = {token: token2};
    expressjwt({secret: secret, getAntiXSSToken: true})(req, res, function(err) {
      assert.equal(err, undefined);
      assert.equal('bar', req.user.foo);
    });
  });

  it('should work with custom get token function', function() {
    var secret = 'shhhhhh';
    var token = jwt.sign({foo: 'bar', jti: 123}, secret);
    var token2 = jwt.sign({refJti: 123}, secret);

    function getToken(req) { return token2; };

    req.headers = {};
    req.headers.authorization = 'Bearer ' + token;
    expressjwt({secret: secret, getAntiXSSToken: getToken})(req, res, function(err) {
      assert.equal(err, undefined);
      assert.equal('bar', req.user.foo);
    });
  })

});
