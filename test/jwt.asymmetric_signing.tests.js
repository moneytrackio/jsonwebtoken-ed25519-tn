var jwt = require('../index');
var ed25519Keys = require('./ed25519_keys');
var fs = require('fs');
var path = require('path');

var expect = require('chai').expect;
var assert = require('chai').assert;
var ms = require('ms');
var sinon = require('sinon');

function loadKey(filename) {
  return fs.readFileSync(path.join(__dirname, filename));
}

var algorithms = {
  RS256: {
    pub_key: loadKey('pub.pem'),
    priv_key: loadKey('priv.pem'),
    invalid_pub_key: loadKey('invalid_pub.pem')
  },
  ES256: {
    // openssl ecparam -name secp256r1 -genkey -param_enc explicit -out ecdsa-private.pem
    priv_key: loadKey('ecdsa-private.pem'),
    // openssl ec -in ecdsa-private.pem -pubout -out ecdsa-public.pem
    pub_key: loadKey('ecdsa-public.pem'),
    invalid_pub_key: loadKey('ecdsa-public-invalid.pem')
  },
  ED25519: {
    priv_key: ed25519Keys.privateKey,
    pub_key: ed25519Keys.publicKey,
    invalid_pub_key: ed25519Keys.invalidPublicKey
  }
};

describe('Asymmetric Algorithms', function(){

  Object.keys(algorithms).forEach(function (algorithm) {
    describe(algorithm, function () {
      var pub = algorithms[algorithm].pub_key;
      var priv = algorithms[algorithm].priv_key;

      // "invalid" means it is not the public key for the loaded "priv" key
      var invalid_pub = algorithms[algorithm].invalid_pub_key;

      describe('when signing a token', function () {
        var token = jwt.sign({ foo: 'bar' }, priv, { algorithm: algorithm });

        it('should be syntactically valid', function () {
          expect(token).to.be.a('string');
          expect(token.split('.')).to.have.length(3);
        });

        context('asynchronous', function () {
          it('should validate with public key', function (done) {
            jwt.verify(token, pub, { algorithm: algorithm }, function (err, decoded) {
              assert.ok(decoded.foo);
              assert.equal('bar', decoded.foo);
              done();
            });
          });

          it('should throw with invalid public key', function (done) {
            jwt.verify(token, invalid_pub, { algorithm: algorithm }, function (err, decoded) {
              assert.isUndefined(decoded);
              assert.isNotNull(err);
              done();
            });
          });
        });

        context('synchronous', function () {
          it('should validate with public key', function () {
            var decoded = jwt.verify(token, pub, { algorithm: algorithm });
            assert.ok(decoded.foo);
            assert.equal('bar', decoded.foo);
          });

          it('should throw with invalid public key', function () {
            var jwtVerify = jwt.verify.bind(null, token, invalid_pub, { algorithm: algorithm })
            assert.throw(jwtVerify, 'invalid signature');
          });
        });

      });

      describe('when signing a token with expiration', function () {
        var token = jwt.sign({ foo: 'bar' }, priv, { algorithm: algorithm, expiresIn: '10m' });

        it('should be valid expiration', function (done) {
          jwt.verify(token, pub, { algorithm: algorithm }, function (err, decoded) {
            assert.isNotNull(decoded);
            assert.isNull(err);
            done();
          });
        });

        it('should be invalid', function (done) {
          // expired token
          token = jwt.sign({ foo: 'bar' }, priv, { algorithm: algorithm, expiresIn: -1 * ms('10m') });

          jwt.verify(token, pub, { algorithm: algorithm }, function (err, decoded) {
            assert.isUndefined(decoded);
            assert.isNotNull(err);
            assert.equal(err.name, 'TokenExpiredError');
            assert.instanceOf(err.expiredAt, Date);
            assert.instanceOf(err, jwt.TokenExpiredError);
            done();
          });
        });

        it('should NOT be invalid', function (done) {
          // expired token
          token = jwt.sign({ foo: 'bar' }, priv, { algorithm: algorithm, expiresIn: -1 * ms('10m') });

          jwt.verify(token, pub, { algorithm: algorithm, ignoreExpiration: true }, function (err, decoded) {
            assert.ok(decoded.foo);
            assert.equal('bar', decoded.foo);
            done();
          });
        });
      });

      describe('when signing a token with not before', function () {
        var token = jwt.sign({ foo: 'bar' }, priv, { algorithm: algorithm, notBefore: -10 * 3600 });

        it('should be valid expiration', function (done) {
          jwt.verify(token, pub, { algorithm: algorithm }, function (err, decoded) {
            assert.isNotNull(decoded);
            assert.isNull(err);
            done();
          });
        });

        it('should be invalid', function (done) {
          // not active token
          token = jwt.sign({ foo: 'bar' }, priv, { algorithm: algorithm, notBefore: '10m' });

          jwt.verify(token, pub, { algorithm: algorithm }, function (err, decoded) {
            assert.isUndefined(decoded);
            assert.isNotNull(err);
            assert.equal(err.name, 'NotBeforeError');
            assert.instanceOf(err.date, Date);
            assert.instanceOf(err, jwt.NotBeforeError);
            done();
          });
        });


        it('should valid when date are equals', function (done) {
          var fakeClock = sinon.useFakeTimers({now: 1451908031});

          token = jwt.sign({ foo: 'bar' }, priv, { algorithm: algorithm, notBefore: 0 });

          jwt.verify(token, pub, { algorithm: algorithm }, function (err, decoded) {
            fakeClock.uninstall();
            assert.isNull(err);
            assert.isNotNull(decoded);
            done();
          });
        });

        it('should NOT be invalid', function (done) {
          // not active token
          token = jwt.sign({ foo: 'bar' }, priv, { algorithm: algorithm, notBefore: '10m' });

          jwt.verify(token, pub, { algorithm: algorithm, ignoreNotBefore: true }, function (err, decoded) {
            assert.ok(decoded.foo);
            assert.equal('bar', decoded.foo);
            done();
          });
        });
      });

      describe('when signing a token with audience', function () {
        var token = jwt.sign({ foo: 'bar' }, priv, { algorithm: algorithm, audience: 'urn:foo' });

        it('should check audience', function (done) {
          jwt.verify(token, pub, { algorithm: algorithm, audience: 'urn:foo' }, function (err, decoded) {
            assert.isNotNull(decoded);
            assert.isNull(err);
            done();
          });
        });

        it('should check audience using RegExp', function (done) {
          jwt.verify(token, pub, { algorithm: algorithm, audience: /urn:f[o]{2}/  }, function (err, decoded) {
            assert.isNotNull(decoded);
            assert.isNull(err);
            done();
          });
        });

        it('should check audience in array', function (done) {
          jwt.verify(token, pub, { algorithm: algorithm, audience: ['urn:foo', 'urn:other'] }, function (err, decoded) {
            assert.isNotNull(decoded);
            assert.isNull(err);
            done();
          });
        });

        it('should check audience in array using RegExp', function (done) {
          jwt.verify(token, pub, { algorithm: algorithm, audience: ['urn:bar', /urn:f[o]{2}/, 'urn:other'] }, function (err, decoded) {
            assert.isNotNull(decoded);
            assert.isNull(err);
            done();
          });
        });

        it('should throw when invalid audience', function (done) {
          jwt.verify(token, pub, { algorithm: algorithm, audience: 'urn:wrong' }, function (err, decoded) {
            assert.isUndefined(decoded);
            assert.isNotNull(err);
            assert.equal(err.name, 'JsonWebTokenError');
            assert.instanceOf(err, jwt.JsonWebTokenError);
            done();
          });
        });

        it('should throw when invalid audience using RegExp', function (done) {
          jwt.verify(token, pub, { algorithm: algorithm, audience: /urn:bar/ }, function (err, decoded) {
            assert.isUndefined(decoded);
            assert.isNotNull(err);
            assert.equal(err.name, 'JsonWebTokenError');
            assert.instanceOf(err, jwt.JsonWebTokenError);
            done();
          });
        });

        it('should throw when invalid audience in array', function (done) {
          jwt.verify(token, pub, { algorithm: algorithm, audience: ['urn:wrong', 'urn:morewrong', /urn:bar/] }, function (err, decoded) {
            assert.isUndefined(decoded);
            assert.isNotNull(err);
            assert.equal(err.name, 'JsonWebTokenError');
            assert.instanceOf(err, jwt.JsonWebTokenError);
            done();
          });
        });

      });

      describe('when signing a token with array audience', function () {
        var token = jwt.sign({ foo: 'bar' }, priv, { algorithm: algorithm, audience: ['urn:foo', 'urn:bar'] });

        it('should check audience', function (done) {
          jwt.verify(token, pub, { algorithm: algorithm, audience: 'urn:foo' }, function (err, decoded) {
            assert.isNotNull(decoded);
            assert.isNull(err);
            done();
          });
        });

        it('should check other audience', function (done) {
          jwt.verify(token, pub, { algorithm: algorithm, audience: 'urn:bar' }, function (err, decoded) {
            assert.isNotNull(decoded);
            assert.isNull(err);
            done();
          });
        });

        it('should check audience using RegExp', function (done) {
          jwt.verify(token, pub, { algorithm: algorithm, audience: /urn:f[o]{2}/ }, function (err, decoded) {
            assert.isNotNull(decoded);
            assert.isNull(err);
            done();
          });
        });

        it('should check audience in array', function (done) {
          jwt.verify(token, pub, { algorithm: algorithm, audience: ['urn:foo', 'urn:other'] }, function (err, decoded) {
            assert.isNotNull(decoded);
            assert.isNull(err);
            done();
          });
        });

        it('should check audience in array using RegExp', function (done) {
          jwt.verify(token, pub, { algorithm: algorithm, audience: ['urn:one', 'urn:other', /urn:f[o]{2}/] }, function (err, decoded) {
            assert.isNotNull(decoded);
            assert.isNull(err);
            done();
          });
        });

        it('should throw when invalid audience', function (done) {
          jwt.verify(token, pub, { algorithm: algorithm, audience: 'urn:wrong' }, function (err, decoded) {
            assert.isUndefined(decoded);
            assert.isNotNull(err);
            assert.equal(err.name, 'JsonWebTokenError');
            assert.instanceOf(err, jwt.JsonWebTokenError);
            done();
          });
        });

        it('should throw when invalid audience using RegExp', function (done) {
          jwt.verify(token, pub, { algorithm: algorithm, audience: /urn:wrong/ }, function (err, decoded) {
            assert.isUndefined(decoded);
            assert.isNotNull(err);
            assert.equal(err.name, 'JsonWebTokenError');
            assert.instanceOf(err, jwt.JsonWebTokenError);
            done();
          });
        });

        it('should throw when invalid audience in array', function (done) {
          jwt.verify(token, pub, { algorithm: algorithm, audience: ['urn:wrong', 'urn:morewrong'] }, function (err, decoded) {
            assert.isUndefined(decoded);
            assert.isNotNull(err);
            assert.equal(err.name, 'JsonWebTokenError');
            assert.instanceOf(err, jwt.JsonWebTokenError);
            done();
          });
        });

        it('should throw when invalid audience in array', function (done) {
          jwt.verify(token, pub, { algorithm: algorithm, audience: ['urn:wrong', 'urn:morewrong', /urn:alsowrong/] }, function (err, decoded) {
            assert.isUndefined(decoded);
            assert.isNotNull(err);
            assert.equal(err.name, 'JsonWebTokenError');
            assert.instanceOf(err, jwt.JsonWebTokenError);
            done();
          });
        });

      });

      describe('when signing a token without audience', function () {
        var token = jwt.sign({ foo: 'bar' }, priv, { algorithm: algorithm });

        it('should check audience', function (done) {
          jwt.verify(token, pub, { algorithm: algorithm, audience: 'urn:wrong' }, function (err, decoded) {
            assert.isUndefined(decoded);
            assert.isNotNull(err);
            assert.equal(err.name, 'JsonWebTokenError');
            assert.instanceOf(err, jwt.JsonWebTokenError);
            done();
          });
        });

        it('should check audience using RegExp', function (done) {
          jwt.verify(token, pub, { algorithm: algorithm, audience: /urn:wrong/ }, function (err, decoded) {
            assert.isUndefined(decoded);
            assert.isNotNull(err);
            assert.equal(err.name, 'JsonWebTokenError');
            assert.instanceOf(err, jwt.JsonWebTokenError);
            done();
          });
        });

        it('should check audience in array', function (done) {
          jwt.verify(token, pub, { algorithm: algorithm, audience: ['urn:wrong', 'urn:morewrong', /urn:alsowrong/] }, function (err, decoded) {
            assert.isUndefined(decoded);
            assert.isNotNull(err);
            assert.equal(err.name, 'JsonWebTokenError');
            assert.instanceOf(err, jwt.JsonWebTokenError);
            done();
          });
        });

      });

      describe('when signing a token with issuer', function () {
        var token = jwt.sign({ foo: 'bar' }, priv, { algorithm: algorithm, issuer: 'urn:foo' });

        it('should check issuer', function (done) {
          jwt.verify(token, pub, { algorithm: algorithm, issuer: 'urn:foo' }, function (err, decoded) {
            assert.isNotNull(decoded);
            assert.isNull(err);
            done();
          });
        });

        it('should check the issuer when providing a list of valid issuers', function (done) {
          jwt.verify(token, pub, { algorithm: algorithm, issuer: ['urn:foo', 'urn:bar'] }, function (err, decoded) {
            assert.isNotNull(decoded);
            assert.isNull(err);
            done();
          });
        });

        it('should throw when invalid issuer', function (done) {
          jwt.verify(token, pub, { algorithm: algorithm, issuer: 'urn:wrong' }, function (err, decoded) {
            assert.isUndefined(decoded);
            assert.isNotNull(err);
            assert.equal(err.name, 'JsonWebTokenError');
            assert.instanceOf(err, jwt.JsonWebTokenError);
            done();
          });
        });
      });

      describe('when signing a token without issuer', function () {
        var token = jwt.sign({ foo: 'bar' }, priv, { algorithm: algorithm });

        it('should check issuer', function (done) {
          jwt.verify(token, pub, { algorithm: algorithm, issuer: 'urn:foo' }, function (err, decoded) {
            assert.isUndefined(decoded);
            assert.isNotNull(err);
            assert.equal(err.name, 'JsonWebTokenError');
            assert.instanceOf(err, jwt.JsonWebTokenError);
            done();
          });
        });
      });

      describe('when signing a token with subject', function () {
        var token = jwt.sign({ foo: 'bar' }, priv, { algorithm: algorithm, subject: 'subject' });

        it('should check subject', function (done) {
          jwt.verify(token, pub, { algorithm: algorithm, subject: 'subject' }, function (err, decoded) {
            assert.isNotNull(decoded);
            assert.isNull(err);
            done();
          });
        });

        it('should throw when invalid subject', function (done) {
          jwt.verify(token, pub, { algorithm: algorithm, subject: 'wrongSubject' }, function (err, decoded) {
            assert.isUndefined(decoded);
            assert.isNotNull(err);
            assert.equal(err.name, 'JsonWebTokenError');
            assert.instanceOf(err, jwt.JsonWebTokenError);
            done();
          });
        });
      });

      describe('when signing a token without subject', function () {
        var token = jwt.sign({ foo: 'bar' }, priv, { algorithm: algorithm });

        it('should check subject', function (done) {
          jwt.verify(token, pub, { algorithm: algorithm, subject: 'subject' }, function (err, decoded) {
            assert.isUndefined(decoded);
            assert.isNotNull(err);
            assert.equal(err.name, 'JsonWebTokenError');
            assert.instanceOf(err, jwt.JsonWebTokenError);
            done();
          });
        });
      });

      describe('when signing a token with jwt id', function () {
        var token = jwt.sign({ foo: 'bar' }, priv, { algorithm: algorithm, jwtid: 'jwtid' });

        it('should check jwt id', function (done) {
          jwt.verify(token, pub, { algorithm: algorithm, jwtid: 'jwtid' }, function (err, decoded) {
            assert.isNotNull(decoded);
            assert.isNull(err);
            done();
          });
        });

        it('should throw when invalid jwt id', function (done) {
          jwt.verify(token, pub, { algorithm: algorithm, jwtid: 'wrongJwtid' }, function (err, decoded) {
            assert.isUndefined(decoded);
            assert.isNotNull(err);
            assert.equal(err.name, 'JsonWebTokenError');
            assert.instanceOf(err, jwt.JsonWebTokenError);
            done();
          });
        });
      });

      describe('when signing a token without jwt id', function () {
        var token = jwt.sign({ foo: 'bar' }, priv, { algorithm: algorithm });

        it('should check jwt id', function (done) {
          jwt.verify(token, pub, { algorithm: algorithm, jwtid: 'jwtid' }, function (err, decoded) {
            assert.isUndefined(decoded);
            assert.isNotNull(err);
            assert.equal(err.name, 'JsonWebTokenError');
            assert.instanceOf(err, jwt.JsonWebTokenError);
            done();
          });
        });
      });

      describe('when verifying a malformed token', function () {
        it('should throw', function (done) {
          jwt.verify('fruit.fruit.fruit', pub, function (err, decoded) {
            assert.isUndefined(decoded);
            assert.isNotNull(err);
            assert.equal(err.name, 'JsonWebTokenError');
            done();
          });
        });
      });

      describe('when decoding a jwt token with additional parts', function () {
        var token = jwt.sign({ foo: 'bar' }, priv, { algorithm: algorithm });

        it('should throw', function (done) {
          jwt.verify(token + '.foo', pub, function (err, decoded) {
            assert.isUndefined(decoded);
            assert.isNotNull(err);
            done();
          });
        });
      });

      describe('when decoding a invalid jwt token', function () {
        it('should return null', function (done) {
          var payload = jwt.decode('whatever.token');
          assert.isNull(payload);
          done();
        });
      });

      describe('when decoding a valid jwt token', function () {
        it('should return the payload', function (done) {
          var obj = { foo: 'bar' };
          var token = jwt.sign(obj, priv, { algorithm: algorithm });
          var payload = jwt.decode(token);
          assert.equal(payload.foo, obj.foo);
          done();
        });
        it('should return the header and payload and signature if complete option is set', function (done) {
          var obj = { foo: 'bar' };
          var token = jwt.sign(obj, priv, { algorithm: algorithm });
          var decoded = jwt.decode(token, { complete: true });
          assert.equal(decoded.payload.foo, obj.foo);
          assert.deepEqual(decoded.header, { typ: 'JWT', alg: algorithm === 'Ed25519' ? 'EdDSA' : algorithm });
          assert.ok(typeof decoded.signature == 'string');
          done();
        });
      });
    });
  });
});
