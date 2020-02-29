var jwt = require('../');
var ed25519Keys = require('./ed25519_keys');
var base64url = require('../lib/base64url');
var expect = require('chai').expect;

function fromBase64(base64String) {
  if (typeof Buffer.from === 'function') {
    return Buffer.from(base64String, 'base64');
  } else {
    return new Buffer(base64String, 'base64');
  }
}

describe('public key and private key in different formats (buffer, base64, hex)', function () {
  var privateKeyBuffer = fromBase64(ed25519Keys.privateKey);
  var publicKeyBuffer = fromBase64(ed25519Keys.publicKey);

  var privateKeyFormats = {
    "buffer": privateKeyBuffer,
    "hex": privateKeyBuffer.toString('hex'),
    "base64": privateKeyBuffer.toString('base64')
  }

  var publicKeyFormats = {
    "buffer": publicKeyBuffer,
    "hex": publicKeyBuffer.toString('hex'),
    "base64": publicKeyBuffer.toString('base64')
  }

  Object.keys(privateKeyFormats).forEach(function(privateKeyFormat) {
    describe(privateKeyFormat, function() {
      Object.keys(publicKeyFormats).forEach(function(publicKeyFormat) {
        describe(publicKeyFormat, function() {
          it('should sign and verify', function (done) {
            var token = jwt.sign({ foo: 'bar' }, { key: privateKeyFormats[privateKeyFormat], algorithm: 'ED25519'});
            jwt.verify(token, { key: publicKeyFormats[publicKeyFormat], algorithm: 'ED25519' }, done);
          });
        });
      });

      // Check that JWK is valid
      describe('toJWK', function () {
        it('should create a JWK with valid `x` field', function () {
          var jwk = jwt.toJWK(privateKeyFormats[privateKeyFormat]);
          expect(jwk.x).to.equal(base64url(publicKeyBuffer));
        });
      });
    })
  });
});
