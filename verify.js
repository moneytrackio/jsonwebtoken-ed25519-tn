var JsonWebTokenError = require('./lib/JsonWebTokenError');
var NotBeforeError    = require('./lib/NotBeforeError');
var TokenExpiredError = require('./lib/TokenExpiredError');
var decode            = require('./decode');
var timespan          = require('./lib/timespan');
var ed25519Utils      = require('./lib/ed25519Utils');
var jws               = require('jws');
var ed25519           = require('./lib/ed25519');
var util              = require('util');

module.exports = function (jwtString, secretOrPublicKey, options, callback) {
  if ((typeof options === 'function') && !callback) {
    callback = options;
    options = {};
  }

  if (!options) {
    options = {};
  }

  //clone this object since we are going to mutate it.
  options = Object.assign({}, options);

  var done;

  if (callback) {
    done = callback;
  } else {
    done = function(err, data) {
      if (err) throw err;
      return data;
    };
  }

  // secretOrPublicKey may be an object of the format: { "algorithm": ..., "key": ... }
  if (secretOrPublicKey && secretOrPublicKey.algorithm) {
    if (options.algorithm) {
      if (options.algorithm !== secretOrPublicKey.algorithm) {
        return done(new JsonWebTokenError('The algorithm specified in the key is different from the algorithm specified in the options'));
      }
    } else {
      options.algorithm = secretOrPublicKey.algorithm;
    }
    secretOrPublicKey = secretOrPublicKey.key;
  }

  if (options.clockTimestamp && typeof options.clockTimestamp !== 'number') {
    return done(new JsonWebTokenError('clockTimestamp must be a number'));
  }

  var clockTimestamp = options.clockTimestamp || Math.floor(Date.now() / 1000);

  if (!jwtString){
    return done(new JsonWebTokenError('jwt must be provided'));
  }

  if (typeof jwtString !== 'string') {
    return done(new JsonWebTokenError('jwt must be a string'));
  }

  var parts = jwtString.split('.');

  if (parts.length !== 3){
    return done(new JsonWebTokenError('jwt malformed'));
  }

  var hasSignature = parts[2].trim() !== '';

  if (!hasSignature && secretOrPublicKey){
    return done(new JsonWebTokenError('jwt signature is required'));
  }

  if (hasSignature && !secretOrPublicKey) {
    return done(new JsonWebTokenError('secret or public key must be provided'));
  }

  if (!options.algorithm) {
    var assumedAlgorithms = ~(secretOrPublicKey || '').toString().indexOf('BEGIN CERTIFICATE') ||
                         ~(secretOrPublicKey || '').toString().indexOf('BEGIN PUBLIC KEY') ?
                          [ 'RS256','RS384','RS512','ES256','ES384','ES512' ] :
                         ~(secretOrPublicKey || '').toString().indexOf('BEGIN RSA PUBLIC KEY') ?
                          [ 'RS256','RS384','RS512' ] :
                          [ 'HS256','HS384','HS512' ];
    // We intentionally don't tell the user that his algorithm might be "none".
    return done(new JsonWebTokenError('algorithm must be specified in the options or in the key. Looking at the key, it is probably one of: ' + assumedAlgorithms.join(', ')))
  }

  var decodedToken;

  try {
    decodedToken = decode(jwtString, { complete: true });
  } catch(err) {
    return done(err);
  }

  if (!decodedToken) {
    return done(new JsonWebTokenError('invalid token'));
  }

  var header = decodedToken.header;

  if (!(options.algorithm === 'ED25519' && header.alg === 'EdDSA' ||
        options.algorithm === header.alg)) {
    return done(new JsonWebTokenError('invalid algorithm'));
  }

  var getSecret;

  if (typeof secretOrPublicKey === 'function') {
    if (!callback) {
      return done(new JsonWebTokenError('verify must be called asynchronous if secret or public key is provided as a callback'));
    }
    getSecret = secretOrPublicKey;
  }
  else {
    getSecret = function(header, secretCallback) {
      return secretCallback(null, secretOrPublicKey);
    };
  }

  return getSecret(header, function(err, secretOrPublicKey) {
    if(err) {
      return done(new JsonWebTokenError('error in secret or public key callback: ' + err.message));
    }

    var hasSignature = parts[2].trim() !== '';

    if (!hasSignature && secretOrPublicKey){
      return done(new JsonWebTokenError('jwt signature is required'));
    }

    if (hasSignature && !secretOrPublicKey) {
      return done(new JsonWebTokenError('secret or public key must be provided'));
    }

    if (header.alg === 'ED25519') {
      try {
        secretOrPublicKey = ed25519Utils.toPublicKey(secretOrPublicKey);
      } catch (err) {
        return done(new JsonWebTokenError('Invalid Ed25519 public key'));
      }
    }

    var valid;

    try {
      if (header.alg === 'ED25519') {
        // Token must have good format because jws.decode validated it.
        var securedInput = ed25519Utils.bufferFromString(util.format('%s.%s', parts[0], parts[1]));
        var signature = ed25519Utils.bufferFromString(parts[2], 'base64');
        valid = (signature.length === ed25519Utils.SIGNATURE_SIZE) && ed25519.Verify(securedInput, signature, secretOrPublicKey);
      } else {
        valid = jws.verify(jwtString, header.alg, secretOrPublicKey);
      }
    } catch (e) {
      return done(e);
    }

    if (!valid) {
      return done(new JsonWebTokenError('invalid signature'));
    }

    var payload = decodedToken.payload;

    if (typeof payload.nbf !== 'undefined' && !options.ignoreNotBefore) {
      if (typeof payload.nbf !== 'number') {
        return done(new JsonWebTokenError('invalid nbf value'));
      }
      if (payload.nbf > clockTimestamp + (options.clockTolerance || 0)) {
        return done(new NotBeforeError('jwt not active', new Date(payload.nbf * 1000)));
      }
    }

    if (typeof payload.exp !== 'undefined' && !options.ignoreExpiration) {
      if (typeof payload.exp !== 'number') {
        return done(new JsonWebTokenError('invalid exp value'));
      }
      if (clockTimestamp >= payload.exp + (options.clockTolerance || 0)) {
        return done(new TokenExpiredError('jwt expired', new Date(payload.exp * 1000)));
      }
    }

    if (options.audience) {
      var audiences = Array.isArray(options.audience) ? options.audience : [options.audience];
      var target = Array.isArray(payload.aud) ? payload.aud : [payload.aud];

      var match = target.some(function (targetAudience) {
        return audiences.some(function (audience) {
          return audience instanceof RegExp ? audience.test(targetAudience) : audience === targetAudience;
        });
      });

      if (!match) {
        return done(new JsonWebTokenError('jwt audience invalid. expected: ' + audiences.join(' or ')));
      }
    }

    if (options.issuer) {
      var invalid_issuer =
              (typeof options.issuer === 'string' && payload.iss !== options.issuer) ||
              (Array.isArray(options.issuer) && options.issuer.indexOf(payload.iss) === -1);

      if (invalid_issuer) {
        return done(new JsonWebTokenError('jwt issuer invalid. expected: ' + options.issuer));
      }
    }

    if (options.subject) {
      if (payload.sub !== options.subject) {
        return done(new JsonWebTokenError('jwt subject invalid. expected: ' + options.subject));
      }
    }

    if (options.jwtid) {
      if (payload.jti !== options.jwtid) {
        return done(new JsonWebTokenError('jwt jwtid invalid. expected: ' + options.jwtid));
      }
    }

    if (options.maxAge) {
      if (typeof payload.iat !== 'number') {
        return done(new JsonWebTokenError('iat required when maxAge is specified'));
      }

      var maxAgeTimestamp = timespan(options.maxAge, payload.iat);
      if (typeof maxAgeTimestamp === 'undefined') {
        return done(new JsonWebTokenError('"maxAge" should be a number of seconds or string representing a timespan eg: "1d", "20h", 60'));
      }
      if (clockTimestamp >= maxAgeTimestamp + (options.clockTolerance || 0)) {
        return done(new TokenExpiredError('maxAge exceeded', new Date(maxAgeTimestamp * 1000)));
      }
    }

    return done(null, payload);
  });
};
