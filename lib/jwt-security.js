const jwt     = require('jsonwebtoken');
const fs      = require('fs');
const path    = require('path');
const Promise = require('bluebird');
const log     = require('metalogger')();

let publicKey;
let pathToPubKey = '';
let invalidPathToPubKey;

var exports = module.exports = function(opts) {

  if (process.env.NODE_JWT_SEC_PUB_KEY_PATH) {
    pathToPubKey = process.env.NODE_JWT_SEC_PUB_KEY_PATH;
  } else if (opts && opts.pathToPubKey) {
    pathToPubKey = opts.pathToPubKey;
  }
  invalidPathToPubKey = false;

  return protector;
};

/**
 * Very specific construct that Express.js4 Middleware expects from 
 * middleware.
 */
var protector = function(req, res, next) {
  return new Promise(function (resolve, reject) {
    return validator(req).then(() => {
      resolve(true);
    }).catch((err) => {
      denyAccess(res, err.msg, err.code);
    });
  }).then((result) => {
    next();
  });
};


/**
 * 
 * Main promisified validator.
 * 
 * @param {*} req - HTTP Request
 */
var validator = function(req) {

  return new Promise((resolve, reject) => {

      let fail = new JWTSecurityError();

      if (invalidPathToPubKey) {
        fail.msg = 'Authentication Malfunctioned';
        fail.code = 500;
        return reject(fail);
      }

      if (!publicKey) { // not yet set, try to read it first time
        return getPublicKey(pathToPubKey).then((pKey) => {
          publicKey = pKey;
          let violation = protectorHeaderInvalid(req);
          if (violation) {
            fail.msg = violation;
            return reject(fail);
          }
          return protectorTokenValidation(req).then(() => {
            return resolve();
          }).catch((err) => {
            fail.msg = err.toString();
            return reject(fail);
          });
        }).catch((err) => {
          if (process.env.NODE_ENV && process.env.NODE_ENV === 'test' &&
              err.wasPubKeyPathDeduced) {
                fail.msg = `Public Key File Path Implicit: ${err.pubKeyPath}`;
                fail.code = 203;
                return reject(fail);
          } else {
            invalidPathToPubKey = true;
            fail.code = 500;
            fail.msg = 'Authentication Malfunction';
            return reject(fail);            
          }
        });
      } else {
        let violation = protectorHeaderInvalid(req);
        if (violation) {
          fail.msg = violation;
          return reject(fail);
        }
        return protectorTokenValidation(req).then(() => {
          return resolve();
        }).catch((err) => {
          fail.msg = err;
          return reject(fail);
        });
      }
  });

};

function protectorHeaderInvalid(req) {
  if (!(req.headers && req.headers.authorization)) {
    return 'Authorization header missing.';
  }
  
  let token = parseToken(req.headers.authorization);
  if (!token) {
    return 'Bearer token missing or invalid in the Authorization header';
  }

  return false;
}

function protectorTokenValidation(req) {
  return new Promise((resolve, reject) => {
      let token = parseToken(req.headers.authorization);

      return verifyToken(token).then((decoded) => {
        if (process.env.NODE_JWT_SEC_EXPECTED_ISS &&
            decoded.iss !== process.env.NODE_JWT_SEC_EXPECTED_ISS) {
              reject(new Error('Invalid Issuer'));
        } else {
          req.headers['x-api-client-id'] = decoded.sub;
          resolve();
        }
      }).catch((err) => {
        err.message = 'Malformed or invalid Bearer token';
        reject(err);
      });
  });
}

function parseToken (authHeader) {
  const regex = /Bearer\s+(\S+)/;
  let matches = authHeader.match(regex);
  if (Array.isArray(matches) && matches.length >1) {
    return matches[1];
  }
  return false;
}

function getPublicKey(pathToPubKey) {
  return new Promise((resolve, reject) => {
    let wasPubKeyPathDeduced = false;

    if (!pathToPubKey) {
      var appDir = path.dirname(require.main.filename);
      pathToPubKey = path.resolve(appDir, 'config', 'jwt.pem.pub');
      wasPubKeyPathDeduced = true;
    }

    fs.readFile(pathToPubKey, function (err, data) {
      if (err) {
        err.wasPubKeyPathDeduced = wasPubKeyPathDeduced;
        err.pubKeyPath = pathToPubKey;
        reject(err);
      } else  {
        resolve(data.toString().trim());
      }
    });
  });
}

function signToken(token, privateKey, duration) {
  var encoded;
  encoded = jwt.sign(token, privateKey, {expiresIn: duration, 
                                         algorithm: 'RS256'});
  return encoded;
}

function verifyToken(token) {
  return new Promise((resolve, reject) => {
    var opts = {
      algorithms: ['RS256']
    };

    jwt.verify(token, 
              publicKey,
              opts,
              function(err, decoded) {
                if (err) {
                  reject(err);
                } else {
                  resolve(decoded);
                }
              });
  });
}

/**
 * denyAccess responds to the caller with tailored error message.
 * 
 * @param {any} res - http response object
 * @param {string} - detailed message
 * @param {number} [responseCode=403] - http response code
 * @param {any} [err={}] - err object
 * about you not handling `err`, just pass it here and we will waste it safely.
 */
function denyAccess(res, reason, responseCode = 403, err = {}) {
  var msg = 'ACCESS DENIED';
  msg += `: ${reason}`;
  var out = {};
  out.description = msg;
  res.status(responseCode).json(out);
}

// @see http://stackoverflow.com/a/32749533
class ExtendableError extends Error {
  constructor(message) {
    super(message);
    this.name = this.constructor.name;
    if (typeof Error.captureStackTrace === 'function') {
      Error.captureStackTrace(this, this.constructor);
    } else { 
      this.stack = (new Error(message)).stack; 
    }
  }
}    

class JWTSecurityError extends ExtendableError {
  constructor(message, responseCode=403) {
    super(message);
    this.msg = message;
    this.code = responseCode;
  }
}

// All of these vars are exposed for unit-testing purposes
exports.parseToken   = parseToken;
exports.verifyToken  = verifyToken;
exports.signToken    = signToken;
exports.getPublicKey = getPublicKey;
exports.rootDir      = path.resolve(__dirname, '../');