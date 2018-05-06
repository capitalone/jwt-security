/*
 * Copyright 2018 Capital One Services, LLC Licensed under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0 Unless required by applicable law
 * or agreed to in writing, software distributed under the License is
 * distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the specific language
 * governing permissions and limitations under the License.
*/

const jwt     = require('jsonwebtoken');
const fs      = require('fs');
const path    = require('path');
const Promise = require('bluebird');
const log     = require('metalogger')();

let publicKey;
let pathToPubKey = '';
let wasPubKeyPathDeduced = false;
let invalidPathToPubKey;

var exports = module.exports = function(opts) {

  // Express.js4 and Bluebird are touchy with unnecessarily firing
  // "forgotten returns", so we may need to enable this to silence noise.
  // For now we are good:
  // Promise.config({
  //   // Enables all warnings except forgotten return statements.
  //   warnings: {
  //       wForgottenReturn: false
  //   }
  // });

  if (process.env.NODE_JWT_SEC_PUB_KEY_PATH) {
    pathToPubKey = process.env.NODE_JWT_SEC_PUB_KEY_PATH;
  } else if (opts && opts.pathToPubKey) {
    pathToPubKey = opts.pathToPubKey;
  }
  invalidPathToPubKey = false;

  try {
    publicKey = getPublicKey(pathToPubKey);
  } catch (err) {
    invalidPathToPubKey = true;
    //throw new Error(err);
  }

  return protector;
};

/**
 * Very specific construct that Express.js4 Middleware expects from 
 * middleware implementations.
 */
var protector = function(req, res, next) {
  validator(req).then(() => {
    return next();
  }).catch((err) => {
    denyAccess(res, err.msg, err.code);
    return next(err);
  })  
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

      // Failing early to ensure we skip unnecessary delays. Meaning:
      // invalidPathToPubKey will be 'false' if a previous request has
      // failed and we shouldn't perform rest of the checks. The compromise
      // here is that: when pubkey path issue is resolved, Node processes
      // will need to be restarted, for the initializer to kick-in.
      if (invalidPathToPubKey) {
        fail.msg = 'Authentication Malfunctioned';
        /* istanbul ignore if  */
        if (process.env.NODE_ENV && process.env.NODE_ENV !== 'test' ) {
          log.error(`Invalid path to public key: ${pathToPubKey}`);
        }

        if (process.env.NODE_ENV && process.env.NODE_ENV === 'test' && 
            wasPubKeyPathDeduced) {
          fail.msg = `Public Key File Path Implicit: ${pathToPubKey}`;
          fail.code = 203;
          return reject(fail);
        }        
        fail.code = 500;
        return reject(fail);
      }

      let violation = protectorHeaderInvalid(req);
      if (violation) {
        fail.msg = violation;
        return reject(fail);
      }
      protectorTokenValidation(req).then(() => {
        return resolve();
      }).catch((err) => {
        fail.msg = err;
        return reject(fail);
      });
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

      verifyToken(token).then((decoded) => {
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

/**
 * Synchronous function. This has to be syncrhonous because system is not
 * ready to be usable until PubKey read is attempted.
 * @param {*} pathToPubKey 
 */
function getPublicKey(_pathToPubKey) {
  
  let data;
  if (!_pathToPubKey) {
    var appDir = path.dirname(require.main.filename);
    pathToPubKey = path.resolve(appDir, 'config', 'jwt.pem.pub');
    wasPubKeyPathDeduced = true;
    data = fs.readFileSync(pathToPubKey);
  } else {
    data = fs.readFileSync(_pathToPubKey);
  }

  return data.toString().trim();
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
