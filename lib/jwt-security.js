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

var protector = function(req, res, next) {

  if (invalidPathToPubKey) {
    return denyAccess(res, 'Authentication Malfunctioned', 500);
  }

  if (!publicKey) { // not yet set, try to read it first time
    getPublicKey(pathToPubKey).then((pKey, moreInfo = {}) => {
      publicKey = pKey;
      protectorValidations(req, res, next);
    }).catch((err) => {
      if (process.env.NODE_ENV && process.env.NODE_ENV === 'test' &&
          err.wasPubKeyPathDeduced) {
        return denyAccess(res, `Public Key File Path Implicit: ${err.pubKeyPath}`, 203, err);
      } else {
        invalidPathToPubKey = true;
        return denyAccess(res, 'Authentication Malfunction', 500, err);
      }
    });
  } else {
    protectorValidations(req, res, next);
  }
};

function protectorValidations(req, res, next) {
  if (!(req.headers && req.headers.authorization)) {
    return denyAccess(res, 'Authorization header missing.');
  }
  
  var token = parseToken(req.headers.authorization);
  if (!token) {
    return denyAccess(res, 'Bearer token missing or invalid in the Authorization header');
  }

  verifyToken(token).then((decoded) => {
    if (process.env.NODE_JWT_SEC_EXPECTED_ISS &&
        decoded.iss !== process.env.NODE_JWT_SEC_EXPECTED_ISS) {
      return denyAccess(res, 'Invalid Issuer');  
    } else {
      req.headers['x-api-client-id'] = decoded.sub;
      return next();
    }
  }).catch((err) => {
    return denyAccess(res, 'Malformed or invalid Bearer token', 403, err);
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

  let wasPubKeyPathDeduced = false;

  if (!pathToPubKey) {
    var appDir = path.dirname(require.main.filename);
    pathToPubKey = path.resolve(appDir, 'config', 'jwt.pem.pub');
    wasPubKeyPathDeduced = true;
  }

  return new Promise((resolve, reject) => {
    fs.readFile(pathToPubKey, (err, data) => {
      if (err) {
        err.wasPubKeyPathDeduced = wasPubKeyPathDeduced;
        err.pubKeyPath = pathToPubKey;
        reject(err);
      } else  {
        let more = {};
        more.wasPubKeyPathDeduced = wasPubKeyPathDeduced;
        more.pubKeyPath = pathToPubKey;
        resolve(data.toString().trim(), more);
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

  var opts = {
    algorithms: ['RS256']
  };

  return new Promise((resolve, reject) => {
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

// All of these vars are exposed for unit-testing purposes
exports.parseToken   = parseToken;
exports.verifyToken  = verifyToken;
exports.signToken    = signToken;
exports.getPublicKey = getPublicKey;
exports.rootDir      = path.resolve(__dirname, '../');