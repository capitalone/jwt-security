const jwt     = require('jsonwebtoken');
const fs      = require('fs');
const path    = require('path');
const Promise = require('bluebird');
const log     = require('metalogger')();

const expectedIssuer = 'https://api.capitalone.com/';

let publicKey;

var exports = module.exports = function(opts) {

  let pathToPubKey = opts.pathToPubKey || '';

  /*
  getPublicKey(pathToPubKey).then((pKey) => {
    log.info("pKey", pKey);
    publicKey = pKey;
  }).catch((err) => {
    log.info("", err);
  });*/

  publicKey = getPublicKeySync(pathToPubKey)

  return protector;
};

var protector = function(req, res, next) {
      
  if (!publicKey) {
    denyAccess(res, 'Authentication Malfunction', '', 500);
  }

  if (!(req.headers && req.headers.authorization)) {
    return denyAccess(res, 'Authorization header missing.');
  }
  
  var token = parseToken(req.headers.authorization);
  if (!token) {
    return denyAccess(res, 'Bearer token missing or invalid in the Authorization header');
  }

  verifyToken(token).then((decoded) => {
    if (decoded.iss !== expectedIssuer) {
      return denyAccess(res, 'Invalid Issuer');  
    } else {
      req.headers['x-api-client-id'] = decoded.sub;
      return new Promise((resolve, reject) => {
        next();
      });
    }
  }).catch((err) => {
    return denyAccess(res, 'Malformed or invalid Bearer token', 403, err);
  });
};

function parseToken (authHeader) {
  const regex = /Bearer\s+(\S+)/;
  let matches = authHeader.match(regex);
  if (Array.isArray(matches) && matches.length >1) {
    return matches[1];
  }
  return false;
}

function getPublicKey(pathToPubKey) {

  var appDir = path.dirname(require.main.filename);
  pathToPubKey = pathToPubKey || path.resolve(appDir, 'config', 'jwt.pem.pub');

  return new Promise((resolve, reject) => {
    fs.readFile(pathToPubKey, (err, data) => {
      if (err) {
        reject(err);
      } else  {
        resolve(data.toString().trim());
      }
    });
  });
}

function getPublicKeySync(pathToPubKey) {

  var appDir = path.dirname(require.main.filename);
  pathToPubKey = pathToPubKey || path.resolve(appDir, 'config', 'jwt.pem.pub');

  var data = fs.readFileSync(pathToPubKey);
  return data.toString().trim();
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
 * @param {string} [reason=''] - detailed message
 * @param {number} [responseCode=403] - http response code
 * @param {any} [waste=null] - if you need to shut eslint foolishly complaining
 * about you not handling `err`, just pass it here and we will waste it safely.
 */
function denyAccess(res, reason = '', responseCode = 403, waste = null) {
  var msg = 'ACCESS DENIED';
  if (reason) {
    msg += `: ${reason}`;
  }
  var out = {};
  out.description = msg;
  res.status(responseCode).json(out);
}

// All of these vars are exposed for unit-testing purposes
exports.parseToken   = parseToken;
exports.verifyToken  = verifyToken;
exports.signToken    = signToken;
exports.getPublicKey = getPublicKey;
//module.exports.getPublicKey = getPublicKey;
exports.rootDir      = path.resolve(__dirname, '../');