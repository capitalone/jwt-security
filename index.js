const jwt     = require('jsonwebtoken');
const fs      = require('fs');
const path    = require('path');
const Promise = require('bluebird');
const log     = require('metalogger')();

const expectedIssuer = 'https://api.capitalone.com/';

let publicKey;

var exports = module.exports = function(options) {
  getPublicKey().then((pKey) => {
    publicKey = pKey;
  });

  return protector;
};

var protector = function(req, res, next) {
      
  if (!(req.headers && req.headers.authorization)) {
    return denyAccess(res, 'Authorization header missing.');
  }
  
  var token = parseToken(req.headers.authorization);
  if (!token) {
    return denyAccess(res, 'Bearer token missing or invalid in the Authorization header');
  }

  decodeToken(token).then((decoded) => {
    if (decoded.iss !== expectedIssuer) {
      return denyAccess(res, 'Invalid Issuer');  
    } else {
      req.headers['x-api-client-id'] = decoded.sub;
      return new Promise((resolve, reject) => {
        next();
      });
      
    }
  }).catch((err) => {
    log.error(err);
    return denyAccess(res, 'Malformed or invalid Bearer token');
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

function getPublicKey() {

  var appDir = path.dirname(require.main.filename);
  return new Promise((resolve, reject) => {
    var pathToPubKey = path.resolve(appDir, 'config', 'jwt.pem.pub');
    fs.readFile(pathToPubKey, (err, data) => {
      if (err) {
        reject(err);
      } else  {
        resolve(data.toString().trim());
      }
    });
  });
}

function decodeToken(token) {

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

function denyAccess(res, reason = '') {
  var msg = 'ACCESS DENIED';
  if (reason) {
    msg += `: ${reason}`;
  }
  var out = {};
  out.description = msg;
  res.status(403).json(out);
}

exports.parseToken = parseToken;
