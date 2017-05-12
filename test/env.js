const jwt = require('jsonwebtoken');
const path = require('path');
const jwts = require('../index');
const fs   = require('fs');

process.env.NODE_ENV = 'test';

var token = {
  "iss": "https://api.capitalone.com/",
  "sub": "ab7f1968-0c40-4f67-9ae7-67b9dcaf893f",
  "scopes" : [
    "metadata",
    "authz",
    "storage"
  ]
}; 

var pathToPrivateKey = path.resolve(__dirname, 'support', 'jwt.pem.base64');
var privateKey = fs.readFileSync(pathToPrivateKey).toString();
privateKey = new Buffer(privateKey, 'base64').toString('ascii');

process.env.TEST_PRIVATE_KEY = privateKey;
process.env.TEST_BEARER_TOKEN = jwts.signToken(token, privateKey, '1h');