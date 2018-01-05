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

const jwt = require('jsonwebtoken');
const path = require('path');
const jwts = require('../index');
const fs   = require('fs');

process.env.NODE_ENV = 'test';
process.env.NODE_JWT_SEC_EXPECTED_ISS = 'https://api.capitalone.com/';

var token = {
  "iss": "https://api.capitalone.com/",
  "sub": "ab7f1968-0c40-4f67-9ae7-67b9dcaf893f",
  "scopes" : [
    "metadata",
    "authz",
    "storage"
  ]
}; 

var invalidISSToken = {
  "iss": "irakli :)",
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
process.env.TEST_BEARER_TOKEN_INVALID_ISS = jwts.signToken(invalidISSToken, privateKey, '1h');