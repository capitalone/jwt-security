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

const request     = require('supertest');
const assert      = require('chai').assert;
const sinon       = require('sinon');
const express     = require('express');
const log         = require('metalogger')();
const path        = require('path');
const Promise     = require('bluebird');

const jwts        = require('../lib/jwt-security');
const appConfig = require("./support/appConfig.js");

describe('Deduced public key file path', () => {
  // Not using the main app, because we have different config than other tests
  let app = express();
  app = appConfig.setup(app, true); // do not deduce public key path

  it('If no public key path is provided main script\'s config folder is assumed', (done) => {
      request(app)
      .post('/hello')
      .set('Authorization', `Bearer ${process.env.TEST_BEARER_TOKEN}`)
      .expect((response) => {
        let regex = /ACCESS DENIED: Public Key File Path Implicit:.+mocha\/bin\/config\/jwt.pem.pub/i;
        assert.match(response.body.description, regex);
      })
      .expect(203)
      .end(done);
  });
});