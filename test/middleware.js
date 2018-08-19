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
//const proxyquire  = require('proxyquire');
const sinon       = require('sinon');
const express     = require('express');
const log         = require('metalogger')();
const path        = require('path');
const Promise     = require('bluebird');

const jwts        = require('../lib/jwt-security');
const appConfig = require("./support/appConfig.js");

describe('JWT Middleware Tests', () => {
  describe('Public Key File Present and Good', () =>{
    let app;

    beforeEach(() => {
      app = express();
      app = appConfig.setup(app);
      this.sinonbox = sinon.createSandbox();
    });

    afterEach(() => {
      this.sinonbox.restore();
    });

    it('Invalid JWT token returns 403', (done) => {
      request(app)
        .post('/hello')
        .set('Authorization', 'Bearer foo')
        .expect(403)
        .end(done);
    });

    it('Valid JWT token with invalid ISS still returns 403', (done) => {
      request(app)
        .post('/hello')
        .set('Authorization', `Bearer ${process.env.TEST_BEARER_TOKEN_INVALID_ISS}`)
        .expect(403)
        .end(done);
    });
    
    it('Missing Authorization Header returns 403', (done) => {
      request(app)
        .post('/hello')
        .expect(403)
        .end(done);
    });

    it('Missing Bearer Token returns 403', (done) => {
      request(app)
        .post('/hello')
        .set('Authorization', 'just foo')
        .expect(403)
        .end(done);
    });

    it('Valid JWT token passes through - 200', (done) => {
      request(app)
        .post('/hello')
        .set('Authorization', `Bearer ${process.env.TEST_BEARER_TOKEN}`)
        .expect(200)
        .end(done);
    });

    it('Valid JWT token passes through - 202 Accepted', (done) => {
      request(app)
        .post('/hello202')
        .set('Authorization', `Bearer ${process.env.TEST_BEARER_TOKEN}`)
        .expect(202)
        .end(done);
    });
  });
});

