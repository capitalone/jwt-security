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