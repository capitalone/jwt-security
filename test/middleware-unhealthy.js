const request     = require('supertest');
const assert      = require('chai').assert;
const sinon       = require('sinon');
const express     = require('express');
const log         = require('metalogger')();
const path        = require('path');
const Promise     = require('bluebird');

const jwts        = require('../lib/jwt-security');
const appConfig = require("./support/appConfig.js");

describe('JWT Middleware (Unhealthy) Tests', () => {
  describe(('Missing Public Key File'), () => {
    let app;

    beforeEach(() => {
      process.env.NODE_JWT_SEC_PUB_KEY_PATH="/tmp/pub.pem"; // doesn't exist
      app = express();
      app = appConfig.setup(app);
    });

    afterEach(() => {
      process.env.NODE_JWT_SEC_PUB_KEY_PATH=""; // reset 
    });  

    it('Missing Public Key File Leads to HTTP 500', (done) => {

      request(app)
        .post('/hello')
        .set('Authorization', `Bearer ${process.env.TEST_BEARER_TOKEN}`)
        .expect(500)
        .expect((response) => {
          var resp = response.body.description;
          assert.equal(resp, "ACCESS DENIED: Authentication Malfunction");
          process.env.NODE_JWT_SEC_PUB_KEY_PATH=""; // reset 
        })
        .end(done);
    });

    // This is important to prevent constant reading and parsing of missing
    // public key file, in case of misconfigured service
    it('Don\'t try to read missing pub key file on subsequent requests', (done) => {

      request(app)
        .post('/hello')
        .set('Authorization', `Bearer ${process.env.TEST_BEARER_TOKEN}`)
        .expect((response) => {
          var resp = response.body.description;
          assert.equal(resp, "ACCESS DENIED: Authentication Malfunction");
        })
        .expect(500).then(() => {
          request(app)
            .post('/hello')
            .set('Authorization', `Bearer ${process.env.TEST_BEARER_TOKEN}`)
            .expect((response) => {
              var resp = response.body.description;
              // note that second time error message is slightly different
              // ("malfunction*ed*") allowing us subtle hint that different branch
              // of code is catching this
              assert.equal(resp, "ACCESS DENIED: Authentication Malfunctioned");
            })
            .expect(500)
            .end(done);
        });
    });
  });
});

