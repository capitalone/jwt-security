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
  var app;

  beforeEach(() => {
    app = express();
    app = appConfig.setup(app);
    this.sinonbox = sinon.sandbox.create();
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
      .set('Authorization', `Bearer ${process.env.TEST_BEARET_TOKEN_INVALID_ISS}`)
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

describe.only(('Missing Public Key File'), () => {

  it('Missing Public Key File Leads to HTTP 500', (done) => {

    process.env.NODE_JWT_SEC_PUB_KEY_PATH="/tmp/pub.pem"; // doesn't exist
    var app = express();
    app = appConfig.setup(app);

    request(app)
      .post('/hello')
      .set('Authorization', `Bearer ${process.env.TEST_BEARER_TOKEN}`)
      .expect((response) => {
        var resp = response.body.description;
        assert.equal(resp, "ACCESS DENIED: Authentication Malfunction");
        process.env.NODE_JWT_SEC_PUB_KEY_PATH=""; // reset 
      })
      .expect(500)
      .end(done);
  });

  // This is important to prevent constant reading and parsing of missing
  // public key file, in case of misconfigured service
  it('Don\'t try to read missing pub key file on subsequent requests', (done) => {

    process.env.NODE_JWT_SEC_PUB_KEY_PATH="/tmp/pub.pem"; // doesn't exist
    var app = express();
    app = appConfig.setup(app);

    request(app)
      .post('/hello')
      .set('Authorization', `Bearer ${process.env.TEST_BEARER_TOKEN}`)
      .expect((response) => {
        var resp = response.body.description;
        assert.equal(resp, "ACCESS DENIED: Authentication Malfunction");
        process.env.NODE_JWT_SEC_PUB_KEY_PATH=""; // reset 
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
            process.env.NODE_JWT_SEC_PUB_KEY_PATH=""; // reset 
          })
          .expect(500)
          .end(done);
      });
  });  

});