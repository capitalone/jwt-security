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

  it.skip('Missing Public Key File Leads to HTTP 500', (done) => {

/*
    var jwts_proxy = proxyquire('../lib/jwt-security.js', {
      'getPublicKey': function () {
        return new Promise(function(resolve, reject) {
          log.info("and this did happen");
          reject('could not read from file');
        });
      }
    });
*/

    var stub = this.sinonbox.stub(jwts, "getPublicKey");
    //log.info("stub", stub);
    stub.callsFake(() => {
      log.info("aaaaaaaaaaa");
      return new Promise((resolve, reject) => reject('error'));
    });

    request(app)
      .post('/hello')
      .set('Authorization', `Bearer ${process.env.TEST_BEARER_TOKEN}`)
      .expect((response) => {
        log.info("response", response.body);
      })
      .expect(500)
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