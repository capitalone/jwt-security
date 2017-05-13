const request     = require('supertest');
const assert      = require('chai').assert;
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