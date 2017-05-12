const request     = require('supertest');
const assert      = require('chai').assert;
const sinon       = require('sinon');
const express     = require('express');
const log         = require('metalogger')();
const Promise     = require('bluebird');
const jwts        = require('../index');

describe('permissions endpoint', () => {
  var app;

  beforeEach((done) => {
    app = express();

    app.listen(3456, function () {
      console.log('test app listening on port 3000!');
      done();
    });

    app.use(jwts());
    app.get('/hello', (req, res) => {
      res.status(200).json({status: "ok"});
    });

    this.sinonbox = sinon.sandbox.create();
  });

  afterEach(() => {
    this.sinonbox.restore();
  });

});