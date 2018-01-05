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

// eslint-disable global-require
const path         = require('path')
    , util         = require('util')
    , log          = require('metalogger')();

const jwts        = require('../../lib/jwt-security');

exports.setup = function(app, emptyPubKeyPath = false) {
  process.env.NODE_ENV = "test";
  
  let opts = {};
  opts.pathToPubKey = path.resolve(__dirname, 'jwt.pem.pub');

  if (emptyPubKeyPath) {
    app.use(jwts());
  } else {
    app.use(jwts(opts));
  }

  app.use('/hello', (req, res) => {
    res.status(200).json({
      "status" : "awesome :)"
    });
  });

  app.use('/hello202', (req, res) => {
    res.status(202).json({
      "status" : "awesome :)"
    });
  });

  return app;
};