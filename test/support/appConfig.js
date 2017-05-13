// eslint-disable global-require
const path         = require('path')
    , util         = require('util')
    , log          = require('metalogger')();

const jwts        = require('../../lib/jwt-security');

exports.setup = function(app) {
  process.env.NODE_ENV = "test";
  
  let opts = {};
  opts.pathToPubKey = path.resolve(__dirname, 'jwt.pem.pub');

  app.use(jwts(opts));

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