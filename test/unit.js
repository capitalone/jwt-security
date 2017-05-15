/** @see: http://chaijs.com/api/bdd/ **/

const assert = require("chai").assert;
const path   = require('path');
const jwts   = require("../lib/jwt-security");

describe('parseToken ', () => {
  it('Invalid tokens fail', () => {
    var sampleToken = "Bearer: somethingother";
    var bearer = jwts.parseToken(sampleToken);
    assert.equal(bearer, false);

    sampleToken = "Bearer-token somethingother";
    bearer = jwts.parseToken(sampleToken);
    assert.equal(bearer, false);
  });

  it('Valid token parses', () => {
    var token = 'ZTMzYjdjYzktMTYwMC00NTE3LThmMzYtYmI0MWEzM2ZkYjFi';
    var sampleToken = `Bearer ${token}`;
    var bearer = jwts.parseToken(sampleToken);
    assert.equal(bearer, token);
  });
});

describe('getPublicKey', () => {
  it('Identify correct default location to get public key from', () => {
    // Attention: When default location is used in an API, the main file is
    // API's index.js and path automatically resolves to
    // <project_root>/config/jwt.pem.pub. During a test run the main file is
    // mocha/bin/index.js and getting error described here means we are
    // resolving default path correctly, even if file isn't read (which isn't
    // the purpose of this test - we test file being read in the next test)
    
    return jwts.getPublicKey().then((pubKey) => {
      assert.equal(pubKey, '', 'Default location test failed');
    }).catch((err) => {
      var regex = /ENOENT: no such file or directory.+\/mocha\/bin\/config\/jwt.pem.pub/i;
      assert.equal(regex.test(err.toString()), true);
    });

  });

  it('Successful retrival using getPublicKey(path) syntax', () => {

    const pathToPubKey = path.resolve(jwts.rootDir, 'test', 'support', 'jwt.pem.pub');

    return jwts.getPublicKey(pathToPubKey).then((pubKey) => {
      assert.equal(pubKey.substr(0,24), '-----BEGIN PUBLIC KEY---');
    });

  });
});