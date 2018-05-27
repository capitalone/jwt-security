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
    
    try {
      const pubKey = jwts.getPublicKey();
      assert.equal(pubKey, '', 'Default location test failed');
    } catch (err) {
      var regex = /ENOENT: no such file or directory.+\/mocha\/bin\/config\/jwt.pem.pub/i;
      assert.equal(regex.test(err.toString()), true);
    }
  });

  it('Successful retrival using getPublicKey(path) syntax', () => {
    const pathToPubKey = path.resolve(jwts.rootDir, 'test', 'support', 'jwt.pem.pub');
    const pubKey = jwts.getPublicKey(pathToPubKey);
    assert.equal(pubKey.substr(0,24), '-----BEGIN PUBLIC KEY---');
  });
});