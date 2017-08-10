[![License](https://img.shields.io/badge/license-Apache%202-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

# JWT Security

JSON Web Tokens (JWT)-based security middleware for
[Express.js](https://expressjs.com/)

## Motivation 

Public API perimeters of systems are typically secured using API Gateways and OAuth2. However, when we implement a system using a microservice architecture, it is important to also secure communication *between* microservices, even if they are "hidden" from the outside world, behind the Gateway. An effective, and increasingly popular, solution to securing such communications is: using JSON Web Tokens (JWTs). JWTs have gained significant popularity due to their decentralized, stateless and asymmetric approach to authentication that makes a solution based on them scalable, performant and secure.  You can read more about using JWTs for security at: http://www.freshblurbs.com/blog/2017/04/09/json-web-tokens-oauth2.html

## Installation

In package.json:

```
"jwt-security" : "git+https://github.kdc.capitalone.com/digital-trust/jwt-security.git"
```

## Using:

Wherever you load your middleware (e.g. appConfig.js for your
[NodeBootstrap](http://nodebootstrap.io)), make sure to insert this, **before**
the wiring-up of route handlers:

```
app.use(require('jwt-security')(opts));
```

For instance:

```
let opts = {};
// our pem file is under 'config' folder of the project root
opts.pathToPubKey = path.resolve(require.resolve('express'), '../../../config/jwt.pem.pub');

app.use(require('jwt-security')(opts));

// route mappings come here:
app.use('/users', usersHandler);
```

## Customization

JWT-Security takes into account following environmental variables:

- `NODE_JWT_SEC_PUB_KEY_PATH` - absolute path to public key file the middleware
  should be using.
- `NODE_JWT_SEC_EXPECTED_ISS` - expected `iss` ([RFC7519](https://tools.ietf.org/html/rfc7519#section-4.1.1)) claim in JWT. If set, JWT
  security will validate the claim to equal this value.

## Contributors

We welcome your interest in Capital One’s Open Source Projects (the
“Project”). Any Contributor to the project must accept and sign a CLA
indicating agreement to the license terms. Except for the license
granted in this CLA to Capital One and to recipients of software
distributed by Capital One, you reserve all right, title, and interest
in and to your contributions; this CLA does not impact your rights to
use your own contributions for any other purpose.

- [Link to CLA](https://docs.google.com/forms/d/19LpBBjykHPox18vrZvBbZUcK6gQTj7qv1O5hCduAZFU/viewform)
- [Link to Corporate Agreement](https://docs.google.com/forms/d/e/1FAIpQLSeAbobIPLCVZD_ccgtMWBDAcN68oqbAJBQyDTSAQ1AkYuCp_g/viewform?usp=send_form)

This project adheres to the
[Open Source Code of Conduct](http://www.capitalone.io/codeofconduct/). By
participating, you are expected to honor this code.


## License

Copyright 2017 Capital One Services, LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
