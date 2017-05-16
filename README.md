# JWT Security

JSON Web Tokens (JWT)-based security middleware for
[Express.js](https://expressjs.com/)

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
