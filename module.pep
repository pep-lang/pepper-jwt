## JSON Web Tokens (RFC 7519): sign and verify JWS compact tokens
## (RFC 7515) with HS256 or EdDSA (Ed25519, RFC 8037), and validate their
## claims.
##
## Bring it in with `import jwt`. Ed25519 comes from the
## [crypto](https://github.com/pep-lang/pepper-crypto) package, so the
## program links libsodium; HMAC-SHA-256 comes from the runtime's `digest`.
##
## - `Key`: a key for one algorithm, from a secret, a crypto key or a JWK
## - `sign`, `verify`: JWTs, with claims as `json.JsonValue` or a struct
## - `Validation`: the `exp`, `nbf`, `iat`, `iss` and `aud` checks
## - `sign_jws`, `verify_jws`: JWS of any payload
##
## @example
##     import json;
##     import jwt;
##
##     main(): int {
##         var key = jwt.Key.hs256("a secret of at least thirty-two bytes".bytes()).value();
##         var claims = json.JsonValue.object();
##         claims["sub"] = json.JsonValue.String("ada");
##         claims["exp"] = json.JsonValue.Integer(4000000000);
##         var token = jwt.sign(claims, key).value();
##         var checked = jwt.verify<json.JsonValue>(token, key);
##         print(checked.value()["sub"].as_string().value());   # ada
##         return 0;
##     }

import "key";
import "token";
import "validation";

export Key;
export sign;
export verify;
export sign_jws;
export verify_jws;
export Validation;
