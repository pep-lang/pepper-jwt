# pepper-jwt

JSON Web Tokens for [Pepper](https://github.com/pep-lang/pepper): sign and
verify JWTs (RFC 7519) and JWS compact tokens (RFC 7515) with HS256 or
EdDSA (Ed25519, RFC 8037), and validate their claims. HMAC-SHA-256 is the
runtime's `digest`, and Ed25519 is
[pepper-crypto](https://github.com/pep-lang/pepper-crypto)'s, on
libsodium; this package writes no cryptography of its own.

One module, **`jwt`**:

- **`Key`**: a key for exactly one algorithm. **`Key.hs256(secret)`**
  (at least 32 bytes), **`Key.ed25519(signing_key)`**,
  **`Key.ed25519_public(verifying_key)`** (checks only), and
  **`Key.from_jwk(text)`** for an `oct` or Ed25519 `OKP` JSON Web Key.
- **`sign(claims, key)`** and **`verify<T>(token, key, validation)`**:
  JWTs, with the claims as a `json.JsonValue` or a struct that `json`
  converts (`[Name]` and `[Ignore]` apply).
- **`Validation`**: what `verify` checks beyond the signature.
  **`leeway(seconds)`**, **`issuer(iss)`**, **`audience(aud)`**,
  **`require_expiration(bool)`** and **`at(unix_seconds)`**, chained.
- **`sign_jws(payload, key)`** and **`verify_jws(token, key)`**: JWS of
  any payload, with no claims checks.

```pepper
import crypto;
import json;
import jwt;

struct Session {
    var sub: String;
    var exp: long;
}

main(): int {
    var key = jwt.Key.ed25519(crypto.SigningKey.generate());

    var session = Session();
    session.sub = "ada";
    session.exp = 4000000000;
    var token = jwt.sign(session, key).value();

    var checks = jwt.Validation().leeway(30);
    var checked = jwt.verify<Session>(token, key, checks);
    if (checked.is_err()) {
        print($"rejected: {checked.error().message}");
        return 1;
    }
    print(checked.value().sub);   # ada
    return 0;
}
```

## What verify checks

- The header's `alg` must be the key's algorithm. A key has one, so `none`
  is always rejected, and an HS256 token never verifies against an
  Ed25519 public key (nor an EdDSA token against an HMAC secret): the
  token cannot choose how it is checked.
- A header with `crit` is rejected, since no extension is supported.
- The three parts must be unpadded base64url, and the HMAC is compared in
  constant time.
- `exp` is required unless `require_expiration(false)`, and the token is
  rejected from `exp` on; it is rejected before `nbf`, and when `iat` is in
  the future. `leeway` widens each by that many seconds. A claim that is
  `null` counts as absent; one that is not a number is an error.
- `iss` and `aud` are checked only when `issuer` or `audience` asks;
  `aud` may be a string or an array of strings.

A rejection is an `Err` whose message says which check failed.

## Limits

- HS256 and EdDSA only. HS384 and HS512 wait for SHA-384 and SHA-512 in
  the runtime's `digest`; RS256 and ES256 wait for RSA and ECDSA in
  pepper-crypto.
- Keys come from bytes, crypto keys or JWKs; there is no PEM reading.
- No JWE (encrypted tokens) and no JWK sets.
- Errors are messages, not a code to match on.

## Using it

This repository is a package: `pep.toml` marks its root, and its root
`module.pep` is the `jwt` module. Add it to a project under the name
`jwt`:

```sh
pepper package add pep-lang/pepper-jwt --name jwt
```

which writes

```toml
[dependencies]
jwt = { github = "pep-lang/pepper-jwt" }
```

and fetches pepper-crypto with it. The program then links libsodium,
1.0.18 or later; see
[Installing libsodium](https://github.com/pep-lang/pepper-crypto#installing-libsodium).

## Tests

```sh
tests/run.sh path/to/pepper
```

runs the `[Test]` functions in `tests/` with `pepper test`: the examples
of RFC 7515 (appendix A.1, HS256) and RFC 8037 (appendix A, Ed25519) in
`rfc_test.pep`, each way a token is rejected in `reject_test.pep`, and
struct claims in `typed_test.pep`. On Windows, set `PEPPER_LIBRARY_PATH`
to libsodium's folder first.

## Releasing

CI (`.github/workflows/ci.yml`) runs the tests on Linux, macOS and
Windows for every push to `main` and every pull request. To release, set
`version` in `pep.toml`, merge, then push the matching tag
(`git tag v1.0.0 && git push origin v1.0.0`): CI tests the tag and
publishes a GitHub release for it. `pepper package add` and `pepper
package update` find versions by their tags.

## License

Apache-2.0; see [LICENSE](LICENSE).
