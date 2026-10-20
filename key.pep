## Keys: `Key` holds the secret or key pair a token is signed or checked
## with, and fixes the one algorithm it may be used for.

import crypto;
import digest;
import json;
import "base64url";

# The shortest HS256 secret RFC 7518 (section 3.2) allows: the hash's size.
const _HS256_MIN_SECRET: ulong = 32;

## A key for one algorithm: `HS256` (an HMAC-SHA-256 secret) or `EdDSA`
## (an Ed25519 key).
##
## A key only signs and checks tokens of its own algorithm, so a token
## cannot choose how it is checked: an HS256 token never verifies against
## an Ed25519 key, nor an EdDSA token against an HMAC secret.
##
## @example
##     import crypto;
##     import jwt;
##
##     main(): int {
##         var hmac = jwt.Key.hs256("a secret of at least thirty-two bytes".bytes()).value();
##         var ed = jwt.Key.ed25519(crypto.SigningKey.generate());
##         print(hmac.algorithm());   # HS256
##         print(ed.algorithm());   # EdDSA
##         return 0;
##     }
export struct Key {
    var _algorithm: String;
    # The HS256 secret; empty for an Ed25519 key.
    var _secret: u8[];
    var _signing: crypto.SigningKey?;
    var _verifying: crypto.VerifyingKey?;

    ## Makes an HS256 key from a shared secret, which both signs and
    ## checks.
    ##
    ## @param secret the secret, at least 32 bytes (RFC 7518 forbids a
    ##   shorter one); the key copies it
    ## @returns the key, or an error when `secret` is shorter than 32 bytes
    static hs256(secret: u8[]): Result<Key> {
        if (secret.count < _HS256_MIN_SECRET) {
            return Result<Key>.err(Error($"an HS256 secret is at least {_HS256_MIN_SECRET} bytes, not {secret.count}"));
        }
        var key = Key();
        key._algorithm = "HS256";
        key._secret = secret.copy();
        return Result<Key>.ok(key);
    }

    ## Makes an EdDSA key that signs with `key` and checks with its public
    ## half.
    ##
    ## @param key the Ed25519 secret key
    ## @returns the key
    static ed25519(key: crypto.SigningKey): Key {
        var made = Key();
        made._algorithm = "EdDSA";
        made._signing = Optional<crypto.SigningKey>.Value(key);
        made._verifying = Optional<crypto.VerifyingKey>.Value(key.verifying_key());
        return made;
    }

    ## Makes an EdDSA key that only checks tokens, from an Ed25519 public
    ## key; signing with it fails.
    ##
    ## @param key the Ed25519 public key
    ## @returns the key
    static ed25519_public(key: crypto.VerifyingKey): Key {
        var made = Key();
        made._algorithm = "EdDSA";
        made._verifying = Optional<crypto.VerifyingKey>.Value(key);
        return made;
    }

    ## Reads a key from a JSON Web Key (RFC 7517): an `oct` key (RFC 7518,
    ## section 6.4) for HS256, or an `OKP` key with `crv` `Ed25519`
    ## (RFC 8037), which signs when it holds the secret `d` and only checks
    ## when it holds just `x`.
    ##
    ## @param text the JWK, a JSON object
    ## @returns the key, or an error when the text is not a JWK, names
    ##   another key type, curve or `alg`, or its key bytes are invalid (an
    ##   Ed25519 `d` whose public key is not `x`, too short a secret)
    ## @example
    ##     import jwt;
    ##
    ##     var key = jwt.Key.from_jwk("{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}").value();
    ##     assert(key.algorithm() == "EdDSA", "an Ed25519 public key");
    static from_jwk(text: String): Result<Key> {
        var parsed = json.parse(text);
        if (parsed.is_err()) {
            return Result<Key>.err(Error($"invalid JWK: {parsed.error().to_string()}"));
        }
        var jwk = parsed.value();
        var kty = jwk["kty"].as_string().value_or("");
        var alg = jwk["alg"].as_string();
        if (kty == "oct") {
            if (alg.is_value() && alg.value() != "HS256") {
                return Result<Key>.err(Error($"unsupported JWK 'alg' '{alg.value()}': only HS256 for an 'oct' key"));
            }
            var k = _jwk_bytes(jwk, "k");
            if (k.is_err()) {
                return Result<Key>.err(k.error());
            }
            return Key.hs256(k.value());
        }
        if (kty == "OKP") {
            var crv = jwk["crv"].as_string().value_or("");
            if (crv != "Ed25519") {
                return Result<Key>.err(Error($"unsupported JWK curve '{crv}': only Ed25519"));
            }
            if (alg.is_value() && alg.value() != "EdDSA") {
                return Result<Key>.err(Error($"unsupported JWK 'alg' '{alg.value()}': only EdDSA for an Ed25519 key"));
            }
            var x = _jwk_bytes(jwk, "x");
            if (x.is_err()) {
                return Result<Key>.err(x.error());
            }
            var public_key = crypto.VerifyingKey.from_bytes(x.value());
            if (public_key.is_err()) {
                return Result<Key>.err(public_key.error());
            }
            if (jwk["d"].is_null()) {
                return Result<Key>.ok(Key.ed25519_public(public_key.value()));
            }
            var d = _jwk_bytes(jwk, "d");
            if (d.is_err()) {
                return Result<Key>.err(d.error());
            }
            var signing = crypto.SigningKey.from_seed(d.value());
            if (signing.is_err()) {
                return Result<Key>.err(signing.error());
            }
            if (!digest.equal_constant_time(signing.value().verifying_key().bytes(), x.value())) {
                return Result<Key>.err(Error("invalid JWK: 'x' is not the public key of 'd'"));
            }
            return Result<Key>.ok(Key.ed25519(signing.value()));
        }
        return Result<Key>.err(Error($"unsupported JWK key type '{kty}': only 'oct' and 'OKP'"));
    }

    ## Returns the algorithm the key signs and checks, as a token header
    ## names it.
    ##
    ## @returns `"HS256"` or `"EdDSA"`
    algorithm(): String {
        return _algorithm;
    }

    # The signature of `input`, or an error for a key that only checks.
    _sign(input: u8[]): Result<u8[]> {
        if (_algorithm == "HS256") {
            return Result<u8[]>.ok(digest.hmac_sha256(_secret, input));
        }
        if (_signing.is_empty()) {
            return Result<u8[]>.err(Error("this EdDSA key holds only a public key, which cannot sign"));
        }
        return Result<u8[]>.ok(_signing.value().sign(input));
    }

    # Whether `signature` is this key's signature of `input`; HS256 compares
    # in constant time.
    _verify(input: u8[], signature: u8[]): bool {
        if (_algorithm == "HS256") {
            return digest.equal_constant_time(digest.hmac_sha256(_secret, input), signature);
        }
        return _verifying.value().verify(input, signature);
    }
}

# The bytes of the JWK's base64url member `name`.
_jwk_bytes(jwk: json.JsonValue, name: String): Result<u8[]> {
    var value = jwk[name].as_string();
    if (value.is_empty()) {
        return Result<u8[]>.err(Error($"invalid JWK: no string member '{name}'"));
    }
    return _decode_base64url(value.value(), $"JWK member '{name}'");
}
