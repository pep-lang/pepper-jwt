## Tokens: `sign` and `verify` for JWTs (RFC 7519), and `sign_jws` and
## `verify_jws` for JWS compact serialization (RFC 7515) of any payload.

import json;
import text;
import "base64url";
import "key";
import "validation";

## Signs `claims` as a JWT: the header `{"alg":...,"typ":"JWT"}` and the
## claims as JSON, signed with `key`.
##
## @typeParam T the claims' type: a `json.JsonValue` object, or a struct
##   that `json.to_json` converts (`[Name]` and `[Ignore]` apply)
## @param claims the claims, such as `sub`, `exp` and the application's own
## @param key the key to sign with
## @returns the token, or an error when `key` only holds a public key
## @example
##     import json;
##     import jwt;
##
##     var key = jwt.Key.hs256("a secret of at least thirty-two bytes".bytes()).value();
##     var claims = json.JsonValue.object();
##     claims["sub"] = json.JsonValue.String("ada");
##     var token = jwt.sign(claims, key).value();
export sign<T>(claims: T, key: Key): Result<String> {
    var header = json.JsonValue.object();
    header["alg"] = json.JsonValue.String(key.algorithm());
    header["typ"] = json.JsonValue.String("JWT");
    return _sign(header, json.to_json(claims).to_string().bytes(), key);
}

## Checks a JWT's signature with `key`, then its claims with `validation`,
## and returns the claims.
##
## The header's `alg` must be `key`'s algorithm: `none` and every other
## algorithm are rejected, so a token cannot pick a weaker check or use a
## public key as an HMAC secret. A header with `crit` is rejected, as this
## package understands no extensions.
##
## @typeParam T the claims' type: `json.JsonValue`, or a struct that
##   `json.from_json` fills
## @param token the token, in compact form
## @param key the key to check with
## @param validation the claims checks; by default `exp` is required and
##   checked against the system clock
## @returns the claims, or an error saying why the token was rejected:
##   malformed, wrong algorithm, bad signature, a time or issuer or audience
##   check that failed, or claims that do not convert to `T`
## @example
##     import json;
##     import jwt;
##
##     var key = jwt.Key.hs256("a secret of at least thirty-two bytes".bytes()).value();
##     var claims = json.JsonValue.object();
##     claims["sub"] = json.JsonValue.String("ada");
##     claims["exp"] = json.JsonValue.Integer(2000000000);
##     var token = jwt.sign(claims, key).value();
##     var checked = jwt.verify<json.JsonValue>(token, key, jwt.Validation().at(1900000000));
##     assert(checked.value()["sub"].as_string().value() == "ada", "the claims");
export verify<T>(token: String, key: Key, validation: Validation = Validation()): Result<T> {
    var payload = verify_jws(token, key);
    if (payload.is_err()) {
        return Result<T>.err(payload.error());
    }
    var payload_text = text.Utf8.decode(payload.value());
    if (payload_text.is_empty()) {
        return Result<T>.err(Error("the token's claims are not UTF-8"));
    }
    var claims = json.parse(payload_text.value());
    if (claims.is_err()) {
        return Result<T>.err(Error($"the token's claims are not JSON: {claims.error().to_string()}"));
    }
    var checked = validation._check(claims.value());
    if (checked.is_err()) {
        return Result<T>.err(checked.error());
    }
    var typed = json.from_json<T>(claims.value());
    if (typed.is_err()) {
        return Result<T>.err(Error($"the token's claims do not convert: {typed.error().to_string()}"));
    }
    return Result<T>.ok(typed.value());
}

## Signs `payload` as a JWS in compact form, with the header
## `{"alg":...}` naming `key`'s algorithm.
##
## @param payload the bytes to sign, which need not be JSON
## @param key the key to sign with
## @returns the JWS, or an error when `key` only holds a public key
export sign_jws(payload: u8[], key: Key): Result<String> {
    var header = json.JsonValue.object();
    header["alg"] = json.JsonValue.String(key.algorithm());
    return _sign(header, payload, key);
}

## Checks a JWS in compact form with `key` and returns its payload. It
## makes the same header checks as `verify` but none of the claims.
##
## @param token the JWS, three base64url parts joined by `.`
## @param key the key to check with
## @returns the payload, or an error when the token is malformed, its
##   `alg` is not `key`'s, it has `crit`, or the signature is wrong
export verify_jws(token: String, key: Key): Result<u8[]> {
    var parts = token.split(".");
    if (parts.count != 3) {
        return Result<u8[]>.err(Error($"a token has 3 parts joined by '.', not {parts.count}"));
    }
    var header_bytes = _decode_base64url(parts[0], "token header");
    if (header_bytes.is_err()) {
        return Result<u8[]>.err(header_bytes.error());
    }
    var header = json.parse(text.Utf8.decode_lossy(header_bytes.value()));
    if (header.is_err() || header.value().as_object().is_empty()) {
        return Result<u8[]>.err(Error("the token's header is not a JSON object"));
    }
    var alg = header.value()["alg"].as_string();
    if (alg.is_empty()) {
        return Result<u8[]>.err(Error("the token's header has no 'alg'"));
    }
    if (alg.value() != key.algorithm()) {
        return Result<u8[]>.err(Error($"the token's algorithm '{alg.value()}' is not the key's '{key.algorithm()}'"));
    }
    if (!header.value()["crit"].is_null()) {
        return Result<u8[]>.err(Error("the token's header has 'crit', and no extension is supported"));
    }
    var payload = _decode_base64url(parts[1], "token payload");
    if (payload.is_err()) {
        return Result<u8[]>.err(payload.error());
    }
    var signature = _decode_base64url(parts[2], "token signature");
    if (signature.is_err()) {
        return Result<u8[]>.err(signature.error());
    }
    if (!key._verify($"{parts[0]}.{parts[1]}".bytes(), signature.value())) {
        return Result<u8[]>.err(Error("the token's signature is not valid"));
    }
    return payload;
}

# The compact JWS of `header` and `payload`, signed with `key`.
_sign(header: json.JsonValue, payload: u8[], key: Key): Result<String> {
    var input = $"{_encode_base64url(header.to_string().bytes())}.{_encode_base64url(payload)}";
    var signature = key._sign(input.bytes());
    if (signature.is_err()) {
        return Result<String>.err(signature.error());
    }
    return Result<String>.ok($"{input}.{_encode_base64url(signature.value())}");
}
