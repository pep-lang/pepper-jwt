# Each way verify rejects a token: the algorithm, the form, the signature,
# and each claim check.

import base64;
import crypto;
import json;
import jwt;

# A token with the given header and payload JSON, and signature text.
_forge(header: String, payload: String, signature: String): String {
    var h = base64.encode(header.bytes(), true, false);
    var p = base64.encode(payload.bytes(), true, false);
    return $"{h}.{p}.{signature}";
}

_hmac_key(): jwt.Key {
    return jwt.Key.hs256("0123456789abcdef0123456789abcdef".bytes()).value();
}

# Claims with `exp` far in the future and the members of `extra`, a JSON
# object's inside.
_claims(extra: String): json.JsonValue {
    var members = extra == "" ? "" : $",{extra}";
    return json.parse($"{{\"exp\":4000000000{members}}}").value();
}

# The message verify rejects `token` with, against `key` and `validation`.
_rejection(token: String, key: jwt.Key, validation: jwt.Validation): String {
    var result = jwt.verify<json.JsonValue>(token, key, validation);
    expect_true(result.is_err());
    return result.is_err() ? result.error().message : "";
}

# The message verify rejects `claims`, signed with the HMAC key, with,
# checked at 1000000000 by `validation`.
_claims_rejection(claims: String, validation: jwt.Validation): String {
    var key = _hmac_key();
    var token = jwt.sign(json.parse(claims).value(), key).value();
    return _rejection(token, key, validation.at(1000000000));
}

_accepts(claims: String, validation: jwt.Validation): bool {
    var key = _hmac_key();
    var token = jwt.sign(json.parse(claims).value(), key).value();
    return jwt.verify<json.JsonValue>(token, key, validation.at(1000000000)).is_ok();
}

[Test]
alg_none_is_rejected() {
    var token = _forge("{\"alg\":\"none\"}", "{\"exp\":4000000000}", "");
    expect_true(_rejection(token, _hmac_key(), jwt.Validation()).contains("'none' is not the key's 'HS256'"));
    var ed = jwt.Key.ed25519(crypto.SigningKey.generate());
    expect_true(_rejection(token, ed, jwt.Validation()).contains("'none'"));
}

[Test]
an_hmac_token_does_not_verify_with_a_public_key() {
    # The classic confusion: an HS256 token whose secret is the public key.
    var signer = crypto.SigningKey.generate();
    var public_bytes = signer.verifying_key().bytes();
    var forged = jwt.sign(_claims(""), jwt.Key.hs256(public_bytes).value()).value();
    var public_key = jwt.Key.ed25519_public(signer.verifying_key());
    expect_true(_rejection(forged, public_key, jwt.Validation()).contains("'HS256' is not the key's 'EdDSA'"));
}

[Test]
an_eddsa_token_does_not_verify_with_an_hmac_key() {
    var token = jwt.sign(_claims(""), jwt.Key.ed25519(crypto.SigningKey.generate())).value();
    expect_true(_rejection(token, _hmac_key(), jwt.Validation()).contains("'EdDSA' is not the key's 'HS256'"));
}

[Test]
a_changed_token_is_rejected() {
    var key = _hmac_key();
    var token = jwt.sign(_claims("\"sub\":\"ada\""), key).value();
    var parts = token.split(".");
    var other_payload = base64.encode(_claims("\"sub\":\"eve\"").to_string().bytes(), true, false);
    var swapped = $"{parts[0]}.{other_payload}.{parts[2]}";
    expect_true(_rejection(swapped, key, jwt.Validation()).contains("signature is not valid"));
    var signature = base64.decode(parts[2], true).value();
    signature[0] = signature[0] ^ 1;
    var flipped = $"{parts[0]}.{parts[1]}.{base64.encode(signature, true, false)}";
    expect_true(_rejection(flipped, key, jwt.Validation()).contains("signature is not valid"));
    var other_key = jwt.Key.hs256("another secret, also 32 bytes long".bytes()).value();
    expect_true(_rejection(token, other_key, jwt.Validation()).contains("signature is not valid"));
}

[Test]
a_changed_eddsa_token_is_rejected() {
    var signer = crypto.SigningKey.generate();
    var key = jwt.Key.ed25519(signer);
    var token = jwt.sign(_claims(""), key).value();
    var other = jwt.Key.ed25519_public(crypto.SigningKey.generate().verifying_key());
    expect_true(_rejection(token, other, jwt.Validation()).contains("signature is not valid"));
    expect_true(jwt.verify<json.JsonValue>(token, jwt.Key.ed25519_public(signer.verifying_key())).is_ok());
}

[Test]
a_malformed_token_is_rejected() {
    var key = _hmac_key();
    var good = jwt.sign(_claims(""), key).value();
    var v = jwt.Validation();
    expect_true(_rejection("abc.def", key, v).contains("3 parts"));
    expect_true(_rejection($"{good}.x", key, v).contains("3 parts"));
    expect_true(_rejection($"{good}=", key, v).contains("padding"));
    expect_true(_rejection($"{good.replace("-", "+")}+", key, v).contains("invalid"));
    expect_true(_rejection(_forge("[1]", "{}", "x"), key, v).contains("not a JSON object"));
    expect_true(_rejection(_forge("not json", "{}", "x"), key, v).contains("not a JSON object"));
    expect_true(_rejection(_forge("{\"typ\":\"JWT\"}", "{}", "x"), key, v).contains("no 'alg'"));
    var crit = _forge("{\"alg\":\"HS256\",\"crit\":[\"b64\"],\"b64\":false}", "{}", "x");
    expect_true(_rejection(crit, key, v).contains("'crit'"));
}

[Test]
claims_that_are_not_an_object_are_rejected() {
    var key = _hmac_key();
    var token = jwt.sign_jws("[1, 2]".bytes(), key).value();
    expect_true(_rejection(token, key, jwt.Validation()).contains("not a JSON object"));
    var not_json = jwt.sign_jws("hello".bytes(), key).value();
    expect_true(_rejection(not_json, key, jwt.Validation()).contains("not JSON"));
}

[Test]
exp_is_checked_with_leeway() {
    # Checked at 1000000000.
    var v = jwt.Validation();
    expect_true(_claims_rejection("{\"exp\":1000000000}", v).contains("expired"));
    expect_true(_claims_rejection("{\"exp\":999999999.5}", jwt.Validation()).contains("expired"));
    expect_true(_accepts("{\"exp\":1000000001}", jwt.Validation()));
    expect_true(_accepts("{\"exp\":999999990}", jwt.Validation().leeway(11)));
    expect_true(_claims_rejection("{\"exp\":999999990}", jwt.Validation().leeway(10)).contains("expired"));
    expect_true(_claims_rejection("{\"exp\":\"tomorrow\"}", jwt.Validation()).contains("'exp' claim is not a number"));
}

[Test]
exp_is_required_unless_turned_off() {
    expect_true(_claims_rejection("{\"sub\":\"ada\"}", jwt.Validation()).contains("no 'exp'"));
    expect_true(_claims_rejection("{\"exp\":null}", jwt.Validation()).contains("no 'exp'"));
    expect_true(_accepts("{\"sub\":\"ada\"}", jwt.Validation().require_expiration(false)));
}

[Test]
nbf_is_checked_with_leeway() {
    var exp = "\"exp\":4000000000";
    expect_true(_claims_rejection($"{{{exp},\"nbf\":1000000001}}", jwt.Validation()).contains("not valid yet"));
    expect_true(_accepts($"{{{exp},\"nbf\":1000000000}}", jwt.Validation()));
    expect_true(_accepts($"{{{exp},\"nbf\":1000000030}}", jwt.Validation().leeway(30)));
    expect_true(_claims_rejection($"{{{exp},\"nbf\":true}}", jwt.Validation()).contains("'nbf' claim is not a number"));
}

[Test]
iat_in_the_future_is_rejected() {
    var exp = "\"exp\":4000000000";
    expect_true(_claims_rejection($"{{{exp},\"iat\":1000000060}}", jwt.Validation()).contains("issued in the future"));
    expect_true(_accepts($"{{{exp},\"iat\":999999000}}", jwt.Validation()));
    expect_true(_accepts($"{{{exp},\"iat\":1000000060}}", jwt.Validation().leeway(60)));
    expect_true(_claims_rejection($"{{{exp},\"iat\":[]}}", jwt.Validation()).contains("'iat' claim is not a number"));
}

[Test]
iss_is_checked_when_asked() {
    var exp = "\"exp\":4000000000";
    var v = jwt.Validation().issuer("https://auth.example.com");
    expect_true(_accepts($"{{{exp},\"iss\":\"https://auth.example.com\"}}", v));
    expect_true(_claims_rejection($"{{{exp},\"iss\":\"https://evil.example.com\"}}", v).contains("issuer"));
    expect_true(_claims_rejection($"{{{exp}}}", jwt.Validation().issuer("")).contains("issuer"));
    expect_true(_accepts($"{{{exp},\"iss\":\"anyone\"}}", jwt.Validation()));
}

[Test]
aud_is_checked_when_asked() {
    var exp = "\"exp\":4000000000";
    var v = jwt.Validation().audience("api");
    expect_true(_accepts($"{{{exp},\"aud\":\"api\"}}", v));
    expect_true(_accepts($"{{{exp},\"aud\":[\"web\",\"api\"]}}", jwt.Validation().audience("api")));
    expect_true(_claims_rejection($"{{{exp},\"aud\":\"web\"}}", jwt.Validation().audience("api")).contains("audience"));
    expect_true(
        _claims_rejection($"{{{exp},\"aud\":[\"web\"]}}", jwt.Validation().audience("api")).contains("audience")
    );
    expect_true(_claims_rejection($"{{{exp}}}", jwt.Validation().audience("")).contains("audience"));
    expect_true(_accepts($"{{{exp},\"aud\":\"web\"}}", jwt.Validation()));
}

[Test]
a_public_key_cannot_sign() {
    var key = jwt.Key.ed25519_public(crypto.SigningKey.generate().verifying_key());
    expect_true(jwt.sign(_claims(""), key).error().message.contains("cannot sign"));
}

[Test]
a_short_hmac_secret_is_rejected() {
    expect_true(jwt.Key.hs256("too short".bytes()).error().message.contains("at least 32 bytes"));
}

[Test]
an_unsupported_jwk_is_rejected() {
    expect_true(jwt.Key.from_jwk("{\"kty\":\"RSA\",\"n\":\"AQAB\",\"e\":\"AQAB\"}").error().message.contains("'RSA'"));
    var x25519 = "{\"kty\":\"OKP\",\"crv\":\"X25519\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}";
    expect_true(jwt.Key.from_jwk(x25519).error().message.contains("'X25519'"));
    var hs512 = "{\"kty\":\"oct\",\"alg\":\"HS512\",\"k\":\"MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY\"}";
    expect_true(jwt.Key.from_jwk(hs512).error().message.contains("'HS512'"));
    expect_true(jwt.Key.from_jwk("{\"kty\":\"oct\"}").error().message.contains("'k'"));
    expect_true(jwt.Key.from_jwk("{").is_err());
    # d is RFC 8037's, x another key's.
    var mismatched = "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"d\":\"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A\",\"x\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}";
    expect_true(jwt.Key.from_jwk(mismatched).error().message.contains("not the public key"));
}

[Test]
a_blank_key_rejects_rather_than_crashes() {
    var blank = jwt.Key();
    var token = _forge("{\"alg\":\"\"}", "{\"exp\":4000000000}", "");
    expect_true(_rejection(token, blank, jwt.Validation()).contains("signature is not valid"));
    expect_true(jwt.sign(_claims(""), blank).error().message.contains("no algorithm"));
}
