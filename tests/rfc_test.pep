# The examples of RFC 7515 (appendix A.1, HS256) and RFC 8037 (appendix
# A, Ed25519).

import crypto;
import digest;
import json;
import jwt;
import text;

# RFC 7515, appendix A.1: the HMAC key, as a JWK, and the token it signs.
const RFC7515_JWK = "{\"kty\":\"oct\",\"k\":\"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow\"}";
const RFC7515_TOKEN = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

# RFC 8037, appendix A.1 and A.2: the Ed25519 key, as JWKs.
const RFC8037_PRIVATE_JWK = "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"d\":\"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}";
const RFC8037_PUBLIC_JWK = "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}";
# RFC 8037, appendix A.4: the JWS of "Example of Ed25519 signing".
const RFC8037_JWS = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg";

[Test]
rfc7515_hs256_example_verifies() {
    var key = jwt.Key.from_jwk(RFC7515_JWK).value();
    expect_equal(key.algorithm(), "HS256");
    # The example's exp is 2011-03-22T18:43:00Z.
    var claims = jwt.verify<json.JsonValue>(RFC7515_TOKEN, key, jwt.Validation().at(1300819379).issuer("joe")).value();
    expect_equal(claims["iss"].as_string().value(), "joe");
    expect_true(claims["http://example.com/is_root"].as_bool().value());
}

[Test]
rfc7515_hs256_example_expires() {
    var key = jwt.Key.from_jwk(RFC7515_JWK).value();
    var late = jwt.verify<json.JsonValue>(RFC7515_TOKEN, key, jwt.Validation().at(1300819380));
    expect_true(late.error().message.contains("expired"));
    expect_true(jwt.verify<json.JsonValue>(RFC7515_TOKEN, key).is_err());
}

[Test]
rfc8037_ed25519_example_signs_and_verifies() {
    var key = jwt.Key.from_jwk(RFC8037_PRIVATE_JWK).value();
    expect_equal(key.algorithm(), "EdDSA");
    expect_equal(jwt.sign_jws("Example of Ed25519 signing".bytes(), key).value(), RFC8037_JWS);
    var public_key = jwt.Key.from_jwk(RFC8037_PUBLIC_JWK).value();
    var payload = jwt.verify_jws(RFC8037_JWS, public_key).value();
    expect_equal(text.Utf8.decode(payload).value(), "Example of Ed25519 signing");
}

[Test]
rfc8037_key_is_the_rfc8032_test_1_key() {
    var key = jwt.Key.from_jwk(RFC8037_PRIVATE_JWK).value();
    var payload = "x".bytes();
    var token = jwt.sign_jws(payload, key).value();
    var signature = token.split(".")[2];
    # Ed25519 is deterministic, so the RFC 8032 key gives the same signature.
    var seed = digest.from_hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60").value();
    var again = jwt.sign_jws(payload, jwt.Key.ed25519(crypto.SigningKey.from_seed(seed).value())).value();
    expect_equal(again.split(".")[2], signature);
}
