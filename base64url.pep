## Base64url without padding (RFC 7515, section 2), the encoding of every
## part of a token and of a JWK's key bytes.

import base64;

# `bytes` as base64url text without padding.
_encode_base64url(bytes: u8[]): String {
    return base64.encode(bytes, true, false);
}

# The bytes base64url `text` stands for. Padding is an error, as RFC 7515
# leaves it out, so each token has one spelling; `what` names the text in
# the error.
_decode_base64url(text: String, what: String): Result<u8[]> {
    if (text.contains("=")) {
        return Result<u8[]>.err(Error($"invalid {what}: base64url padding '='"));
    }
    var bytes = base64.decode(text, true);
    if (bytes.is_err()) {
        return Result<u8[]>.err(Error($"invalid {what}: {bytes.error().message}"));
    }
    return bytes;
}
