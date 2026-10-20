## Claims validation: `Validation` says what `verify` checks in a token's
## claims beyond its signature (RFC 7519, section 4.1).

import json;
import os;

## What `verify` checks in a verified token's claims: the times `exp`,
## `nbf` and `iat`, and, when asked, the issuer `iss` and audience `aud`.
##
## By default a token must carry `exp` and be inside its times, with no
## leeway, against the system clock. A claim set to `null` counts as
## absent. Set options by chaining.
##
## @example
##     import jwt;
##
##     var checks = jwt.Validation().leeway(30).issuer("https://auth.example.com").audience("api");
export struct Validation {
    var _leeway: long;
    var _issuer: String?;
    var _audience: String?;
    var _require_expiration: bool;
    var _now: long?;

    ## Makes the default checks: `exp` required, no leeway, any issuer and
    ## audience, against the system clock.
    construct() {
        _require_expiration = true;
    }

    ## Sets how many seconds of clock difference between the issuer and
    ## this machine to allow on `exp`, `nbf` and `iat`.
    ##
    ## @param seconds the leeway, 0 by default
    ## @returns this `Validation`, for chaining
    leeway(seconds: long): Validation {
        _leeway = seconds;
        return this;
    }

    ## Requires the `iss` claim to be `issuer`.
    ##
    ## @param issuer the issuer the token must name
    ## @returns this `Validation`, for chaining
    issuer(issuer: String): Validation {
        _issuer = Optional<String>.Value(issuer);
        return this;
    }

    ## Requires the `aud` claim to be `audience`, or an array holding it.
    ##
    ## @param audience the audience the token must name
    ## @returns this `Validation`, for chaining
    audience(audience: String): Validation {
        _audience = Optional<String>.Value(audience);
        return this;
    }

    ## Sets whether a token without `exp` is rejected.
    ##
    ## @param required false to accept a token that never expires; true by
    ##   default
    ## @returns this `Validation`, for chaining
    require_expiration(required: bool): Validation {
        _require_expiration = required;
        return this;
    }

    ## Checks the times against `unix_seconds` instead of the system clock,
    ## as tests and replays of old tokens need.
    ##
    ## @param unix_seconds the time, in seconds since 1970-01-01T00:00:00Z
    ## @returns this `Validation`, for chaining
    at(unix_seconds: long): Validation {
        _now = Optional<long>.Value(unix_seconds);
        return this;
    }

    # Checks `claims` as configured.
    _check(claims: json.JsonValue): Result<void> {
        if (claims.as_object().is_empty()) {
            return Result<void>.err(Error("the token's claims are not a JSON object"));
        }
        var now = _now.is_value() ? _now.value() : os.SystemTime.now().unix_seconds();
        var exp = _time_claim(claims, "exp");
        if (exp.is_err()) {
            return Result<void>.err(exp.error());
        }
        if (exp.value().is_empty()) {
            if (_require_expiration) {
                return Result<void>.err(Error("the token has no 'exp' claim"));
            }
        } else if ((now - _leeway) as double >= exp.value().value()) {
            return Result<void>.err(Error("the token has expired ('exp')"));
        }
        var nbf = _time_claim(claims, "nbf");
        if (nbf.is_err()) {
            return Result<void>.err(nbf.error());
        }
        if (nbf.value().is_value() && ((now + _leeway) as double) < nbf.value().value()) {
            return Result<void>.err(Error("the token is not valid yet ('nbf')"));
        }
        var iat = _time_claim(claims, "iat");
        if (iat.is_err()) {
            return Result<void>.err(iat.error());
        }
        if (iat.value().is_value() && iat.value().value() > ((now + _leeway) as double)) {
            return Result<void>.err(Error("the token was issued in the future ('iat')"));
        }
        var iss = claims["iss"].as_string();
        if (_issuer.is_value() && (iss.is_empty() || iss.value() != _issuer.value())) {
            return Result<void>.err(Error($"the token's issuer is not '{_issuer.value()}' ('iss')"));
        }
        if (_audience.is_value() && !_has_audience(claims["aud"], _audience.value())) {
            return Result<void>.err(Error($"the token's audience does not include '{_audience.value()}' ('aud')"));
        }
        return Result<void>.ok();
    }
}

# The NumericDate claim `name`, none when absent or null, or an error when
# it is not a number.
_time_claim(claims: json.JsonValue, name: String): Result<double?> {
    var value = claims[name];
    if (value.is_null()) {
        return Result<double?>.ok(Optional<double>.Empty);
    }
    var number = value.as_double();
    if (number.is_empty()) {
        return Result<double?>.err(Error($"the token's '{name}' claim is not a number"));
    }
    return Result<double?>.ok(number);
}

# Whether `aud`, a string or an array of strings (RFC 7519, section 4.1.3),
# names `audience`.
_has_audience(aud: json.JsonValue, audience: String): bool {
    var single = aud.as_string();
    if (single.is_value()) {
        return single.value() == audience;
    }
    var items = aud.as_array();
    if (items.is_value()) {
        for (var item in items.value()) {
            var name = item.as_string();
            if (name.is_value() && name.value() == audience) {
                return true;
            }
        }
    }
    return false;
}
