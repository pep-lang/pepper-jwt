# Claims as a struct, through json's struct conversion.

import json;
import jwt;

struct Session {
    var sub: String;
    var exp: long;
    [Name("is_admin")]
    var admin: bool;
}

[Test]
claims_round_trip_as_a_struct() {
    var key = jwt.Key.hs256("0123456789abcdef0123456789abcdef".bytes()).value();
    var session = Session();
    session.sub = "ada";
    session.exp = 4000000000;
    session.admin = true;
    var token = jwt.sign(session, key).value();
    var checked = jwt.verify<Session>(token, key, jwt.Validation().at(1000000000)).value();
    expect_equal(checked.sub, "ada");
    expect_equal(checked.exp, 4000000000);
    expect_true(checked.admin);
    var raw = jwt.verify<json.JsonValue>(token, key, jwt.Validation().at(1000000000)).value();
    expect_true(raw["is_admin"].as_bool().value());
}

[Test]
claims_that_do_not_convert_are_rejected() {
    var key = jwt.Key.hs256("0123456789abcdef0123456789abcdef".bytes()).value();
    var token = jwt.sign(json.parse("{\"sub\":7,\"exp\":4000000000}").value(), key).value();
    var result = jwt.verify<Session>(token, key, jwt.Validation().at(1000000000));
    expect_true(result.error().message.contains("do not convert"));
}
