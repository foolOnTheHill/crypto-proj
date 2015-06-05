"use strict";

function assert(condition, message) {
  if (!condition) {
    console.trace();
    throw message || "Assertion failed!";
  }
}

var lib = require("./lib/lib");
var password_manager = require("./password-manager");

var password = "auJKAjkxnasklNcauaLK";
var keychain = password_manager.keychain();

console.log("Initializing a toy password store");
keychain.init(password);

// Random data
var kvs = {};

var d, p;
for (var i = 0; i < 10000; i++) {
	d = lib.bitarray_to_string(unescape(encodeURIComponent(lib.random_bitarray(32))));
	p = lib.bitarray_to_string(unescape(encodeURIComponent(lib.random_bitarray(32))));

	kvs[d] = p;
}

console.log("\n------ Testing");

console.log("Adding keys to password manager");
for (var k in kvs) {
  keychain.set(k, kvs[k]);
}

console.log("Testing 'get'");
for (var k in kvs) {
  assert(keychain.get(k) === kvs[k], "Get failed for key " + k);
}

console.log("Testing 'remove'");
for (var k in kvs) {
	assert(keychain.remove(k));
	assert(!keychain.remove(k));
	assert(!keychain.get(k));
}

console.log("Saving database");
var data = keychain.dump();

var contents = data[0];
var cksum = data[1];

console.log("Loading database");
var new_keychain = password_manager.keychain();
new_keychain.load(password, contents, cksum);

console.log("Checking contents of new database");
for (var k in kvs) {
  assert(keychain.get(k) === new_keychain.get(k));
}

console.log("Testing for authentication tampering:")

console.log("1) Wrong password");
new_keychain = password_manager.keychain();
assert(!new_keychain.load("adqAUdqn", contents, cksum));

console.log("2) Invalid signature")
var contentsObj = JSON.parse(contents);
contentsObj["signature"][0] = 0;

var tampContent = JSON.stringify(contentsObj);
new_keychain = password_manager.keychain();
assert(!new_keychain.load(password, tampContent, cksum));

console.log("3) Wrong hash");
var tampHash = lib.SHA256(tampContent);
new_keychain = password_manager.keychain();

var r;
try {
	new_keychain.load(password, contents, tampHash);
	r = false;
} catch(e) {
	r = true;
}
assert(r);

console.log("4) Wrong salt")
contentsObj = JSON.parse(contents);
contentsObj["salt"][2] = 0;

tampContent = JSON.stringify(contentsObj);
new_keychain = password_manager.keychain();
assert(!new_keychain.load(password, tampContent, cksum));

/* TODO:
 * 1) Swap Attack
 * 2) Rollback Attack
 */

console.log("All tests passed!");