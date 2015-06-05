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
var toDump = password_manager.keychain();

console.log("Initializing a toy password store");
keychain.init(password);
toDump.init(password);

// Random data
var kvs = {};

var d, p;
for (var i = 0; i < 1000; i++) {
	d = lib.bitarray_to_string(unescape(encodeURIComponent(lib.random_bitarray(32))));
	p = lib.bitarray_to_string(unescape(encodeURIComponent(lib.random_bitarray(32))));

	kvs[d] = p;
}

console.log("\nTesting get, set and remove...");
for (var k in kvs) {
	keychain.set(k, kvs[k]);
	assert(keychain.get(k) === kvs[k], "Get failed for key " + k);
	if (Math.random() > 0.50) {
		assert(keychain.remove(k));
		assert(!keychain.remove(k));
		assert(!keychain.get(k));
	}

	toDump.set(k, kvs[k]);
}
console.log("Passed!");

console.log("\nTesting dump and load...");
var new_keychain = password_manager.keychain();
var new_new_keychain = password_manager.keychain();

console.log("Saving database...");
var data = keychain.dump();
var contents = data[0];
var cksum = data[1];

var data2 = toDump.dump();
var contents2 = data2[0];
var cksum2 = data2[1];

console.log("Loading database...");
new_keychain.load(password, contents, cksum);
new_new_keychain.load(password, contents2, cksum2);

console.log("Checking contents of new database...");
for (var k in kvs) {
  assert(keychain.get(k) === new_keychain.get(k));
  assert(toDump.get(k) === new_new_keychain.get(k));
}
console.log('Passed!');

console.log("\nTesting for authentication tampering:")

console.log("1) Wrong password");
new_keychain = password_manager.keychain();
assert(!new_keychain.load("adqAUdqn", contents, cksum));

console.log("2) Invalid signature")
var contentsObj = JSON.parse(contents);
contentsObj["signature"] = lib.random_bitarray(128);

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
contentsObj["salt"] = lib.random_bitarray(64);

tampContent = JSON.stringify(contentsObj);
new_keychain = password_manager.keychain();
assert(!new_keychain.load(password, tampContent, cksum));

console.log("5) Modifying the content");
contentsObj = JSON.parse(contents);

var q = parseInt(Math.random()*10);
for (k in contentsObj) {
	contentsObj[k] = lib.bitarray_slice(lib.random_bitarray(96), 65);
}

tampContent = JSON.stringify(contentsObj);
new_keychain = password_manager.keychain();
assert(!new_keychain.load(password, tampContent, cksum));

console.log("Passed!");

// Swap Attacks
console.log("\nTesting for Swap Attacks...")

data = toDump.dump();
contents = data[0];
cksum = data[1];

var map = JSON.parse(contents);
var keys = [];

for (k in map) {
	if (k !== "signature" && k !== "salt") {
		keys.push(k);
	}
}

var toSwap = { };

toSwap[keys[4]] = map[keys[11]];
toSwap[keys[11]] = map[keys[4]];
toSwap[keys[5]] = map[keys[50]];
toSwap[keys[50]] = map[keys[5]];
toSwap[keys[13]] = map[keys[9]];
toSwap[keys[9]] = map[keys[13]];

for (k in toSwap) {
	map[k] = toSwap[k];
}

data = JSON.stringify(map);
new_keychain = password_manager.keychain();
assert(new_keychain.load(password, data));

var count = 0, p;
for (k in kvs) {
	try {
		p = new_keychain.get(k);
	} catch(e) {
		count++;
	}
}
assert(count === 6);
console.log("Passed!");

// Rollback Attacks
console.log("\nTesting for Rollback Attacks");

var old_data = toDump.dump();
toDump.set("www.facebook.com", "fb_password"); // Modifying the keychain
var new_data = toDump.dump();

var old_contents = old_data[0];
var new_hash = new_data[1];

r = false;
try {
	new_keychain.load(password, old_contents, new_hash);
} catch (e) {
	r = true;
}
assert(r);
console.log("Passed!");

console.log("\nAll tests passed!");