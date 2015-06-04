"use strict";


/********* External Imports ********/

var lib = require("./lib/lib");

var KDF = lib.KDF,
    HMAC = lib.HMAC,
    SHA256 = lib.SHA256,
    setup_cipher = lib.setup_cipher,
    enc_gcm = lib.enc_gcm,
    dec_gcm = lib.dec_gcm,
    bitarray_slice = lib.bitarray_slice,
    bitarray_to_string = lib.bitarray_to_string,
    string_to_bitarray = lib.string_to_bitarray,
    bitarray_to_hex = lib.bitarray_to_hex,
    hex_to_bitarray = lib.hex_to_bitarray,
    bitarray_to_base64 = lib.bitarray_to_base64,
    base64_to_bitarray = lib.base64_to_bitarray,
    byte_array_to_hex = lib.byte_array_to_hex,
    hex_to_byte_array = lib.hex_to_byte_array,
    string_to_padded_byte_array = lib.string_to_padded_byte_array,
    string_to_padded_bitarray = lib.string_to_padded_bitarray,
    string_from_padded_byte_array = lib.string_from_padded_byte_array,
    string_from_padded_bitarray = lib.string_from_padded_bitarray,
    random_bitarray = lib.random_bitarray,
    bitarray_equal = lib.bitarray_equal,
    bitarray_len = lib.bitarray_len,
    bitarray_concat = lib.bitarray_concat,
    dict_num_keys = lib.dict_num_keys;


/********* Implementation ********/


var keychain = function() {
  // Class-private instance variables.
  var priv = {
    secrets: {
      version: "CS 255 Password Manager v1.0",
      salt: undefined,
      keys: {
        AUTH: undefined,
        HMAC: undefined,
        GCM: undefined
      }
    },
    data: { }
  };

  // Password constants
  var MAX_PW_LEN_BYTES = 64; // Maximum length of each record in bytes
  var PADDING_LENGTH = 4;
  var ENC_PW_LENGTH = MAX_PW_LEN_BYTES + PADDING_LENGTH + 1;

  // Keys constants
  var AES_KEY_LENGTH = 128;
  var MAC_KEY_LENGTH = 256;

  // Flag to indicate whether password manager is "ready" or not
  var ready = false;

  var keychain = {};

  /** 
    * Creates an empty keychain with the given password. Once init is called,
    * the password manager should be in a ready state.
    *
    * Arguments:
    *   password: string
    * Return Type: void
    */
  keychain.init = function(password) {
    ready = false; // Blocks the Keychain

    // Generates the salt
    priv.secrets.salt = random_bitarray(AES_KEY_LENGTH);

    // Derives a Master Key from 'password'
    var masterKey = KDF(password, priv.secrets.salt);

    // Generating the other keys
    var hmacString = "bT2XHI7poJiBI0RqHIKN"; // Random strings to derive the keys
    var authString = "icqjutMI3k80pmyhDjgy";
    var gcmString = "Xjfx8KSD3vbIYP4Nm9PK";

    priv.secrets.keys.HMAC = bitarray_slice(HMAC(masterKey, hmacString), 0, MAC_KEY_LENGTH);
    priv.secrets.keys.AUTH = bitarray_slice(HMAC(masterKey, authString), 0, AES_KEY_LENGTH);
    priv.secrets.keys.GCM = bitarray_slice(HMAC(masterKey, gcmString), 0, AES_KEY_LENGTH);

    ready = true; // Keychain is ready
  };

  /**
    * Loads the keychain state from the provided representation (repr). The
    * repr variable will contain a JSON encoded serialization of the contents
    * of the KVS (as returned by the save function). The trusted_data_check
    * is an *optional* SHA-256 checksum that can be used to validate the 
    * integrity of the contents of the KVS. If the checksum is provided and the
    * integrity check fails, an exception should be thrown. You can assume that
    * the representation passed to load is well-formed (e.g., the result of a 
    * call to the save function). Returns true if the data is successfully loaded
    * and the provided password is correct. Returns false otherwise.
    *
    * Arguments:
    *   password:           string
    *   repr:               string
    *   trusted_data_check: string
    * Return Type: boolean
    */
  keychain.load = function(password, repr, trusted_data_check) {
    throw "Not implemented!";
  };

  /**
    * Returns a JSON serialization of the contents of the keychain that can be 
    * loaded back using the load function. The return value should consist of
    * an array of two strings:
    *   arr[0] = JSON encoding of password manager
    *   arr[1] = SHA-256 checksum
    * As discussed in the handout, the first element of the array should contain
    * all of the data in the password manager. The second element is a SHA-256
    * checksum computed over the password manager to preserve integrity. If the
    * password manager is not in a ready-state, return null.
    *
    * Return Type: array
    */ 
  keychain.dump = function() {
    throw "Not implemented!";
  }

  /**
    * Fetches the data (as a string) corresponding to the given domain from the KVS.
    * If there is no entry in the KVS that matches the given domain, then return
    * null. If the password manager is not in a ready state, throw an exception. If
    * tampering has been detected with the records, throw an exception.
    *
    * Arguments:
    *   name: string
    * Return Type: string
    */
  keychain.get = function(name) {
    throw "Not implemented!";
  }

  /** 
  * Inserts the domain and associated data into the KVS. If the domain is
  * already in the password manager, this method should update its value. If
  * not, create a new entry in the password manager. If the password manager is
  * not in a ready state, throw an exception.
  *
  * Arguments:
  *   name: string
  *   value: string
  * Return Type: void
  */
  keychain.set = function(name, value) {
    if (ready) {
      // Keys
      var K_HMAC = priv.secret.keys.HMAC;
      var K_GCM = priv.secret.keys.GCM;

      // Padding the value to 65 bytes. Preventing an adversary from learning any information about the password lengths.
      var paddedPw = string_to_padded_bitarray(value, 0, MAX_PW_LEN_BYTES + 1);
  
      var domain = HMAC(K_HMAC, name);      
      var signedPw = bitarray_concat(paddedPw, domain); // Signing the password to protect against swap attacks

      var encPw = enc_gcm(setup_cipher(K_GCM), signedPw);

      // Saves the data
      priv.data[domain] = encPw;
    } else {
      throw "The keychain is not ready!";
    }
  }

  /**
    * Removes the record with name from the password manager. Returns true
    * if the record with the specified name is removed, false otherwise. If
    * the password manager is not in a ready state, throws an exception.
    *
    * Arguments:
    *   name: string
    * Return Type: boolean
  */
  keychain.remove = function(name) {
    throw "Not implemented!";
  }

  return keychain;
}

module.exports.keychain = keychain;
