/**
 * Crypto Monitor - Capture decrypted C2 communications
 * Hooks Cipher, MessageDigest, Base64, SecretKeySpec to intercept
 * encryption/decryption operations and reveal plaintext C2 data.
 *
 * For: Bank of India Cognidroid - Dynamic Analysis Frida Scripts
 */

"use strict";

var results = {
    decrypted_strings: [],
    encryption_keys: [],
    base64_decoded: [],
    crypto_algorithms: []
};

// ─── Cipher hook — captures plaintext before encryption and after decryption ─
function hookCipher() {
    try {
        var Cipher = Java.use("javax.crypto.Cipher");

        Cipher.doFinal.overload("[B").implementation = function (input) {
            var result = this.doFinal(input);
            var algorithm = this.getAlgorithm();
            var mode = this.getOpmode(); // 1=ENCRYPT, 2=DECRYPT

            if (!results.crypto_algorithms.includes(algorithm)) {
                results.crypto_algorithms.push(algorithm);
            }

            try {
                if (mode === 2) { // DECRYPT
                    var plaintext = Java.use("java.lang.String").$new(result, "UTF-8");
                    // plaintext is a Frida Java String wrapper — .length() is the Java method, which is correct here.
                    if (plaintext.length() > 3) {
                        var entry = { algorithm: algorithm, plaintext: plaintext.substring(0, 500), direction: "decrypt" };
                        results.decrypted_strings.push(entry);
                        send(JSON.stringify({ type: "crypto", algorithm: algorithm, plaintext: plaintext.substring(0, 200), direction: "decrypt" }));
                    }
                } else if (mode === 1) { // ENCRYPT — log the input plaintext
                    var inputStr = Java.use("java.lang.String").$new(input, "UTF-8");
                    if (inputStr.length() > 3) {
                        send(JSON.stringify({ type: "crypto", algorithm: algorithm, plaintext: inputStr.substring(0, 200), direction: "pre_encrypt" }));
                    }
                }
            } catch (e) {}

            return result;
        };

        Cipher.doFinal.overload("[B", "int", "int").implementation = function (input, offset, len) {
            var result = this.doFinal(input, offset, len);
            var algorithm = this.getAlgorithm();
            var mode = this.getOpmode();
            try {
                if (mode === 2) {
                    var plaintext = Java.use("java.lang.String").$new(result, "UTF-8");
                    if (plaintext.length() > 3) {
                        results.decrypted_strings.push({ algorithm: algorithm, plaintext: plaintext.substring(0, 500), direction: "decrypt" });
                        send(JSON.stringify({ type: "crypto", algorithm: algorithm, plaintext: plaintext.substring(0, 200), direction: "decrypt" }));
                    }
                }
            } catch (e) {}
            return result;
        };
    } catch (e) {}
}

// ─── SecretKeySpec — capture encryption keys ──────────────────────────────
function hookSecretKeySpec() {
    try {
        var SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
        SecretKeySpec.$init.overload("[B", "java.lang.String").implementation = function (key, algorithm) {
            var keyHex = Array.from(key).map(b => ('0' + (b & 0xFF).toString(16)).slice(-2)).join('');
            var entry = { algorithm: algorithm, key_hex: keyHex, key_length: key.length };
            results.encryption_keys.push(entry);
            send(JSON.stringify({ type: "crypto_key", algorithm: algorithm, key_hex: keyHex }));
            return this.$init(key, algorithm);
        };
    } catch (e) {}
}

// ─── Base64 decode hook — capture decoded payloads ────────────────────────
function hookBase64() {
    try {
        var Base64 = Java.use("android.util.Base64");
        Base64.decode.overload("java.lang.String", "int").implementation = function (str, flags) {
            var result = this.decode(str, flags);
            try {
                var decoded = Java.use("java.lang.String").$new(result, "UTF-8");
                if (decoded.length() > 5 && (decoded.startsWith("{") || decoded.startsWith("http") || decoded.contains("."))) {
                    results.base64_decoded.push({ encoded: str.substring(0, 100), decoded: decoded.substring(0, 500) });
                    send(JSON.stringify({ type: "base64_decode", decoded: decoded.substring(0, 300) }));
                }
            } catch (e) {}
            return result;
        };
    } catch (e) {}
}

// ─── XOR detection — hook common XOR decryption pattern ──────────────────
function hookStringDecryption() {
    try {
        // Hook String.<init> from byte arrays to catch strings decrypted from byte arrays
        var String = Java.use("java.lang.String");
        String.$init.overload("[B", "java.lang.String").implementation = function (bytes, charset) {
            var str = this.$init(bytes, charset);
            var result = Java.use("java.lang.String").$new(bytes, charset);
            // Only flag strings that look like C2 data (URLs, IPs, JSON)
            if (result.length() > 10 && (
                result.startsWith("http") ||
                result.startsWith("{") ||
                result.matches("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}.*") ||
                result.contains("/api/") ||
                result.contains("/gate") ||
                result.contains("/cmd")
            )) {
                send(JSON.stringify({ type: "decoded_string", value: result.substring(0, 300) }));
                results.decrypted_strings.push({ algorithm: "string_decode", plaintext: result.substring(0, 300), direction: "decoded" });
            }
            return this;
        };
    } catch (e) {}
}

// ─── MessageDigest — log hash operations (MD5/SHA used for C2 auth) ──────
function hookMessageDigest() {
    try {
        var MessageDigest = Java.use("java.security.MessageDigest");
        MessageDigest.digest.overload("[B").implementation = function (input) {
            var result = this.digest(input);
            var algorithm = this.getAlgorithm();
            try {
                var inputStr = Java.use("java.lang.String").$new(input, "UTF-8");
                send(JSON.stringify({ type: "hash", algorithm: algorithm, input: inputStr.substring(0, 100) }));
            } catch (e) {}
            return result;
        };
    } catch (e) {}
}

Java.perform(function () {
    hookCipher();
    hookSecretKeySpec();
    hookBase64();
    hookStringDecryption();
    hookMessageDigest();
    send(JSON.stringify({ type: "init", script: "crypto_monitor", status: "loaded" }));
});
