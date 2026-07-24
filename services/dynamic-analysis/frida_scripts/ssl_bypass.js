/**
 * SSL Pinning Bypass + HTTPS Traffic Monitor
 * Hooks OkHttp3, HttpsURLConnection, TrustManager, and Conscrypt
 * to capture plaintext HTTPS traffic before encryption.
 *
 * For: Bank of India Sentinel - Dynamic Analysis Frida Scripts
 */

"use strict";

var results = {
    network_requests: [],
    ssl_pinning_detected: false
};

// ─── OkHttp3 Interceptor ────────────────────────────────────────────────────
function hookOkHttp3() {
    try {
        var OkHttpClient = Java.use("okhttp3.OkHttpClient");
        var Request = Java.use("okhttp3.Request");
        var Response = Java.use("okhttp3.Response");
        var RealCall = Java.use("okhttp3.internal.connection.RealCall");

        RealCall.execute.implementation = function () {
            var request = this.request();
            var url = request.url().toString();
            var method = request.method();
            var body = "";

            try {
                var reqBody = request.body();
                if (reqBody !== null) {
                    var buffer = Java.use("okio.Buffer").$new();
                    reqBody.writeTo(buffer);
                    body = buffer.readUtf8();
                }
            } catch (e) {}

            var response = this.execute();
            var statusCode = response.code();

            results.network_requests.push({
                url: url,
                method: method,
                request_body: body.substring(0, 2000),
                status_code: statusCode,
                source: "okhttp3"
            });

            send(JSON.stringify({ type: "network", url: url, method: method, body: body.substring(0, 500), status: statusCode }));
            return response;
        };
    } catch (e) {
        // OkHttp3 not present
    }
}

// ─── TrustManager Bypass (disables certificate validation) ─────────────────
function bypassTrustManager() {
    try {
        var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
        var HostnameVerifier  = Java.use("javax.net.ssl.HostnameVerifier");
        var SSLContext = Java.use("javax.net.ssl.SSLContext");

        var TrustManager = Java.registerClass({
            name: "com.sentinel.bypass.TrustManager",
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function (chain, authType) {},
                checkServerTrusted: function (chain, authType) {},
                getAcceptedIssuers: function () { return []; }
            }
        });

        // NOTE: HostnameVerifier is a Java interface — you cannot call $new() on it.
        // We must register a class that implements it.
        var AllowAllHostnameVerifier = Java.registerClass({
            name: "com.sentinel.bypass.AllowAllHostnameVerifier",
            implements: [HostnameVerifier],
            methods: {
                verify: function (hostname, session) { return true; }
            }
        });

        var TrustManagers = [TrustManager.$new()];
        var SSLContextInstance = SSLContext.getInstance("TLS");
        SSLContextInstance.init(null, TrustManagers, null);

        var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
        HttpsURLConnection.setDefaultSSLSocketFactory(SSLContextInstance.getSocketFactory());
        HttpsURLConnection.setDefaultHostnameVerifier(AllowAllHostnameVerifier.$new());

        send(JSON.stringify({ type: "ssl_bypass", status: "TrustManager + HostnameVerifier bypassed" }));
    } catch (e) {
        send(JSON.stringify({ type: "error", script: "ssl_bypass", error: "bypassTrustManager: " + e }));
    }
}

// ─── CertificatePinner Bypass (OkHttp pinning) ────────────────────────────
function bypassCertificatePinner() {
    try {
        var CertificatePinner = Java.use("okhttp3.CertificatePinner");
        CertificatePinner.check.overload("java.lang.String", "java.util.List").implementation = function (hostname, certs) {
            results.ssl_pinning_detected = true;
            send(JSON.stringify({ type: "ssl_bypass", status: "CertificatePinner.check bypassed", hostname: hostname }));
            // Do nothing — bypass pinning
        };
        CertificatePinner.check.overload("java.lang.String", "[Ljava.security.cert.Certificate;").implementation = function (hostname, certs) {
            results.ssl_pinning_detected = true;
            send(JSON.stringify({ type: "ssl_bypass", status: "CertificatePinner.check[] bypassed", hostname: hostname }));
        };
    } catch (e) {}
}

// ─── HttpsURLConnection monitor ───────────────────────────────────────────
function hookUrlConnection() {
    try {
        var URL = Java.use("java.net.URL");
        URL.openConnection.overload().implementation = function () {
            var url = this.toString();
            send(JSON.stringify({ type: "network", url: url, method: "CONNECT", source: "URLConnection" }));
            results.network_requests.push({ url: url, method: "CONNECT", source: "URLConnection" });
            return this.openConnection();
        };
    } catch (e) {}
}

// ─── Conscrypt (Android's TLS implementation) bypass ─────────────────────
function bypassConscrypt() {
    try {
        var ConscryptHostnameVerifier = Java.use("com.android.org.conscrypt.OkHostnameVerifier");
        ConscryptHostnameVerifier.verify.overload("java.lang.String", "javax.net.ssl.SSLSession").implementation = function (hostname, session) {
            send(JSON.stringify({ type: "ssl_bypass", status: "Conscrypt hostname bypass", hostname: hostname }));
            return true;
        };
    } catch (e) {}
}

Java.perform(function () {
    hookOkHttp3();
    bypassTrustManager();
    bypassCertificatePinner();
    hookUrlConnection();
    bypassConscrypt();
    send(JSON.stringify({ type: "init", script: "ssl_bypass", status: "loaded" }));
});
