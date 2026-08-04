/**
 * WebView Monitor
 * Monitors URLs loaded inside Android WebViews.
 *
 * For: Bank of India Sentinel
 */

"use strict";

var results = {
    webview_urls: []
};

function logUrl(url) {

    var entry = {
        url: url,
        timestamp: new Date().toISOString()
    };

    results.webview_urls.push(entry);

    send(JSON.stringify({
        type: "webview",
        url: url
    }));
}

Java.perform(function () {

    try {

        var WebView = Java.use("android.webkit.WebView");

        WebView.loadUrl.overload("java.lang.String").implementation = function (url) {

            logUrl(url);

            return this.loadUrl(url);
        };

        WebView.loadUrl.overload(
            "java.lang.String",
            "java.util.Map"
        ).implementation = function (url, headers) {

            logUrl(url);

            return this.loadUrl(url, headers);
        };

        send(JSON.stringify({
            type: "init",
            script: "webview_monitor",
            status: "loaded"
        }));

    } catch (e) {

        send(JSON.stringify({
            type: "error",
            script: "webview_monitor",
            error: e.toString()
        }));

    }

});