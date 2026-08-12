/**
 * Debug Monitor
 * Detects anti-debugging checks.
 *
 * For: Bank of India Cognidroid
 */

"use strict";

var results = {
    debugger_checks: []
};

function logDebuggerCheck(result) {

    var entry = {
        debugger_detected: result,
        timestamp: new Date().toISOString()
    };

    results.debugger_checks.push(entry);

    send(JSON.stringify({
        type: "debug_check",
        debugger_detected: result
    }));
}

Java.perform(function () {

    try {

        var Debug = Java.use("android.os.Debug");

        Debug.isDebuggerConnected.implementation = function () {

            var detected = this.isDebuggerConnected();

            logDebuggerCheck(detected);

            // Always return false so malware believes
            // no debugger is attached.
            return false;
        };

        send(JSON.stringify({
            type: "init",
            script: "debug_monitor",
            status: "loaded"
        }));

    } catch (e) {

        send(JSON.stringify({
            type: "error",
            script: "debug_monitor",
            error: e.toString()
        }));

    }

});