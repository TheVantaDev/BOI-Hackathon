/**
 * Telephony Monitor
 * Monitors TelephonyManager APIs used by malware for
 * device fingerprinting and emulator detection.
 *
 * For: Bank of India Sentinel - Dynamic Analysis
 */

"use strict";

var results = {
    telephony_queries: []
};

function logEvent(method, value) {
    var entry = {
        method: method,
        value: value,
        timestamp: new Date().toISOString()
    };

    results.telephony_queries.push(entry);

    send(JSON.stringify({
        type: "telephony",
        method: method,
        value: value
    }));
}

Java.perform(function () {

    try {

        var TelephonyManager = Java.use("android.telephony.TelephonyManager");

        // IMEI
        TelephonyManager.getDeviceId.overload().implementation = function () {
            var result = this.getDeviceId();
            logEvent("getDeviceId", result);
            return result;
        };

        TelephonyManager.getDeviceId.overload("int").implementation = function (slot) {
            var result = this.getDeviceId(slot);
            logEvent("getDeviceId(int)", result);
            return result;
        };

        // API 26+
        TelephonyManager.getImei.overload().implementation = function () {
            var result = this.getImei();
            logEvent("getImei", result);
            return result;
        };

        TelephonyManager.getImei.overload("int").implementation = function (slot) {
            var result = this.getImei(slot);
            logEvent("getImei(int)", result);
            return result;
        };

        // IMSI
        TelephonyManager.getSubscriberId.implementation = function () {
            var result = this.getSubscriberId();
            logEvent("getSubscriberId", result);
            return result;
        };

        // SIM operator
        TelephonyManager.getSimOperatorName.implementation = function () {
            var result = this.getSimOperatorName();
            logEvent("getSimOperatorName", result);
            return result;
        };

        // Network operator
        TelephonyManager.getNetworkOperatorName.implementation = function () {
            var result = this.getNetworkOperatorName();
            logEvent("getNetworkOperatorName", result);
            return result;
        };

        send(JSON.stringify({
            type: "init",
            script: "telephony_monitor",
            status: "loaded"
        }));

    } catch (e) {

        send(JSON.stringify({
            type: "error",
            script: "telephony_monitor",
            error: e.toString()
        }));

    }

});