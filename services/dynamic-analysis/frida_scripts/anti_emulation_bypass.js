/**
 * Anti-Emulation Bypass
 * Patches out all common emulator detection methods used by Android banking trojans.
 * Makes the malware believe it is running on a real physical device so it activates
 * its malicious behavior inside the MobSF sandbox.
 *
 * For: Bank of India Sentinel - Dynamic Analysis Frida Scripts
 */

"use strict";

var FAKE_IMEI      = "867132041580756";
var FAKE_IMSI      = "404203612345678";  // Airtel India MCC/MNC
var FAKE_PHONE     = "+919876543210";
var FAKE_SIM_ID    = "8991101200003204510";
var FAKE_MODEL     = "Redmi Note 11";
var FAKE_BRAND     = "Xiaomi";
var FAKE_DEVICE    = "spes";
var FAKE_PRODUCT   = "spes_in";
var FAKE_HARDWARE  = "qcom";             // Qualcomm — real chipset name
var FAKE_MANU      = "Xiaomi";
var FAKE_FINGERPRINT = "Xiaomi/spes_in/spes:12/SKQ1.211006.001/V13.0.4.0.SGGINXM:user/release-keys";

var detected_checks = [];

function logDetection(check) {
    detected_checks.push(check);
    send(JSON.stringify({ type: "anti_emulation", bypassed_check: check }));
}

// ─── Build class fields ────────────────────────────────────────────────────
function patchBuildFields() {
    try {
        var Build = Java.use("android.os.Build");

        Object.defineProperty(Build, "MODEL", { get: function() { logDetection("Build.MODEL"); return FAKE_MODEL; } });
        Object.defineProperty(Build, "BRAND", { get: function() { logDetection("Build.BRAND"); return FAKE_BRAND; } });
        Object.defineProperty(Build, "DEVICE", { get: function() { logDetection("Build.DEVICE"); return FAKE_DEVICE; } });
        Object.defineProperty(Build, "PRODUCT", { get: function() { logDetection("Build.PRODUCT"); return FAKE_PRODUCT; } });
        Object.defineProperty(Build, "HARDWARE", { get: function() { logDetection("Build.HARDWARE"); return FAKE_HARDWARE; } });
        Object.defineProperty(Build, "MANUFACTURER", { get: function() { logDetection("Build.MANUFACTURER"); return FAKE_MANU; } });
        Object.defineProperty(Build, "FINGERPRINT", { get: function() { logDetection("Build.FINGERPRINT"); return FAKE_FINGERPRINT; } });
        Object.defineProperty(Build, "TAGS", { get: function() { return "release-keys"; } });
        Object.defineProperty(Build, "TYPE", { get: function() { return "user"; } });
    } catch (e) {}
}

// ─── TelephonyManager — return real-looking device identifiers ────────────
function patchTelephonyManager() {
    try {
        var TelephonyManager = Java.use("android.telephony.TelephonyManager");

        TelephonyManager.getDeviceId.overload().implementation = function () {
            logDetection("TelephonyManager.getDeviceId");
            return FAKE_IMEI;
        };
        TelephonyManager.getDeviceId.overload("int").implementation = function (slot) {
            logDetection("TelephonyManager.getDeviceId(int)");
            return FAKE_IMEI;
        };
        TelephonyManager.getImei.overload().implementation = function () {
            logDetection("TelephonyManager.getImei");
            return FAKE_IMEI;
        };
        TelephonyManager.getImei.overload("int").implementation = function (slot) {
            logDetection("TelephonyManager.getImei(int)");
            return FAKE_IMEI;
        };
        TelephonyManager.getSubscriberId.implementation = function () {
            logDetection("TelephonyManager.getSubscriberId");
            return FAKE_IMSI;
        };
        TelephonyManager.getLine1Number.implementation = function () {
            logDetection("TelephonyManager.getLine1Number");
            return FAKE_PHONE;
        };
        TelephonyManager.getSimSerialNumber.implementation = function () {
            logDetection("TelephonyManager.getSimSerialNumber");
            return FAKE_SIM_ID;
        };
        TelephonyManager.getNetworkOperator.implementation = function () {
            logDetection("TelephonyManager.getNetworkOperator");
            return "404203"; // Airtel India MCC+MNC
        };
        TelephonyManager.getNetworkOperatorName.implementation = function () {
            return "Airtel";
        };
        TelephonyManager.getSimOperator.implementation = function () {
            return "404203";
        };
        TelephonyManager.getSimOperatorName.implementation = function () {
            return "Airtel";
        };
        TelephonyManager.getSimCountryIso.implementation = function () {
            return "in";
        };
        TelephonyManager.getNetworkCountryIso.implementation = function () {
            return "in";
        };
        TelephonyManager.getPhoneType.implementation = function () {
            return 1; // PHONE_TYPE_GSM
        };
    } catch (e) {}
}

// ─── System Properties / /proc/cpuinfo ───────────────────────────────────
function patchSystemProperties() {
    try {
        var SystemProperties = Java.use("android.os.SystemProperties");
        SystemProperties.get.overload("java.lang.String").implementation = function (key) {
            var val = this.get(key);
            if (key === "ro.hardware" || key === "ro.kernel.qemu" || key === "ro.product.device") {
                logDetection("SystemProperties.get: " + key);
                if (key === "ro.kernel.qemu") return "0";
                if (key === "ro.hardware") return "qcom";
                if (key === "ro.product.device") return FAKE_DEVICE;
            }
            return val;
        };
    } catch (e) {}
}

// ─── PackageManager — hide sandbox/emulator packages ──────────────────────
function patchPackageManager() {
    try {
        var ApplicationInfo = Java.use("android.content.pm.ApplicationInfo");
        var PackageManager = Java.use("android.app.ApplicationPackageManager");

        var SANDBOX_PACKAGES = [
            "com.bluestacks", "com.bignox.app", "com.vphone.launcher",
            "com.google.android.launcher.layouts.genymotion",
            "com.genymotion.superuser", "com.android.emulator.smoketests",
            "com.mumu.store", "com.luckypatcher",
            "com.noxgroup.app.store", "com.microvirt.market"
        ];

        PackageManager.getApplicationInfo.overload("java.lang.String", "int").implementation = function (pkg, flags) {
            if (SANDBOX_PACKAGES.some(function(s) { return pkg.indexOf(s) >= 0; })) {
                logDetection("getApplicationInfo blocked for sandbox pkg: " + pkg);
                throw Java.use("android.content.pm.PackageManager$NameNotFoundException").$new(pkg);
            }
            return this.getApplicationInfo(pkg, flags);
        };
    } catch (e) {}
}

// ─── Sensor availability — emulators often lack physical sensors ──────────
function patchSensorManager() {
    try {
        var SensorManager = Java.use("android.hardware.SensorManager");
        SensorManager.getDefaultSensor.overload("int").implementation = function (type) {
            var result = this.getDefaultSensor(type);
            if (result === null) {
                // Emulator has no sensor — this is an emulator detection signal
                // We can't easily fake a Sensor object, so just log the check
                logDetection("SensorManager.getDefaultSensor(" + type + ") returned null — possible emulator check");
            }
            return result;
        };
    } catch (e) {}
}

// ─── File-based emulator detection bypass (/proc/cpuinfo QEMU string) ─────
function patchFileRead() {
    try {
        var FileInputStream = Java.use("java.io.FileInputStream");
        FileInputStream.$init.overload("java.lang.String").implementation = function (path) {
            if (path && (path.includes("/proc/cpuinfo") || path.includes("/proc/tty/drivers"))) {
                logDetection("FileInputStream check: " + path);
            }
            return this.$init(path);
        };
    } catch (e) {}
}

Java.perform(function () {
    patchBuildFields();
    patchTelephonyManager();
    patchSystemProperties();
    patchPackageManager();
    patchSensorManager();
    patchFileRead();
    send(JSON.stringify({
        type: "init",
        script: "anti_emulation_bypass",
        status: "loaded",
        fake_imei: FAKE_IMEI,
        fake_carrier: "Airtel India"
    }));
});
