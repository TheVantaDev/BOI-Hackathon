/**
 * Overlay Detector - Detect banking overlay attacks in real-time
 * Hooks WindowManager.addView() to detect when malware displays
 * a fake banking login screen over a real banking app.
 *
 * For: Bank of India Sentinel - Dynamic Analysis Frida Scripts
 */

"use strict";

var INDIAN_BANKING_PACKAGES = [
    "com.sbi.SBIFreedomPlus", "com.sbi.lotusintouch", "com.sbi.SBIMobileBanking",
    "net.one97.paytm", "in.org.npci.upiapp", "com.phonepe.app",
    "com.google.android.apps.nbu.paisa.user", "com.hdfc.mobilebanking",
    "com.hdfcbank.hdfcmobile", "com.axis.mobile", "com.bankofbaroda.mobilebanking",
    "com.idbi.mPassbook", "com.icici.ipayapp", "com.kotak.mobilebanking",
    "com.pnb.mobilebanking", "com.canara.mobilebanking", "com.iob.mobilebanking",
    "com.yesbank.mobilebanking", "com.federal.mfederal", "com.amazon.mShop.android.shopping",
    "com.bankofmaharashtra.mobilebanking", "com.ubi.UBIMobile",
    "com.csb.mobilebanking", "com.indus.mobilebanking"
];

var results = {
    overlays_detected: [],
    target_packages_monitored: [],
    overlay_html_captured: [],
    ats_actions: []
};

// ─── WindowManager.addView — detect overlay display ───────────────────────
function hookWindowManagerAddView() {
    try {
        var WindowManager = Java.use("android.view.WindowManager$LayoutParams");
        var type = WindowManager.TYPE_APPLICATION_OVERLAY.value;

        var ViewManagerImpl = Java.use("android.view.ViewManager");

        // Hook through the implementation class
        Java.enumerateClassLoaders({
            onMatch: function(loader) {
                try {
                    Java.classFactory.loader = loader;
                    var WindowManagerImpl = Java.use("android.view.WindowManagerImpl");
                    WindowManagerImpl.addView.implementation = function (view, params) {
                        var lp = Java.cast(params, Java.use("android.view.WindowManager$LayoutParams"));
                        var viewType = lp.type.value;
                        var className = view.$className;

                        // TYPE_APPLICATION_OVERLAY (2038) or TYPE_PHONE (2002) = overlay types used by malware
                        if (viewType === 2038 || viewType === 2002 || viewType === 2003) {
                            var entry = {
                                overlay_type: viewType,
                                view_class: className,
                                timestamp: new Date().toISOString()
                            };

                            // Try to capture HTML if it's a WebView
                            try {
                                var WebView = Java.use("android.webkit.WebView");
                                var webview = Java.cast(view, WebView);
                                webview.evaluateJavascript("document.documentElement.innerHTML", null);
                                entry.is_webview = true;
                            } catch (e) {
                                entry.is_webview = false;
                            }

                            results.overlays_detected.push(entry);
                            send(JSON.stringify({
                                type: "overlay_attack_detected",
                                overlay_type: viewType,
                                view_class: className,
                                severity: "CRITICAL"
                            }));
                        }

                        return this.addView(view, params);
                    };
                } catch (e) {}
            },
            onComplete: function() {}
        });
    } catch (e) {}
}

// ─── AccessibilityService — detect which packages are being monitored ──────
function hookAccessibilityMonitoring() {
    try {
        var AccessibilityEvent = Java.use("android.view.accessibility.AccessibilityEvent");
        AccessibilityEvent.getPackageName.implementation = function () {
            var pkg = this.getPackageName();
            if (pkg !== null) {
                var pkgStr = pkg.toString();
                // Is this malware monitoring an Indian banking app?
                INDIAN_BANKING_PACKAGES.forEach(function(target) {
                    if (pkgStr === target && !results.target_packages_monitored.includes(pkgStr)) {
                        results.target_packages_monitored.push(pkgStr);
                        send(JSON.stringify({
                            type: "banking_app_monitored",
                            target_package: pkgStr,
                            severity: "HIGH"
                        }));
                    }
                });
            }
            return pkg;
        };
    } catch (e) {}
}

// ─── AccessibilityService.performAction — detect ATS input injection ──────
function hookAccessibilityAction() {
    try {
        var AccessibilityNodeInfo = Java.use("android.view.accessibility.AccessibilityNodeInfo");

        AccessibilityNodeInfo.performAction.overload("int").implementation = function (action) {
            var ACTION_SET_TEXT = 2097152;
            var ACTION_CLICK = 16;
            var ACTION_LONG_CLICK = 32;

            var actionName = "unknown_" + action;
            if (action === ACTION_SET_TEXT) actionName = "ACTION_SET_TEXT";
            if (action === ACTION_CLICK) actionName = "ACTION_CLICK";
            if (action === ACTION_LONG_CLICK) actionName = "ACTION_LONG_CLICK";

            if (action === ACTION_SET_TEXT || action === ACTION_CLICK) {
                results.ats_actions.push({ action: actionName, timestamp: new Date().toISOString() });
                send(JSON.stringify({
                    type: "ats_action",
                    action: actionName,
                    note: "Possible Automatic Transfer System input injection"
                }));
            }

            return this.performAction(action);
        };

        AccessibilityNodeInfo.performAction.overload("int", "android.os.Bundle").implementation = function (action, bundle) {
            if (action === 2097152) { // ACTION_SET_TEXT
                var text = "";
                try {
                    text = bundle.getCharSequence("ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE").toString();
                } catch (e) {}
                results.ats_actions.push({ action: "ACTION_SET_TEXT", text: text, timestamp: new Date().toISOString() });
                send(JSON.stringify({
                    type: "ats_text_injection",
                    action: "ACTION_SET_TEXT",
                    injected_text: text,
                    severity: "CRITICAL",
                    note: "ATS: malware injecting text into UI field"
                }));
            }
            return this.performAction(action, bundle);
        };
    } catch (e) {}
}

// ─── ActivityManager — detect foreground app monitoring (overlay trigger) ──
function hookForegroundAppMonitor() {
    try {
        var ActivityManager = Java.use("android.app.ActivityManager");
        ActivityManager.getRunningTasks.implementation = function (maxNum) {
            var result = this.getRunningTasks(maxNum);
            // Malware calls this to know when to trigger overlay
            send(JSON.stringify({ type: "foreground_app_query", note: "Possible overlay trigger check" }));
            return result;
        };
    } catch (e) {}
}

Java.perform(function () {
    hookWindowManagerAddView();
    hookAccessibilityMonitoring();
    hookAccessibilityAction();
    hookForegroundAppMonitor();
    send(JSON.stringify({
        type: "init",
        script: "overlay_detector",
        status: "loaded",
        monitoring_packages: INDIAN_BANKING_PACKAGES.length
    }));
});
