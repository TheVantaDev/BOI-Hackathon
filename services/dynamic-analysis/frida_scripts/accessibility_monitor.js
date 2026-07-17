/**
 * Accessibility Service Monitor
 * Detects abuse of Android Accessibility Services for:
 * - Banking credential harvesting via screen reading
 * - ATS (Automatic Transfer System) input injection
 * - App monitoring for overlay trigger timing
 * - Uninstall prevention
 *
 * For: Bank of India Sentinel - Dynamic Analysis Frida Scripts
 */

"use strict";

var results = {
    accessibility_events: [],
    ats_sequences: [],
    targeted_apps: [],
    ui_text_read: []
};

var BANKING_KEYWORDS = [
    "password", "pin", "otp", "upi", "account", "ifsc", "transfer",
    "amount", "beneficiary", "cvv", "card number", "netbanking",
    "login", "username", "mobile number", "aadhaar", "pan"
];

// ─── AccessibilityService.onAccessibilityEvent ────────────────────────────
function hookOnAccessibilityEvent() {
    try {
        var AccessibilityService = Java.use("android.accessibilityservice.AccessibilityService");
        AccessibilityService.onAccessibilityEvent.implementation = function (event) {
            try {
                var eventType = event.getEventType();
                var pkg = event.getPackageName();
                var pkgStr = pkg ? pkg.toString() : "";
                var source = event.getSource();

                var eventEntry = {
                    event_type: eventType,
                    package: pkgStr,
                    service_class: this.$className
                };

                // Log UI text reading — key indicator of credential scraping
                if (source !== null) {
                    try {
                        var text = source.getText();
                        if (text !== null && text.toString().length() > 0) {
                            var textStr = text.toString().toLowerCase();
                            var isSensitive = BANKING_KEYWORDS.some(function(kw) {
                                return textStr.includes(kw);
                            });

                            if (isSensitive) {
                                results.ui_text_read.push({ text: textStr, from_package: pkgStr });
                                send(JSON.stringify({
                                    type: "sensitive_ui_text_read",
                                    text: textStr.substring(0, 200),
                                    from_package: pkgStr,
                                    severity: "HIGH"
                                }));
                            }
                        }
                    } catch (e) {}
                }

                results.accessibility_events.push(eventEntry);

                // Check for specific high-value event types
                var TYPE_WINDOW_STATE_CHANGED = 32;
                var TYPE_VIEW_TEXT_CHANGED = 16;
                var TYPE_VIEW_FOCUSED = 8;

                if (eventType === TYPE_WINDOW_STATE_CHANGED && pkgStr.length > 0) {
                    // Track which apps are being monitored for foreground changes
                    if (!results.targeted_apps.includes(pkgStr)) {
                        results.targeted_apps.push(pkgStr);
                        send(JSON.stringify({
                            type: "app_foreground_monitored",
                            package: pkgStr,
                            note: "Accessibility service watching this app's foreground state"
                        }));
                    }
                }

                if (eventType === TYPE_VIEW_TEXT_CHANGED) {
                    send(JSON.stringify({
                        type: "text_change_monitored",
                        package: pkgStr,
                        note: "Possible keylogging via text change events"
                    }));
                }

            } catch (e) {}

            return this.onAccessibilityEvent(event);
        };
    } catch (e) {}
}

// ─── AccessibilityService.performGlobalAction ──────────────────────────────
function hookGlobalAction() {
    try {
        var AccessibilityService = Java.use("android.accessibilityservice.AccessibilityService");

        var GLOBAL_ACTION_NAMES = {
            1: "GLOBAL_ACTION_BACK",
            2: "GLOBAL_ACTION_HOME",
            3: "GLOBAL_ACTION_RECENTS",
            4: "GLOBAL_ACTION_NOTIFICATIONS",
            7: "GLOBAL_ACTION_LOCK_SCREEN",
            8: "GLOBAL_ACTION_TAKE_SCREENSHOT",
            12: "GLOBAL_ACTION_KEYCODE_HEADSETHOOK"
        };

        AccessibilityService.performGlobalAction.implementation = function (action) {
            var actionName = GLOBAL_ACTION_NAMES[action] || ("UNKNOWN_" + action);
            results.ats_sequences.push({ action: actionName, timestamp: new Date().toISOString() });
            send(JSON.stringify({
                type: "global_action",
                action: actionName,
                action_code: action,
                note: "Accessibility service performing system-level action without user input"
            }));

            if (action === 8) { // TAKE_SCREENSHOT
                send(JSON.stringify({
                    type: "screenshot_taken",
                    severity: "HIGH",
                    note: "Malware capturing screen content via Accessibility API"
                }));
            }

            return this.performGlobalAction(action);
        };
    } catch (e) {}
}

// ─── GestureDescription dispatch — detect tap injection ───────────────────
function hookGestureDispatch() {
    try {
        var AccessibilityService = Java.use("android.accessibilityservice.AccessibilityService");
        AccessibilityService.dispatchGesture.implementation = function (gesture, callback, handler) {
            results.ats_sequences.push({ action: "dispatchGesture", timestamp: new Date().toISOString() });
            send(JSON.stringify({
                type: "gesture_injection",
                severity: "CRITICAL",
                note: "ATS: Programmatic touch gesture injected — possible automated transaction execution"
            }));
            return this.dispatchGesture(gesture, callback, handler);
        };
    } catch (e) {}
}

// ─── AccessibilityNodeInfo.findAccessibilityNodeInfosByText ───────────────
function hookNodeSearch() {
    try {
        var AccessibilityNodeInfo = Java.use("android.view.accessibility.AccessibilityNodeInfo");
        AccessibilityNodeInfo.findAccessibilityNodeInfosByText.implementation = function (text) {
            var textStr = text ? text.toString() : "";
            var isSensitive = BANKING_KEYWORDS.some(function(kw) {
                return textStr.toLowerCase().includes(kw);
            });
            if (isSensitive || textStr.length > 0) {
                send(JSON.stringify({
                    type: "node_search",
                    search_text: textStr,
                    note: "Malware searching for UI element by text — possible ATS or credential harvesting"
                }));
            }
            return this.findAccessibilityNodeInfosByText(text);
        };
    } catch (e) {}
}

Java.perform(function () {
    hookOnAccessibilityEvent();
    hookGlobalAction();
    hookGestureDispatch();
    hookNodeSearch();
    send(JSON.stringify({ type: "init", script: "accessibility_monitor", status: "loaded" }));
});
