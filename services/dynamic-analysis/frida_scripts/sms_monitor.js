/**
 * SMS Monitor - Capture intercepted OTPs and outgoing SMS
 * Hooks SmsManager.sendTextMessage, BroadcastReceiver for SMS_RECEIVED,
 * and SmsMessage parsing to detect OTP interception by banking trojans.
 *
 * For: Bank of India Cognidroid - Dynamic Analysis Frida Scripts
 */

"use strict";

var results = {
    sms_intercepted: [],
    sms_sent: [],
    otp_patterns: []
};

var OTP_REGEX_PATTERNS = [
    /\b\d{4,8}\b/,                          // Generic 4-8 digit OTP
    /OTP[:\s]+(\d{4,8})/i,
    /one.time.password[:\s]+(\d{4,8})/i,
    /verification.code[:\s]+(\d{4,8})/i,
    /\bPIN[:\s]+(\d{4,6})\b/i,
    /UPI[:\s]+(\d{4,6})/i,
    /transaction.*?(\d{6})/i,
    /your.*?code.*?(\d{4,8})/i
];

function looksLikeOTP(text) {
    return OTP_REGEX_PATTERNS.some(function(pattern) {
        return pattern.test(text);
    });
}

// ─── SmsManager.sendTextMessage hook ──────────────────────────────────────
function hookSmsManagerSend() {
    try {
        var SmsManager = Java.use("android.telephony.SmsManager");

        SmsManager.sendTextMessage.implementation = function (destAddr, scAddr, text, sentIntent, deliveryIntent) {
            var entry = {
                direction: "outgoing",
                destination: destAddr,
                message: text,
                timestamp: new Date().toISOString()
            };
            results.sms_sent.push(entry);
            send(JSON.stringify({ type: "sms_send", destination: destAddr, message: text }));

            // Check if this is forwarding an intercepted OTP to C2
            if (looksLikeOTP(text)) {
                results.otp_patterns.push({ context: "outgoing_sms", content: text, destination: destAddr });
                send(JSON.stringify({ type: "otp_forward_detected", destination: destAddr, content: text }));
            }

            return this.sendTextMessage(destAddr, scAddr, text, sentIntent, deliveryIntent);
        };

        // Also hook sendMultipartTextMessage
        SmsManager.sendMultipartTextMessage.implementation = function (destAddr, scAddr, parts, sentIntents, deliveryIntents) {
            var partsList = [];
            for (var i = 0; i < parts.size(); i++) {
                partsList.push(parts.get(i).toString());
            }
            var fullText = partsList.join("");
            results.sms_sent.push({ direction: "outgoing_multipart", destination: destAddr, message: fullText });
            send(JSON.stringify({ type: "sms_multipart_send", destination: destAddr, message: fullText }));
            return this.sendMultipartTextMessage(destAddr, scAddr, parts, sentIntents, deliveryIntents);
        };
    } catch (e) {}
}

// ─── SmsMessage.getMessageBody hook — intercept incoming SMS content ───────
function hookSmsMessageParsing() {
    try {
        var SmsMessage = Java.use("android.telephony.SmsMessage");

        SmsMessage.getMessageBody.implementation = function () {
            var body = this.getMessageBody();
            var origAddr = "";
            try { origAddr = this.getOriginatingAddress(); } catch (e) {}

            var entry = {
                direction: "incoming",
                from: origAddr,
                body: body,
                timestamp: new Date().toISOString()
            };
            results.sms_intercepted.push(entry);
            send(JSON.stringify({ type: "sms_intercept", from: origAddr, body: body }));

            // Flag OTP messages specifically
            if (looksLikeOTP(body)) {
                results.otp_patterns.push({ context: "incoming_sms", content: body, from: origAddr });
                send(JSON.stringify({ type: "otp_intercepted", from: origAddr, content: body, severity: "CRITICAL" }));
            }

            return body;
        };
    } catch (e) {}
}

// ─── BroadcastReceiver hook for SMS_RECEIVED intent ───────────────────────
function hookBroadcastReceiver() {
    try {
        var BroadcastReceiver = Java.use("android.content.BroadcastReceiver");
        BroadcastReceiver.onReceive.implementation = function (context, intent) {
            var action = intent.getAction();
            if (action && (
                action.includes("SMS_RECEIVED") ||
                action.includes("SMS_DELIVER") ||
                action.includes("WAP_PUSH_RECEIVED")
            )) {
                send(JSON.stringify({
                    type: "sms_broadcast_received",
                    action: action,
                    receiver_class: this.$className
                }));
            }
            return this.onReceive(context, intent);
        };
    } catch (e) {}
}

// ─── NotificationManager hook — detect OTP notification suppression ────────
function hookNotificationSuppression() {
    try {
        var NotificationManager = Java.use("android.app.NotificationManager");
        NotificationManager.cancel.overload("int").implementation = function (id) {
            send(JSON.stringify({ type: "notification_cancelled", id: id, by_class: this.$className }));
            return this.cancel(id);
        };
        NotificationManager.cancel.overload("java.lang.String", "int").implementation = function (tag, id) {
            send(JSON.stringify({ type: "notification_cancelled", tag: tag, id: id, by_class: this.$className }));
            return this.cancel(tag, id);
        };
    } catch (e) {}
}

Java.perform(function () {
    hookSmsManagerSend();
    hookSmsMessageParsing();
    hookBroadcastReceiver();
    hookNotificationSuppression();
    send(JSON.stringify({ type: "init", script: "sms_monitor", status: "loaded" }));
});
