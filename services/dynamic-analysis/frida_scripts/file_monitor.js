/**
 * File Monitor
 * Detects file existence checks, creation and deletion.
 *
 * For: Bank of India Sentinel
 */

"use strict";

var results = {
    file_operations: []
};

function sendEvent(operation, path, extra) {

    var event = {
        operation: operation,
        path: path,
        timestamp: new Date().toISOString()
    };

    if (extra) {
        Object.assign(event, extra);
    }

    results.file_operations.push(event);

    send(JSON.stringify({
        type: "file_operation",
        operation: operation,
        path: path,
        extra: extra || {}
    }));
}

Java.perform(function () {

    try {

        var File = Java.use("java.io.File");

        File.exists.implementation = function () {

            var path = this.getAbsolutePath();
            var result = this.exists();

            sendEvent("exists", path, {
                exists: result
            });

            return result;
        };

        File.createNewFile.implementation = function () {

            var path = this.getAbsolutePath();

            sendEvent("create", path);

            return this.createNewFile();
        };

        File.delete.implementation = function () {

            var path = this.getAbsolutePath();

            sendEvent("delete", path);

            return this.delete();
        };

        send(JSON.stringify({
            type: "init",
            script: "file_monitor",
            status: "loaded"
        }));

    } catch (e) {

        send(JSON.stringify({
            type: "error",
            script: "file_monitor",
            error: e.toString()
        }));

    }

});