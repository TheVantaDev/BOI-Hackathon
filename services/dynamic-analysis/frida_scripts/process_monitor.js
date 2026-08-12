/**
 * Process Monitor
 * Detects Runtime.exec() and ProcessBuilder execution.
 *
 * For: Bank of India Cognidroid
 */

"use strict";

var results = {
    process_events: []
};

function logProcess(command, source) {

    var entry = {
        command: command,
        source: source,
        timestamp: new Date().toISOString()
    };

    results.process_events.push(entry);

    send(JSON.stringify({
        type: "process_execution",
        command: command,
        source: source
    }));
}

Java.perform(function () {

    try {

        var Runtime = Java.use("java.lang.Runtime");

        Runtime.exec.overload("java.lang.String").implementation = function (cmd) {

            logProcess(cmd, "Runtime.exec");

            return this.exec(cmd);
        };

        Runtime.exec.overload("[Ljava.lang.String;").implementation = function (cmds) {

            var Arrays = Java.use("java.util.Arrays");

            var command = Arrays.toString(cmds);

            logProcess(command, "Runtime.exec[]");

            return this.exec(cmds);
        };

    } catch (e) {

        send(JSON.stringify({
            type: "error",
            script: "process_monitor",
            error: e.toString()
        }));

    }

    try {

        var ProcessBuilder = Java.use("java.lang.ProcessBuilder");

        ProcessBuilder.start.implementation = function () {

            var command = this.command().toString();

            logProcess(command, "ProcessBuilder.start");

            return this.start();
        };

    } catch (e) {

        send(JSON.stringify({
            type: "error",
            script: "process_monitor",
            error: e.toString()
        }));

    }

    send(JSON.stringify({
        type: "init",
        script: "process_monitor",
        status: "loaded"
    }));

});