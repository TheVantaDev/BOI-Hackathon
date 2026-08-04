/**
 * Native Library Monitor
 * Detects loading of native libraries at runtime.
 *
 * For: Bank of India Sentinel
 */

"use strict";

var results = {
    native_libraries: []
};

function logLibrary(method, library) {

    var entry = {
        method: method,
        library: library,
        timestamp: new Date().toISOString()
    };

    results.native_libraries.push(entry);

    send(JSON.stringify({
        type: "native_library",
        method: method,
        library: library
    }));
}

Java.perform(function () {

    try {

        var System = Java.use("java.lang.System");

        System.loadLibrary.overload("java.lang.String").implementation = function (lib) {

            logLibrary("loadLibrary", lib);

            return this.loadLibrary(lib);
        };

        System.load.overload("java.lang.String").implementation = function (path) {

            logLibrary("load", path);

            return this.load(path);
        };

        send(JSON.stringify({
            type: "init",
            script: "native_load_monitor",
            status: "loaded"
        }));

    } catch (e) {

        send(JSON.stringify({
            type: "error",
            script: "native_load_monitor",
            error: e.toString()
        }));

    }

});