/**
 * Location Monitor
 * Detects access to device location APIs.
 *
 * For: Bank of India Sentinel
 */

"use strict";

var results = {
    location_requests: []
};

function logLocation(provider, latitude, longitude) {

    var entry = {
        provider: provider,
        latitude: latitude,
        longitude: longitude,
        timestamp: new Date().toISOString()
    };

    results.location_requests.push(entry);

    send(JSON.stringify({
        type: "location_access",
        provider: provider,
        latitude: latitude,
        longitude: longitude
    }));
}

Java.perform(function () {

    try {

        var Location = Java.use("android.location.Location");

        Location.getLatitude.implementation = function () {

            var lat = this.getLatitude();

            try {
                var lon = this.getLongitude();
                var provider = this.getProvider();

                logLocation(provider, lat, lon);

            } catch (e) {}

            return lat;
        };

        send(JSON.stringify({
            type: "init",
            script: "location_monitor",
            status: "loaded"
        }));

    } catch (e) {

        send(JSON.stringify({
            type: "error",
            script: "location_monitor",
            error: e.toString()
        }));

    }

});