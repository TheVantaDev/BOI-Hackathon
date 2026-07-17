/**
 * DEX Loader Monitor - Detect dynamic code loading
 * Hooks DexClassLoader, PathClassLoader, InMemoryDexClassLoader
 * to capture paths and contents of dynamically loaded payloads.
 *
 * For: Bank of India Sentinel - Dynamic Analysis Frida Scripts
 */

"use strict";

var results = {
    dex_loads: [],
    downloaded_payloads: [],
    reflection_calls: []
};

// ─── DexClassLoader hook ───────────────────────────────────────────────────
function hookDexClassLoader() {
    try {
        var DexClassLoader = Java.use("dalvik.system.DexClassLoader");
        DexClassLoader.$init.implementation = function (dexPath, optimizedDir, libraryPath, parent) {
            var entry = {
                loader: "DexClassLoader",
                dex_path: dexPath,
                optimized_dir: optimizedDir,
                timestamp: new Date().toISOString()
            };
            results.dex_loads.push(entry);
            send(JSON.stringify({
                type: "dynamic_code_load",
                loader: "DexClassLoader",
                dex_path: dexPath,
                severity: "HIGH"
            }));
            return this.$init(dexPath, optimizedDir, libraryPath, parent);
        };
    } catch (e) {}
}

// ─── InMemoryDexClassLoader hook (API 26+) ────────────────────────────────
function hookInMemoryDexClassLoader() {
    try {
        var InMemoryDexClassLoader = Java.use("dalvik.system.InMemoryDexClassLoader");
        InMemoryDexClassLoader.$init.overload("java.nio.ByteBuffer", "java.lang.ClassLoader").implementation = function (buffer, parent) {
            var size = buffer.capacity();
            var entry = {
                loader: "InMemoryDexClassLoader",
                payload_size_bytes: size,
                timestamp: new Date().toISOString()
            };
            results.dex_loads.push(entry);
            send(JSON.stringify({
                type: "dynamic_code_load",
                loader: "InMemoryDexClassLoader",
                payload_size_bytes: size,
                severity: "CRITICAL",
                note: "Payload never written to disk — in-memory execution"
            }));
            return this.$init(buffer, parent);
        };
    } catch (e) {}
}

// ─── PathClassLoader hook ─────────────────────────────────────────────────
function hookPathClassLoader() {
    try {
        var PathClassLoader = Java.use("dalvik.system.PathClassLoader");
        PathClassLoader.$init.overload("java.lang.String", "java.lang.ClassLoader").implementation = function (path, parent) {
            if (path && !path.includes("/framework/") && !path.includes("/system/")) {
                results.dex_loads.push({ loader: "PathClassLoader", path: path });
                send(JSON.stringify({ type: "dynamic_code_load", loader: "PathClassLoader", path: path }));
            }
            return this.$init(path, parent);
        };
    } catch (e) {}
}

// ─── Class.forName reflection hook ───────────────────────────────────────
function hookClassForName() {
    try {
        var Class = Java.use("java.lang.Class");
        Class.forName.overload("java.lang.String").implementation = function (className) {
            // Only log reflection calls to non-system classes that look suspicious
            if (!className.startsWith("java.") &&
                !className.startsWith("android.") &&
                !className.startsWith("com.google.") &&
                !className.startsWith("kotlin.")) {
                results.reflection_calls.push({ class_name: className });
                send(JSON.stringify({ type: "reflection_class_load", class_name: className }));
            }
            return this.forName(className);
        };
    } catch (e) {}
}

// ─── File download monitoring (.dex, .apk, .jar) ─────────────────────────
function hookFileDownload() {
    try {
        var FileOutputStream = Java.use("java.io.FileOutputStream");
        FileOutputStream.$init.overload("java.lang.String").implementation = function (path) {
            if (path && (
                path.endsWith(".dex") ||
                path.endsWith(".apk") ||
                path.endsWith(".jar") ||
                path.endsWith(".so")
            )) {
                results.downloaded_payloads.push({ path: path, timestamp: new Date().toISOString() });
                send(JSON.stringify({
                    type: "payload_file_write",
                    path: path,
                    severity: "HIGH",
                    note: "Suspicious payload file being written to disk"
                }));
            }
            return this.$init(path);
        };
    } catch (e) {}
}

// ─── Runtime.exec hook — shell command execution ──────────────────────────
function hookRuntimeExec() {
    try {
        var Runtime = Java.use("java.lang.Runtime");
        Runtime.exec.overload("java.lang.String").implementation = function (cmd) {
            send(JSON.stringify({
                type: "shell_exec",
                command: cmd,
                severity: "HIGH",
                note: "Malware executing shell command"
            }));
            results.dex_loads.push({ type: "shell_exec", command: cmd });
            return this.exec(cmd);
        };
        Runtime.exec.overload("[Ljava.lang.String;").implementation = function (cmds) {
            var cmdArr = Java.use("java.util.Arrays").toString(cmds);
            send(JSON.stringify({ type: "shell_exec", command: cmdArr, severity: "HIGH" }));
            return this.exec(cmds);
        };
    } catch (e) {}
}

Java.perform(function () {
    hookDexClassLoader();
    hookInMemoryDexClassLoader();
    hookPathClassLoader();
    hookClassForName();
    hookFileDownload();
    hookRuntimeExec();
    send(JSON.stringify({ type: "init", script: "dex_loader_monitor", status: "loaded" }));
});
