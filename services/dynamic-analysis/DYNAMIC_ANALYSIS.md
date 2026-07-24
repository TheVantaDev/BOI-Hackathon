# Dynamic Analysis Progress (22 July 2026)

## Completed

- Created branch: feature/dynamic-analysis
- Installed Android Studio Emulator.
- Created AVD: BOI-Sandbox.
- Enabled virtualization.
- Verified ADB connectivity.
- Installed and ran Frida server.
- Verified Frida client communication.
- Verified Docker Desktop.
- Started all project containers.
- Verified MobSF is accessible.
- Connected MobSF to Android Emulator via:
    host.docker.internal:5555

## Current Status

MobSF successfully:

- Uploads APKs.
- Performs static analysis.
- Connects to emulator.

MobSF fails during dynamic analysis because:

```text
VM's /system is not writable.
This VM cannot be used for Dynamic Analysis.
Root cause:

MobSF requires a rooted Android emulator (RootAVD or equivalent).
Standard Android Studio emulators cannot remount /system.
Verified Working Components
Emulator
adb devices

Output:

emulator-5554
localhost:5555
Frida
frida-ps -U

Successfully lists Android processes.

MobSF
http://localhost:8008

Credentials:

mobsf
mobsf

API Key:

sentinel_mobsf_key
Tomorrow's Tasks
Option 1 (Preferred)

Set up RootAVD.

Goals:

Obtain rooted emulator.
Verify:
adb root
adb remount

Expected:

remount succeeded

Then test:

SMS monitoring.
Overlay detection.
Accessibility abuse.
Dynamic DEX loading.
SSL bypass.
Crypto monitoring.
Option 2

Implement fallback pipeline.

Create:

_run_mobsf_analysis()
_run_adb_frida_analysis()

Pipeline:

APK
 ↓
ADB install
 ↓
Launch app
 ↓
Frida attach
 ↓
Run JS hooks
 ↓
Capture events
 ↓
Generate report
Remaining Deliverables
Dynamic Analysis Service.
Frida Integration.
ADB Automation.
Tcpdump Integration.
Dynamic Report Generation.
End-to-end testing.
Dashboard verification.
Test Cases
SMS Demo APK
DroidBench samples
InsecureBankv2
Damn Vulnerable Bank
OWASP MSTG Crackmes
Banking malware samples (if available)
APK with SSL pinning.
APK with Accessibility abuse.
APK using dynamic DEX loading.
APK downloading payloads at runtime.