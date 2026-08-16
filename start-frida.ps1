# ─── BOI Dynamic Analysis — Daily Startup Script ─────────────────────────
# Run this once after starting your Android Emulator each day.
# Usage:  powershell -ExecutionPolicy Bypass -File .\start-frida.ps1
# ──────────────────────────────────────────────────────────────────────────

$ErrorActionPreference = "SilentlyContinue"

Write-Host "`n=== BOI Frida Startup ===" -ForegroundColor Cyan

# ── Step 1: Find the emulator device ──
Write-Host "`n[1/5] Checking emulator..." -ForegroundColor Yellow

# Disconnect stale TCP connections (not the emulator itself)
$staleDevices = adb devices 2>&1 | Out-String
# Only disconnect IP-based connections like 127.0.0.1:5555 that cause duplicates
if ($staleDevices -match "127\.0\.0\.1:\d+\s+device") {
    adb disconnect 127.0.0.1:5555 2>&1 | Out-Null
}

$rawOutput = adb devices 2>&1 | Out-String
# Find emulator device ID (e.g., emulator-5554)
if ($rawOutput -match "(emulator-\d+)\s+device") {
    $emulator = $Matches[1]
} else {
    Write-Host "  ERROR: No Android emulator found!" -ForegroundColor Red
    Write-Host "  Start your emulator from Android Studio first." -ForegroundColor Red
    exit 1
}
Write-Host "  Found: $emulator" -ForegroundColor Green

# ── Step 2: ADB root ──
Write-Host "`n[2/5] Setting ADB root..." -ForegroundColor Yellow
adb -s $emulator root 2>&1 | Out-Null
Start-Sleep -Seconds 2
Write-Host "  ADB root OK" -ForegroundColor Green

# ── Step 3: Start frida-server ──
Write-Host "`n[3/5] Starting frida-server on emulator..." -ForegroundColor Yellow

# Kill any existing instance
adb -s $emulator shell "pkill -9 frida-server" 2>&1 | Out-Null
Start-Sleep -Seconds 1

# Check if binary exists on emulator
$fridaCheck = adb -s $emulator shell "ls /data/local/tmp/frida-server" 2>&1 | Out-String
if ($fridaCheck -match "No such file") {
    Write-Host "  frida-server not found on emulator. Pushing..." -ForegroundColor Yellow
    if (Test-Path ".\frida-server") {
        adb -s $emulator push .\frida-server /data/local/tmp/frida-server
        adb -s $emulator shell "chmod 755 /data/local/tmp/frida-server"
    } else {
        Write-Host "  ERROR: frida-server binary not found in project root!" -ForegroundColor Red
        Write-Host "  Download matching version from: https://github.com/frida/frida/releases" -ForegroundColor Red
        exit 1
    }
}

# Start frida-server in background
Start-Process -NoNewWindow -FilePath "adb" -ArgumentList "-s", $emulator, "shell", "/data/local/tmp/frida-server -l 0.0.0.0:27042"
Start-Sleep -Seconds 3

$fridaProc = adb -s $emulator shell "ps -e" 2>&1 | Out-String
if ($fridaProc -match "frida-server") {
    Write-Host "  frida-server running" -ForegroundColor Green
} else {
    # -D flag may not be supported in all versions, try background fork
    Start-Process -NoNewWindow -FilePath "adb" -ArgumentList "-s", $emulator, "shell", "/data/local/tmp/frida-server -l 0.0.0.0:27042 &"
    Start-Sleep -Seconds 3
    $fridaProc2 = adb -s $emulator shell "ps -e" 2>&1 | Out-String
    if ($fridaProc2 -match "frida-server") {
        Write-Host "  frida-server running (background)" -ForegroundColor Green
    } else {
        Write-Host "  WARNING: frida-server may not have started. Try manually:" -ForegroundColor Yellow
        Write-Host "    adb -s $emulator shell `"/data/local/tmp/frida-server -l 0.0.0.0:27042 &`"" -ForegroundColor Gray
    }
}

# ── Step 4: ADB port forwarding ──
Write-Host "`n[4/5] Setting up port forwarding..." -ForegroundColor Yellow
adb -s $emulator forward --remove-all 2>&1 | Out-Null
adb -s $emulator forward tcp:27043 tcp:27042 2>&1 | Out-Null

$fwdList = adb forward --list 2>&1 | Out-String
if ($fwdList -match "27043") {
    Write-Host "  Port forward: host:27043 -> emulator:27042" -ForegroundColor Green
} else {
    Write-Host "  WARNING: Port forwarding may have failed" -ForegroundColor Yellow
}

# ── Step 5: Verify Docker container can reach the emulator ──
Write-Host "`n[5/5] Verifying Docker container connectivity..." -ForegroundColor Yellow
$dockerAdb = docker compose -f infra/docker-compose.yml exec dynamic-analysis adb connect host.docker.internal:5555 2>&1 | Out-String
if ($dockerAdb -match "connected") {
    Write-Host "  Container -> Emulator ADB: OK" -ForegroundColor Green
} else {
    Write-Host "  WARNING: Container ADB connection failed" -ForegroundColor Yellow
    Write-Host "  Make sure dynamic-analysis container is running" -ForegroundColor Gray
}

$dockerFrida = docker compose -f infra/docker-compose.yml exec dynamic-analysis frida-ps -H host.docker.internal:27043 2>&1 | Out-String
if ($dockerFrida -match "PID") {
    Write-Host "  Container -> Frida: OK" -ForegroundColor Green
} else {
    Write-Host "  WARNING: Container cannot reach frida-server" -ForegroundColor Yellow
}

Write-Host "`n=== Ready! Dynamic analysis with Frida is active ===" -ForegroundColor Cyan
Write-Host "  Upload APKs through the frontend and Frida will instrument them.`n" -ForegroundColor Gray
