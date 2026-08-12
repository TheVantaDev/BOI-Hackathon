# setup_emulator.ps1
# One-time setup script for Android AVD (emulator) on Windows for MobSF Dynamic Analysis
# Run this ONCE in PowerShell as Administrator before starting the Docker stack.
#
# Prerequisites: Android Studio installed (provides sdkmanager, avdmanager, emulator)
# Download: https://developer.android.com/studio

param(
    [string]$AvdName    = "Sentinel_AVD",
    [string]$SystemImage = "system-images;android-30;google_apis;x86_64",
    [string]$Device     = "pixel_4",
    [int]   $AdbPort   = 5555
)

Write-Host "=== BOI Cognidroid - Android Emulator Setup ===" -ForegroundColor Cyan
Write-Host ""

# ─── Locate Android SDK ───────────────────────────────────────────────────────
$ANDROID_HOME = $env:ANDROID_HOME
if (-not $ANDROID_HOME) {
    $ANDROID_HOME = "$env:LOCALAPPDATA\Android\Sdk"
}
if (-not (Test-Path $ANDROID_HOME)) {
    Write-Host "ERROR: Android SDK not found at $ANDROID_HOME" -ForegroundColor Red
    Write-Host "Install Android Studio from https://developer.android.com/studio" -ForegroundColor Yellow
    Write-Host "Then set ANDROID_HOME environment variable to your SDK path." -ForegroundColor Yellow
    exit 1
}

$sdkmanager  = "$ANDROID_HOME\cmdline-tools\latest\bin\sdkmanager.bat"
$avdmanager  = "$ANDROID_HOME\cmdline-tools\latest\bin\avdmanager.bat"
$emulator    = "$ANDROID_HOME\emulator\emulator.exe"
$adb         = "$ANDROID_HOME\platform-tools\adb.exe"

# Fallback paths for older SDK layouts
if (-not (Test-Path $sdkmanager)) { $sdkmanager = "$ANDROID_HOME\tools\bin\sdkmanager.bat" }
if (-not (Test-Path $avdmanager))  { $avdmanager  = "$ANDROID_HOME\tools\bin\avdmanager.bat" }

foreach ($tool in @($sdkmanager, $avdmanager, $emulator, $adb)) {
    if (-not (Test-Path $tool)) {
        Write-Host "ERROR: Required tool not found: $tool" -ForegroundColor Red
        Write-Host "Make sure Android Studio SDK is fully installed with emulator tools." -ForegroundColor Yellow
        exit 1
    }
}

Write-Host "Android SDK found at: $ANDROID_HOME" -ForegroundColor Green
Write-Host ""

# ─── Install system image ─────────────────────────────────────────────────────
Write-Host "Step 1: Installing Android system image ($SystemImage)..." -ForegroundColor Yellow
Write-Host "        This may take several minutes on first run." -ForegroundColor Gray
& $sdkmanager --install $SystemImage "platform-tools" "emulator" 2>&1 | Write-Host
if ($LASTEXITCODE -ne 0) {
    Write-Host "WARNING: sdkmanager returned non-zero exit. Continuing anyway..." -ForegroundColor Yellow
}
Write-Host "System image installed." -ForegroundColor Green
Write-Host ""

# ─── Create AVD ───────────────────────────────────────────────────────────────
Write-Host "Step 2: Creating AVD '$AvdName'..." -ForegroundColor Yellow

# Check if AVD already exists
$existingAvds = & $avdmanager list avd 2>&1
if ($existingAvds -match $AvdName) {
    Write-Host "AVD '$AvdName' already exists — skipping creation." -ForegroundColor Green
} else {
    echo "no" | & $avdmanager create avd `
        --name $AvdName `
        --package $SystemImage `
        --device $Device `
        --force 2>&1 | Write-Host

    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: AVD creation failed." -ForegroundColor Red
        exit 1
    }
    Write-Host "AVD '$AvdName' created." -ForegroundColor Green
}
Write-Host ""

# ─── Start emulator ───────────────────────────────────────────────────────────
Write-Host "Step 3: Starting emulator '$AvdName'..." -ForegroundColor Yellow
Write-Host "        The emulator window will open. Wait for it to fully boot." -ForegroundColor Gray

$emulatorArgs = @(
    "-avd", $AvdName,
    "-no-snapshot-save",
    "-no-audio",
    "-gpu", "auto"
)

# Start emulator in background
$emulatorProcess = Start-Process -FilePath $emulator -ArgumentList $emulatorArgs -PassThru -WindowStyle Normal
Write-Host "Emulator started (PID: $($emulatorProcess.Id))" -ForegroundColor Green
Write-Host ""

# ─── Wait for emulator to boot ────────────────────────────────────────────────
Write-Host "Step 4: Waiting for emulator to boot (this takes 60-120 seconds)..." -ForegroundColor Yellow

$timeout = 180
$elapsed = 0
$booted  = $false

while ($elapsed -lt $timeout) {
    Start-Sleep -Seconds 5
    $elapsed += 5
    $bootStatus = & $adb shell getprop sys.boot_completed 2>&1
    if ($bootStatus -match "1") {
        $booted = $true
        break
    }
    Write-Host "  Waiting... ($elapsed/$timeout s)" -ForegroundColor Gray
}

if (-not $booted) {
    Write-Host "WARNING: Emulator did not report boot within ${timeout}s." -ForegroundColor Yellow
    Write-Host "         Try running the ADB commands below manually after it finishes booting." -ForegroundColor Yellow
} else {
    Write-Host "Emulator booted successfully!" -ForegroundColor Green
}
Write-Host ""

# ─── Enable ADB over TCP ─────────────────────────────────────────────────────
Write-Host "Step 5: Enabling ADB over TCP (port $AdbPort)..." -ForegroundColor Yellow
& $adb tcpip $AdbPort 2>&1 | Write-Host

# Give ADB a moment to switch to TCP mode
Start-Sleep -Seconds 2

# Connect to verify
& $adb connect "127.0.0.1:$AdbPort" 2>&1 | Write-Host

# Verify connection
$devices = & $adb devices 2>&1
Write-Host ""
Write-Host "Connected ADB devices:" -ForegroundColor Cyan
$devices | Write-Host
Write-Host ""

# ─── Root the emulator (required for Frida server) ────────────────────────────
Write-Host "Step 6: Rooting emulator (required for Frida)..." -ForegroundColor Yellow
& $adb root 2>&1 | Write-Host
Start-Sleep -Seconds 2
& $adb connect "127.0.0.1:$AdbPort" 2>&1 | Write-Host
Write-Host ""

# ─── Summary ─────────────────────────────────────────────────────────────────
Write-Host "=== Setup Complete ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "Emulator '$AvdName' is running and connected via ADB on port $AdbPort." -ForegroundColor Green
Write-Host ""
Write-Host "Docker Compose will connect MobSF to the emulator via:" -ForegroundColor White
Write-Host "  MOBSF_ANALYZER_IDENTIFIER=host.docker.internal:$AdbPort" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next steps:" -ForegroundColor White
Write-Host "  1. Make sure infra/.env has: ANDROID_EMULATOR_PORT=$AdbPort" -ForegroundColor Gray
Write-Host "  2. Start the stack: cd infra && docker compose up -d" -ForegroundColor Gray
Write-Host "  3. Open MobSF at http://localhost:8008 and check Dynamic Analyzer" -ForegroundColor Gray
Write-Host "     -> 'Connected Devices' should show the emulator" -ForegroundColor Gray
Write-Host ""
Write-Host "IMPORTANT: Keep the emulator running while using dynamic analysis." -ForegroundColor Yellow
Write-Host "           The emulator PID is: $($emulatorProcess.Id)" -ForegroundColor Gray
Write-Host ""
Write-Host "To stop the emulator later:" -ForegroundColor White
Write-Host "  Stop-Process -Id $($emulatorProcess.Id)" -ForegroundColor Gray
