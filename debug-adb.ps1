$x = adb devices 2>&1 | Out-String
Write-Host "RAW OUTPUT:"
Write-Host $x
Write-Host "---"
Write-Host "Contains emulator:" ($x -match "emulator")
Write-Host "Match test:" ($x -match "(emulator-\d+)")
if ($x -match "(emulator-\d+)") {
    Write-Host "FOUND:" $Matches[1]
} else {
    Write-Host "NOT FOUND"
}
