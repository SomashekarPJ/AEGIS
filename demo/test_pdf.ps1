# Read clean PDF bytes and base64 encode them
$cleanPdfPath = "C:\Users\soma2\Downloads\ZYNEX-Software.pdf"
$cleanPdfBytes = [System.IO.File]::ReadAllBytes($cleanPdfPath)
$cleanPdfBase64 = [System.Convert]::ToBase64String($cleanPdfBytes)

# 1. Test running the CLEAN PDF
$bodyClean = @{
    name = "ZYNEX-Software.pdf"
    workload_path = "ZYNEX-Software.pdf"
    code_content = "data:application/pdf;base64,$cleanPdfBase64"
} | ConvertTo-Json -Depth 10

Write-Host "--- Spawning Sandbox for Clean PDF ---"
$responseClean = Invoke-RestMethod -Uri "http://localhost:8080/api/sandbox/run" -Method Post -Body $bodyClean -ContentType "application/json"
$cleanId = $responseClean.id
Write-Host "Spawned Clean Sandbox ID: $cleanId"
Write-Host "Initial Risk Score: $($responseClean.risk_score), Status: $($responseClean.status)"

# 2. Test running the MALICIOUS PDF (same content but renamed to trigger filename scan)
$bodyMalicious = @{
    name = "malware_threat_test.pdf"
    workload_path = "malware_threat_test.pdf"
    code_content = "data:application/pdf;base64,$cleanPdfBase64"
} | ConvertTo-Json -Depth 10

Write-Host "`n--- Spawning Sandbox for Malicious PDF ---"
$responseMalicious = Invoke-RestMethod -Uri "http://localhost:8080/api/sandbox/run" -Method Post -Body $bodyMalicious -ContentType "application/json"
$maliciousId = $responseMalicious.id
Write-Host "Spawned Malicious Sandbox ID: $maliciousId"
Write-Host "Initial Risk Score: $($responseMalicious.risk_score), Status: $($responseMalicious.status)"

# Wait for 10 seconds for telemetry and attacks to run and trigger mitigation
Write-Host "`nWaiting 10 seconds for threat scan events and defenses to trigger..."
Start-Sleep -Seconds 10

# 3. Retrieve status and risk score for Clean Sandbox
$sandboxes = Invoke-RestMethod -Uri "http://localhost:8080/api/sandboxes" -Method Get
$cleanInfo = $sandboxes | Where-Object { $_.id -eq $cleanId }
Write-Host "`n--- Clean Sandbox Status ---"
Write-Host "ID: $($cleanInfo.id)"
Write-Host "Status: $($cleanInfo.status)"
Write-Host "Risk Score: $($cleanInfo.risk_score)"
Write-Host "Violations Count: $($cleanInfo.violations_count)"

# 4. Retrieve status and risk score for Malicious Sandbox
$malInfo = $sandboxes | Where-Object { $_.id -eq $maliciousId }
Write-Host "`n--- Malicious Sandbox Status ---"
Write-Host "ID: $($malInfo.id)"
Write-Host "Status: $($malInfo.status)"
Write-Host "Risk Score: $($malInfo.risk_score)"
Write-Host "Violations Count: $($malInfo.violations_count)"

# 5. Retrieve Logs for Clean Sandbox
$cleanLogs = Invoke-RestMethod -Uri "http://localhost:8080/api/logs?sandbox_id=$cleanId" -Method Get
Write-Host "`n--- Clean Sandbox Log Audit ---"
$cleanLogs | ForEach-Object { Write-Host "[$($_.level)] [$($_.action)] $($_.message)" }

# 6. Retrieve Logs for Malicious Sandbox
$malLogs = Invoke-RestMethod -Uri "http://localhost:8080/api/logs?sandbox_id=$maliciousId" -Method Get
Write-Host "`n--- Malicious Sandbox Log Audit ---"
$malLogs | ForEach-Object { Write-Host "[$($_.level)] [$($_.action)] $($_.message)" }
