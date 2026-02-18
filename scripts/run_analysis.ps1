param(
    [Parameter(Mandatory = $true)] [string]$Bucket,
    [Parameter(Mandatory = $true)] [string]$Prefix = "",
    [string]$Region = "us-east-1"
)
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$ResultsDir = Join-Path $ProjectRoot "results"
$S3Target = "s3://$Bucket/$Prefix"
if (-not (Test-Path $ResultsDir))
{
    New-Item -ItemType Directory -Path $ResultsDir | Out-Null
}
Write-Host "----------------------------------------------" -ForegroundColor Cyan
Write-Host " PANOPTIK ORCHESTRATOR: PROJECT AEGIS        " -ForegroundColor Cyan
Write-Host "----------------------------------------------" -ForegroundColor Cyan
Write-Host "Target: $S3Target"
Write-Host "Local Results: $ResultsDir"
Write-Host "[*] Building Panoptik Image..." -ForegroundColor Gray
docker build -t panoptik-image -f "$ProjectRoot/Dockerfile" "$ProjectRoot"
docker run --rm `
    -v "${ResultsDir}:/data/results" `
    -e AWS_ACCESS_KEY_ID="$( $env:AWS_ACCESS_KEY_ID )" `
    -e AWS_SECRET_ACCESS_KEY="$( $env:AWS_SECRET_ACCESS_KEY )" `
    -e AWS_DEFAULT_REGION="$Region" `
    panoptik-image `
    "$S3Target" --cleanup --max-size 5
if ($LASTEXITCODE -eq 0)
{
    Write-Host "`n[+] Analysis batch complete. Check 'results' folder." -ForegroundColor Green
}
else
{
    Write-Host "`n[!] The analysis container failed or exited with an error." -ForegroundColor Red
}