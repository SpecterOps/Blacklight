# Host wrapper: build Scout Windows/Linux matrix with Docker only.
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoDir = (Resolve-Path (Join-Path $ScriptDir "..")).Path
$Image = if ($env:SCOUT_BUILD_IMAGE) { $env:SCOUT_BUILD_IMAGE } else { "blacklight-scout-build" }
$Docker = if ($env:DOCKER) { $env:DOCKER } else { "docker" }

if (-not (Get-Command $Docker -ErrorAction SilentlyContinue)) {
    Write-Error "Docker is required ($Docker not found on PATH)."
}

Set-Location $RepoDir
& $Docker build -t $Image -f blacklight-scout/Dockerfile blacklight-scout
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& $Docker run --rm -v "${RepoDir}:/src" -w /src $Image
exit $LASTEXITCODE
