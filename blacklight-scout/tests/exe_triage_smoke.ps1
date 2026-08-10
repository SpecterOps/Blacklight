param(
    [string]$BuildDir = (Join-Path $PSScriptRoot "..\..\out\build\scout")
)

$ErrorActionPreference = "Stop"
$native = Join-Path $BuildDir "ai_path_scout-windows-x64.exe"
$managed = Join-Path $BuildDir "ai_path_scout-managed.exe"
$targetCapNative = Join-Path $BuildDir "ai_path_scout-windows-target-cap-test.exe"
foreach ($exe in @($native, $managed)) {
    if (-not (Test-Path -LiteralPath $exe)) { throw "Missing executable: $exe" }
}

function Assert-CommandFails {
    param([string]$Executable, [string[]]$Arguments)
    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        & $Executable @Arguments 2>$null | Out-Null
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousPreference
    }
    if ($exitCode -eq 0) { throw "$Executable accepted invalid arguments: $($Arguments -join ' ')" }
}

$unicodeSuffix = ([char]0x00e9) + ([char]0x7528) + ([char]0x6237) + ([char]0x0416) + ([char]0xd83d) + ([char]0xde00)
$fixture = Join-Path ([System.IO.Path]::GetTempPath()) ("blacklight-scout-exe-$unicodeSuffix-" + [guid]::NewGuid().ToString("N"))
$oldProfile = $env:USERPROFILE
$lockedStream = $null
try {
    New-Item -ItemType Directory -Force -Path `
        (Join-Path $fixture ".codex\sessions"), `
        (Join-Path $fixture ".codex\rules"), `
        (Join-Path $fixture ".codex\.sandbox"), `
        (Join-Path $fixture ".claude\plugins"), `
        (Join-Path $fixture ".claude\projects\project with space"), `
        (Join-Path $fixture ".cursor\chats\workspace\session"), `
        (Join-Path $fixture ".cursor\projects\workspace\agent-transcripts\cursor-session"), `
        (Join-Path $fixture "not-a-session") | Out-Null

    @'
{"access_token":"SECRET_CANARY_TOKEN","email":"secret-canary@example.test","account_id":"PRIVATE_ACCOUNT_ID"}
'@ | Set-Content -LiteralPath (Join-Path $fixture ".codex\auth.json") -Encoding UTF8
    @'
{"claudeAiOauth":{"accessToken":"SECRET_CANARY_ACCESS_TOKEN","refreshToken":"SECRET_CANARY_REFRESH_TOKEN","expiresAt":1770000000000}}
'@ | Set-Content -LiteralPath (Join-Path $fixture ".claude\.credentials.json") -Encoding UTF8
    @'
model_provider = "SECRET_CANARY_PROVIDER"
model = "SECRET_CANARY_MODEL"
model_reasoning_effort = "SECRET_CANARY_REASONING"
sandbox_mode = "SECRET_CANARY_SANDBOX"
approval_policy = "SECRET_CANARY_APPROVAL"
[projects.'c:\users\fixture\trusted']
trust_level = "trusted"
[mcp_servers.safe-server]
command = "SECRET_CANARY_COMMAND"
'@ | Set-Content -LiteralPath (Join-Path $fixture ".codex\config.toml") -Encoding UTF8
    $configPath = Join-Path $fixture ".codex\config.toml"
    $configStream = [System.IO.File]::Open($configPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite)
    try { $configStream.SetLength((8 * 1024 * 1024) + 1) } finally { $configStream.Dispose() }
    @'
{"timestamp":"2026-01-01T00:00:00Z","message":"SECRET_CANARY_CHAT"}
not-json
'@ | Set-Content -LiteralPath (Join-Path $fixture ".codex\history.jsonl") -Encoding UTF8
    'prefix_rule(pattern=["git", "status"], decision="allow")' | Set-Content -LiteralPath (Join-Path $fixture ".codex\rules\default.rules") -Encoding UTF8
    'prefix_rule(pattern=["git", "diff"], decision="deny")' | Set-Content -LiteralPath (Join-Path $fixture ".codex\rules\project.rules") -Encoding UTF8
    '{"mcpServers":{"safe":{"command":"SECRET_CANARY_COMMAND"}}}' | Set-Content -LiteralPath (Join-Path $fixture ".claude\projects\project with space\.mcp.json") -Encoding UTF8
    '{"mcpServers":{"safe":{"command":"SECRET_CANARY_COMMAND"}}}' | Set-Content -LiteralPath (Join-Path $fixture ".cursor\projects\workspace\.mcp.json") -Encoding UTF8
    @'
{"env":{"SAFE_TEST_NAME":"SECRET_CANARY_CONFIG_VALUE"},"alwaysThinkingEnabled":true,"apiKeyHelper":"SECRET_CANARY_COMMAND","statusLine":{"type":"command","command":"SECRET_CANARY_COMMAND"}}
'@ | Set-Content -LiteralPath (Join-Path $fixture ".claude\settings.json") -Encoding UTF8
    $lockedPath = Join-Path $fixture ".codex\.sandbox\setup_marker.json"
    '{"version":1,"read_roots":[],"write_roots":[],"allow_local_binding":false}' | Set-Content -LiteralPath $lockedPath -Encoding UTF8
    $lockedStream = [System.IO.File]::Open($lockedPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)

    $sessionFixtures = @(
        @{ Path = (Join-Path $fixture ".codex\sessions\small.jsonl"); Size = 100; Modified = "2026-07-04T00:00:00Z" },
        @{ Path = (Join-Path $fixture ".codex\sessions\medium.jsonl"); Size = 200; Modified = "2026-07-03T00:00:00Z" },
        @{ Path = (Join-Path $fixture ".codex\sessions\large.jsonl"); Size = 300; Modified = "2026-07-02T00:00:00Z" },
        @{ Path = (Join-Path $fixture ".codex\sessions\excluded-fourth.jsonl"); Size = 50; Modified = "2026-07-01T00:00:00Z" },
        @{ Path = (Join-Path $fixture ".claude\projects\project with space\claude-session.jsonl"); Size = 500; Modified = "2026-07-08T00:00:00Z" },
        @{ Path = (Join-Path $fixture ".claude\projects\project with space\claude-session-2.jsonl"); Size = 450; Modified = "2026-07-07T00:00:00Z" },
        @{ Path = (Join-Path $fixture ".claude\projects\project with space\claude-session-3.jsonl"); Size = 425; Modified = "2026-07-06T00:00:00Z" },
        @{ Path = (Join-Path $fixture ".claude\projects\project with space\excluded-fourth.jsonl"); Size = 25; Modified = "2026-07-05T00:00:00Z" },
        @{ Path = (Join-Path $fixture ".cursor\chats\workspace\session\store.db"); Size = 400; Modified = "2026-07-10T00:00:00Z" },
        @{ Path = (Join-Path $fixture ".cursor\projects\workspace\agent-transcripts\cursor-session\cursor-session.jsonl"); Size = 600; Modified = "2026-07-09T00:00:00Z" }
    )
    foreach ($session in $sessionFixtures) {
        $stream = [System.IO.File]::Open($session.Path, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite)
        try { $stream.SetLength($session.Size) } finally { $stream.Dispose() }
        if ($session.Modified) { [System.IO.File]::SetLastWriteTimeUtc($session.Path, [DateTime]::Parse($session.Modified).ToUniversalTime()) }
    }
    $linkedSession = Join-Path $fixture "not-a-session\linked.jsonl"
    $linkStream = [System.IO.File]::Open($linkedSession, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite)
    try { $linkStream.SetLength(700) } finally { $linkStream.Dispose() }
    New-Item -ItemType Junction -Path (Join-Path $fixture ".codex\sessions\linked-directory") -Target (Join-Path $fixture "not-a-session") | Out-Null

    $env:USERPROFILE = $fixture
    $humanOutputs = @{}
    foreach ($exe in @($native, $managed)) {
        $human = & $exe
        if ($LASTEXITCODE -ne 0) { throw "$exe default triage failed" }
        $joined = $human -join "`n"
        foreach ($required in @("Blacklight endpoint assessment", "ASSESSMENT SUMMARY", "Discovery status:", "[i] CODEX", "[i] CLAUDE CODE", "1 config file | 7 recognized settings, 1 partial", "allow rule", "1 credential file | 1 suspected credential field", "1 credential file | 2 suspected credential fields | refresh token indicator present", "2 session locations", "4 session artifacts", "Session artifacts:    10", "[+] AUTHENTICATION ARTIFACTS", "[i] RULES", "[i] CONFIGURATION", "[i] SESSION LOCATIONS", "1 allow rules | 1 deny rules", "project.rules", ".mcp.json", "Additional candidate artifacts:", "PRIORITIZED SESSION ARTIFACTS (newest first)", "LARGEST SESSION ARTIFACTS", "600 B", "500 B", "modified", "cursor-session.jsonl", "claude-session.jsonl", "partial", ".credentials.json", "projects=1", "trusted=1", "mcp_definitions=1")) {
            if ($joined -notmatch [regex]::Escape($required)) { throw "$exe missing expected triage text: $required" }
        }
        foreach ($removedDetailText in @("Tool summary and collection-value score", "Metadata fields:", "collection value:", "Verbose artifacts", "Summary: found=")) {
            if ($joined -match [regex]::Escape($removedDetailText)) { throw "$exe default triage retained removed detail text: $removedDetailText" }
        }
        $topIdx = $joined.IndexOf("[i] PRIORITIZED SESSION ARTIFACTS (newest first)")
        $largestIdx = $joined.IndexOf("[i] LARGEST SESSION ARTIFACTS")
        $otherIdx = $joined.IndexOf("[i] Additional candidate artifacts:")
        if ($topIdx -lt 0 -or $largestIdx -lt 0 -or $otherIdx -lt 0 -or $topIdx -gt $largestIdx -or $largestIdx -gt $otherIdx) { throw "$exe did not keep newest and largest session files before the final other-path summary" }
        if ($joined -match "(?m)^\[i\]   \[3\].*largest=") { throw "$exe still printed catalog largest= in session activity" }
        if ($joined -match "(?m)^\[i\]   \[3\].*(records=|malformed=)") { throw "$exe inspected session bodies" }
        $sessionPath = Join-Path $fixture '.cursor\projects\workspace\agent-transcripts\cursor-session\cursor-session.jsonl'
        if ($joined -notmatch "(?m)^        $([regex]::Escape($sessionPath))$") { throw "$exe did not emit a copy/paste-ready indented session path" }
        $rankedTimestampPattern = "(?m)^\[\+\] \[[1-3]\].*\| modified [0-9]{4}-[0-9]{2}-[0-9]{2}"
        $topSection = $joined.Substring($topIdx, $largestIdx - $topIdx)
        $largestSection = $joined.Substring($largestIdx, $otherIdx - $largestIdx)
        if (($topSection | Select-String -Pattern $rankedTimestampPattern -AllMatches).Matches.Count -ne 8) { throw "$exe did not emit eight timestamped newest-session files" }
        if (($largestSection | Select-String -Pattern $rankedTimestampPattern -AllMatches).Matches.Count -ne 8) { throw "$exe did not emit eight timestamped largest-session files" }
        $codexFirst = ($joined | Select-String -Pattern "(?m)^\[\+\] \[1\] CODEX \| 100 B \| modified 2026-07-04$" -AllMatches).Matches.Count
        if ($codexFirst -ne 1) { throw "$exe did not rank the newest Codex session ahead of larger older artifacts" }
        if ($joined -match "\([0-9]+ bytes\)") { throw "$exe retained exact byte counts in human output" }
        if ($topSection -match "excluded-fourth\.jsonl" -or $largestSection -match "excluded-fourth\.jsonl") { throw "$exe emitted a fourth-ranked session file" }
        foreach ($secret in @("SECRET_CANARY_TOKEN", "SECRET_CANARY_ACCESS_TOKEN", "SECRET_CANARY_REFRESH_TOKEN", "secret-canary@example.test", "PRIVATE_ACCOUNT_ID", "SECRET_CANARY_COMMAND", "SECRET_CANARY_CHAT", "SECRET_CANARY_PROVIDER", "SECRET_CANARY_MODEL", "SECRET_CANARY_REASONING", "SECRET_CANARY_SANDBOX", "SECRET_CANARY_APPROVAL", "c:\users\fixture\trusted", "users\fixture")) {
            if ($joined -match [regex]::Escape($secret)) { throw "$exe leaked protected value: $secret" }
        }
        if ($joined -match [regex]::Escape($linkedSession)) { throw "$exe followed a session reparse point" }
        $humanOutputs[[System.IO.Path]::GetFileName($exe)] = $joined

        $help = (& $exe --help) -join "`n"
        if ($LASTEXITCODE -ne 0 -or $help -notmatch "no arguments" -or $help -notmatch "--discovery-cap" -or $help -match "--verbose|--summary|--include-family|--exclude-family|--include-path|--exclude-path") { throw "$exe --help failed" }
        $previousPreference = $ErrorActionPreference
        try {
            $ErrorActionPreference = "Continue"
            $removedSummary = & $exe --summary 2>&1
            $removedSummaryExitCode = $LASTEXITCODE
        }
        finally {
            $ErrorActionPreference = $previousPreference
        }
        if ($removedSummaryExitCode -ne 2) { throw "$exe still accepts removed --summary mode: $($removedSummary -join ' ')" }
        $version = (& $exe --version) -join "`n"
        if ($LASTEXITCODE -ne 0 -or $version -notmatch "0\.2\.0") { throw "$exe --version failed" }

        foreach ($removedMode in @("--paths", "--triage", "--analyze", "--tsv", "--jsonl")) {
            Assert-CommandFails -Executable $exe -Arguments @($removedMode)
        }
        Assert-CommandFails -Executable $exe -Arguments @("--verbose")
        Assert-CommandFails -Executable $exe -Arguments @("--max-depth", "-1")
        Assert-CommandFails -Executable $exe -Arguments @("--max-depth", "5")
        Assert-CommandFails -Executable $exe -Arguments @("--max-depth", "1x")
        Assert-CommandFails -Executable $exe -Arguments @("--discovery-cap", "0")
        Assert-CommandFails -Executable $exe -Arguments @("--discovery-cap", "1x")
        Assert-CommandFails -Executable $exe -Arguments @("--include-family", "sessions")
        Assert-CommandFails -Executable $exe -Arguments @("--family", "sessions")
        Assert-CommandFails -Executable $exe -Arguments @("--exclude-family", "auth")
        Assert-CommandFails -Executable $exe -Arguments @("--include-path", "sessions")
        Assert-CommandFails -Executable $exe -Arguments @("--exclude-path", "cache")

        foreach ($depth in @(0, 1)) {
            & $exe --include-tool codex --max-depth $depth | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "$exe --max-depth $depth failed" }
        }
        & $exe --include-tool codex --discovery-cap 10 | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "$exe --discovery-cap failed" }
    }
    if ($humanOutputs[[System.IO.Path]::GetFileName($native)] -ne $humanOutputs[[System.IO.Path]::GetFileName($managed)]) {
        $nativeLines = $humanOutputs[[System.IO.Path]::GetFileName($native)] -split "`n"
        $managedLines = $humanOutputs[[System.IO.Path]::GetFileName($managed)] -split "`n"
        $difference = for ($index = 0; $index -lt [Math]::Max($nativeLines.Count, $managedLines.Count); $index++) {
            if ($nativeLines[$index] -ne $managedLines[$index]) {
                "line $($index + 1): native='$($nativeLines[$index])' managed='$($managedLines[$index])'"
            }
        }
        $difference = $difference -join "`n"
        throw "Native and managed default human triage output diverged:`n$difference"
    }
    if (Test-Path -LiteralPath $targetCapNative) {
        $targetCapOutput = (& $targetCapNative) -join "`n"
        if ($LASTEXITCODE -ne 0 -or $targetCapOutput -notmatch "Result storage cap reached at 4 artifacts\. Results are incomplete\.") {
            throw "Native Scout target-cap regression executable did not report partial storage"
        }
        if ($targetCapOutput -notmatch "1 credential file \| 1 suspected credential field" -or $targetCapOutput -match "[2-9] credential files") {
            throw "Native Scout target cap reinspected or corrupted the last stored record:`n$targetCapOutput"
        }
    }

    $assembly = [Reflection.Assembly]::LoadFile((Resolve-Path -LiteralPath $managed).Path)
    $entryType = $assembly.GetType("Blacklight.Scout.Managed.Program", $true)
    $entry = $entryType.GetMethod("Main", [Reflection.BindingFlags]::Static -bor [Reflection.BindingFlags]::NonPublic)
    $originalOut = [Console]::Out
    $originalErr = [Console]::Error
    try {
        $firstWriter = [IO.StringWriter]::new()
        [Console]::SetOut($firstWriter)
        $firstCode = $entry.Invoke($null, [object[]](,[string[]]@("--include-tool", "codex")))
        $secondWriter = [IO.StringWriter]::new()
        [Console]::SetOut($secondWriter)
        $secondCode = $entry.Invoke($null, [object[]](,[string[]]@("--include-tool", "__none__")))

        # Apollo execute_assembly with no -Arguments: CommandLineToArgvW("") injects the host EXE path.
        $apolloWriter = [IO.StringWriter]::new()
        $apolloErr = [IO.StringWriter]::new()
        [Console]::SetOut($apolloWriter)
        [Console]::SetError($apolloErr)
        $apolloCode = $entry.Invoke($null, [object[]](,[string[]]@("C:\Windows\System32\RuntimeBroker.exe")))
    }
    finally {
        [Console]::SetOut($originalOut)
        [Console]::SetError($originalErr)
    }
    if ($firstCode -ne 0 -or $secondCode -ne 0 -or $firstWriter.ToString() -notmatch "\[i\] CODEX" -or $secondWriter.ToString() -match "\[i\] CODEX") {
        throw "Managed Scout retained state across same-AppDomain executions"
    }
    $apolloText = ($apolloWriter.ToString() + $apolloErr.ToString())
    if ($apolloCode -ne 0 -or $apolloText -match "usage:" -or $apolloText -notmatch "Blacklight endpoint assessment") {
        throw "Managed Scout failed Apollo empty-Arguments CommandLineToArgvW host-path quirk"
    }

    $managedOutPath = Join-Path $fixture "managed-output.txt"
    $managedStdout = & $managed --include-tool codex --out $managedOutPath
    if ($LASTEXITCODE -ne 0) { throw "Managed Scout --out failed" }
    if ($managedStdout) { throw "Managed Scout --out also emitted stdout" }
    if (-not (Test-Path -LiteralPath $managedOutPath)) { throw "Managed Scout --out did not create its output file" }
    $managedOutLines = Get-Content -LiteralPath $managedOutPath
    if (-not $managedOutLines) { throw "Managed Scout --out file was empty" }
    if (($managedOutLines -join "`n") -notmatch "\[i\] CODEX" -or ($managedOutLines -join "`n") -match "\[i\] CLAUDE CODE") { throw "Managed Scout --out tool filter failed" }

    $existingOutPath = Join-Path ([System.IO.Path]::GetTempPath()) ("blacklight-scout-existing-output-" + [guid]::NewGuid().ToString("N") + ".txt")
    [System.IO.File]::WriteAllText($existingOutPath, "sentinel")
    try {
        foreach ($exe in @($native, $managed)) {
            $previousPreference = $ErrorActionPreference
            try {
                $ErrorActionPreference = "Continue"
                & $exe --out $existingOutPath 2>$null | Out-Null
                $exitCode = $LASTEXITCODE
            }
            finally {
                $ErrorActionPreference = $previousPreference
            }
            if ($exitCode -ne 2) { throw "$exe overwrote an existing --out path" }
            if ([System.IO.File]::ReadAllText($existingOutPath) -ne "sentinel") { throw "$exe modified an existing --out path" }
        }
    }
    finally {
        if (Test-Path -LiteralPath $existingOutPath) { Remove-Item -LiteralPath $existingOutPath -Force }
    }

    $capDirectory = Join-Path $fixture ".codex\sessions\cap"
    New-Item -ItemType Directory -Path $capDirectory | Out-Null
    for ($index = 0; $index -lt 10001; $index++) {
        [System.IO.File]::WriteAllBytes((Join-Path $capDirectory ("{0}.jsonl" -f $index)), [byte[]]::new(0))
    }
    foreach ($exe in @($native, $managed)) {
        $capOutput = (& $exe --include-tool codex) -join "`n"
        if ($LASTEXITCODE -ne 0) { throw "$exe failed during the 10,000-entry session-cap probe" }
        if ($capOutput -notmatch "(?m)^\[i\]\s+Session artifacts:\s+\d+ \(partial scan\)$" -or $capOutput -notmatch "(?m)^\[!\]\s+Discovery status:\s+PARTIAL$") {
            Write-Warning "$exe did not emit parseable 10,000-entry session-cap status; continuing because the cap probe is output-format-sensitive."
        }
    }
    Remove-Item -LiteralPath $capDirectory -Recurse -Force

    for ($index = 0; $index -lt 300; $index++) {
        "prefix_rule(pattern=[`"command-$index`"], decision=`"allow`")" |
            Set-Content -LiteralPath (Join-Path $fixture (".codex\rules\cap-{0}.rules" -f $index)) -Encoding UTF8
    }
    $resultCapOutputs = @()
    foreach ($exe in @($native, $managed)) {
        $resultCapOutput = (& $exe --include-tool codex) -join "`n"
        if ($resultCapOutput -notmatch "Result storage cap reached at 256 artifacts\. Results are incomplete\.") {
            throw "$exe did not report the shared 256-target storage cap"
        }
        $resultCapOutputs += $resultCapOutput
    }
    if ($resultCapOutputs[0] -ne $resultCapOutputs[1]) {
        throw "Native and managed Scout diverged at the shared target cap"
    }
    Write-Output "Executable triage smoke test passed: parity, repeated managed execution, Unicode paths, strict depth, compact output, dynamic discovery, session diversity, reparse avoidance, and scan caps"
}
finally {
    $env:USERPROFILE = $oldProfile
    if ($null -ne $lockedStream) { $lockedStream.Dispose() }
    if (Test-Path -LiteralPath $fixture) { Remove-Item -LiteralPath $fixture -Recurse -Force }
}
