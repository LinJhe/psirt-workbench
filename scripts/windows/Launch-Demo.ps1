[CmdletBinding()]
param(
    [string]$Distro = $env:PSIRT_WSL_DISTRO,
    [switch]$NoOpen,
    [switch]$NoPause
)

$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($Distro)) { $Distro = 'kali-linux' }
$ExitCode = 2
$Mutex = $null
$OwnsMutex = $false

try {
    if ($Distro -notmatch '^[A-Za-z0-9._-]+$') {
        throw 'Invalid WSL distribution name. Set PSIRT_WSL_DISTRO to an installed distribution.'
    }
    $RepositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
    $Sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $Hash = [System.BitConverter]::ToString($Sha.ComputeHash(
            [System.Text.Encoding]::UTF8.GetBytes($RepositoryRoot.ToLowerInvariant())
        )).Replace('-', '').Substring(0, 24)
    } finally { $Sha.Dispose() }
    $Mutex = New-Object System.Threading.Mutex($false, ('Local\PSIRT.Workbench.Demo.' + $Hash))
    try { $OwnsMutex = $Mutex.WaitOne(0) }
    catch [System.Threading.AbandonedMutexException] { $OwnsMutex = $true }
    if (-not $OwnsMutex) {
        Write-Host 'A launch for this demo is already in progress. Please wait for its window.'
        $ExitCode = 75
    } else {
        Write-Host '[1/3] Locating this copy inside WSL...'
        if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) {
            throw 'WSL is unavailable. Install/configure it separately; this launcher installs nothing.'
        }
        # UNC paths already identify a WSL distribution and do not need wslpath.
        if ($RepositoryRoot -match '^\\\\(?:wsl\.localhost|wsl\$)\\([^\\]+)\\(.+)$') {
            $PathDistro = $Matches[1]
            if ($PathDistro -ine $Distro) {
                throw ('This folder belongs to WSL distribution ' + $PathDistro +
                    '. Select it with -Distro or PSIRT_WSL_DISTRO.')
            }
            $LinuxRoot = '/' + $Matches[2].Replace('\', '/')
        } else {
            $Translated = @(& wsl.exe --distribution $Distro --exec wslpath -a -u $RepositoryRoot)
            if ($LASTEXITCODE -ne 0 -or $Translated.Count -ne 1) {
                throw 'Cannot translate this folder into a WSL path.'
            }
            $LinuxRoot = [string]$Translated[0]
        }
        if (-not $LinuxRoot.StartsWith('/') -or $LinuxRoot -match '[\x00-\x1f"]') {
            throw 'Unsupported project path. Use a path without control characters or double quotes.'
        }
        $DemoScript = $LinuxRoot.TrimEnd('/') + '/scripts/demo.py'
        Write-Host '[2/3] Opening the isolated synthetic workbench...'
        $Raw = @(& wsl.exe --distribution $Distro --exec python3 -B $DemoScript start)
        $WslExit = $LASTEXITCODE
        if ($WslExit -ne 0) {
            throw ('Demo startup failed with exit code ' + $WslExit + '. No old report was opened.')
        }
        try { $Receipt = ($Raw -join "`n") | ConvertFrom-Json }
        catch { throw 'The demo did not return a valid startup receipt. No report was opened.' }
        if ($Receipt.exit_code -ne 0 -or -not $Receipt.url) {
            throw 'The demo did not confirm a successful start. No report was opened.'
        }
        $Url = [System.Uri]([string]$Receipt.url)
        if ($Url.Scheme -ne 'http' -or $Url.Host -ne '127.0.0.1' -or
            $Url.Port -lt 1 -or $Url.UserInfo -or $Url.Fragment -or $Url.Query -or
            $Url.AbsolutePath -ne '/casework.html') {
            throw 'The startup receipt did not contain the expected loopback workbench URL.'
        }
        Write-Host ('[3/3] Ready: ' + $Url.AbsoluteUri)
        Write-Host 'Synthetic demo only. Company sources were not refreshed.'
        if (-not $NoOpen) { Start-Process -FilePath $Url.AbsoluteUri | Out-Null }
        $ExitCode = 0
    }
} catch {
    Write-Host ('Startup failed: ' + $_.Exception.Message) -ForegroundColor Red
    $ExitCode = 2
} finally {
    if ($OwnsMutex -and $Mutex) { $Mutex.ReleaseMutex() }
    if ($Mutex) { $Mutex.Dispose() }
    if (-not $NoPause) { [void](Read-Host 'Press Enter to close this launcher') }
}
exit $ExitCode
