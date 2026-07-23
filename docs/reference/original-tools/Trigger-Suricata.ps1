<#
.SYNOPSIS
  Generate benign traffic that trips a Suricata v7 signature on Windows, to
  validate detection/logging (and IPS drop behavior) end to end.

  Nothing here is an actual exploit -- each mode sends a harmless canary string
  or a benign URI that a well-known rule matches on.

.EXAMPLE
  # Run from an elevated (Administrator) PowerShell:
  .\Trigger-Suricata.ps1 testmyids    # trip ET/GPL SID 2100498 (needs ET Open ruleset)
  .\Trigger-Suricata.ps1 local        # add a LOCAL test rule + trip it (ruleset-independent)
  .\Trigger-Suricata.ps1 watch        # tail alerts from eve.json
#>
[CmdletBinding()]
param(
  [Parameter(Position=0)]
  [ValidateSet('testmyids','local','watch')]
  [string]$Mode = 'watch',

  [string]$SuricataRoot = 'C:\Program Files\Suricata',
  [string]$ServiceName  = 'Suricata',
  [string]$Target       = 'http://example.com/suricata-self-test-9000001'
)

$ErrorActionPreference = 'Stop'
$Eve        = Join-Path $SuricataRoot 'log\eve.json'
$LocalRules = Join-Path $SuricataRoot 'rules\local.rules'
$Sid        = '9000001'

function Show-Alerts {
  Write-Host ">> Watching $Eve for alerts (Ctrl-C to stop) ..."
  if (-not (Test-Path $Eve)) { throw "eve.json not found at $Eve (set -SuricataRoot)" }
  Get-Content -Path $Eve -Wait -Tail 0 | ForEach-Object {
    try { $o = $_ | ConvertFrom-Json } catch { return }
    if ($o.event_type -eq 'alert') {
      $act = if ($o.alert.action) { $o.alert.action } else { 'alert' }
      "{0}  sid={1}  {2}  {3}  {4}:{5}->{6}:{7}" -f `
        $o.timestamp, $o.alert.signature_id, $act, $o.alert.signature,
        $o.src_ip, $o.src_port, $o.dest_ip, $o.dest_port
    }
  }
}

switch ($Mode) {

  'testmyids' {
    # testmyids.org returns exactly "uid=0(root) gid=0(root) groups=0(root)",
    # which trips SID 2100498 "GPL ATTACK_RESPONSE id check returned root".
    # Requires the traffic to cross the interface Suricata is sniffing via npcap.
    Write-Host ">> Requesting testmyids canary (trips SID 2100498) ..."
    try   { Invoke-WebRequest -UseBasicParsing -UserAgent 'SuricataSelfTest' `
              -Uri 'http://testmynids.org/uid/index.html' | Out-Null }
    catch { Invoke-WebRequest -UseBasicParsing -UserAgent 'SuricataSelfTest' `
              -Uri 'http://testmyids.com/uid/index.html'  | Out-Null }
    Write-Host ">> Sent. Check alerts:  .\Trigger-Suricata.ps1 watch"
  }

  'local' {
    # Ruleset-independent: install our own alert rule, reload, then trip it.
    $rule = 'alert http any any -> any any (msg:"LOCAL Suricata self-test trigger"; ' +
            'flow:established,to_server; http.method; content:"GET"; http.uri; ' +
            "content:`"/suricata-self-test-9000001`"; nocase; classtype:not-suspicious; " +
            "sid:$Sid; rev:1;)"

    if (-not (Test-Path $LocalRules) -or -not (Select-String -Path $LocalRules -SimpleMatch "sid:$Sid" -Quiet)) {
      Write-Host ">> Adding LOCAL test rule (sid:$Sid) to $LocalRules ..."
      Add-Content -Path $LocalRules -Value $rule
    }

    # Windows Suricata has no reliable live socket reload -- restart the service.
    Write-Host ">> Restarting '$ServiceName' service to load the rule ..."
    Restart-Service -Name $ServiceName
    Start-Sleep -Seconds 3

    Write-Host ">> Generating matching request to $Target ..."
    try { Invoke-WebRequest -UseBasicParsing -Uri $Target | Out-Null } catch { }
    Write-Host ">> Sent. Check alerts:  .\Trigger-Suricata.ps1 watch"
  }

  'watch' { Show-Alerts }
}
