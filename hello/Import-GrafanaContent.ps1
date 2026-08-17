<#
.SYNOPSIS
  Imports the gold-standard dashboard set (or any Export-GrafanaContent.ps1 dashboard bundle) into a Grafana
  instance: creates folders, upserts dashboards by uid, optionally sets the home dashboard, archives superseded
  dashboards and provisions the unified alert rules.

.DESCRIPTION
  Idempotent: re-running upserts the same uids in place (Grafana keeps version history).
  Works on Windows PowerShell 5.1 and PowerShell 7. Token (service account) or username/password auth.
  Nothing is deleted, ever. -WhatIf shows the plan.

.PARAMETER Url         Grafana base URL, e.g. http://srvcre1appops01:9091
.PARAMETER Token       Service-account token (Admin role) - or use -Credential
.PARAMETER Credential  Grafana user with Admin (basic auth); e.g. (Get-Credential admin)
.PARAMETER Path        Folder containing manifest.json (gold set) OR any folder tree of *.json dashboard files
                       written by Export-GrafanaContent.ps1 / build.py. Default: .\gold-dashboards next to this script.
.PARAMETER Only        Import only these dashboard uids
.PARAMETER Exclude     Skip these dashboard uids
.PARAMETER SetHome     Dashboard uid to make the org home dashboard (gold set: gs-home)
.PARAMETER ArchiveOld  Uids of existing dashboards to MOVE into folder "_Retired - superseded" (never deleted)
.PARAMETER ImportAlertRules  Also provision alerting\gold-alert-rules.json (requires unified alerting ON)
.PARAMETER ReplaceLegacyAlertDashboards  Allow overwriting an existing dashboard that carries legacy panel alerts
.PARAMETER ReportPath  Optional CSV of what happened

.EXAMPLE
  .\Import-GrafanaContent.ps1 -Url http://srvcre1appops01:9091 -Credential (Get-Credential admin) -WhatIf
  .\Import-GrafanaContent.ps1 -Url http://srvcre1appops01:9091 -Token glsa_xxx -SetHome gs-home
  .\Import-GrafanaContent.ps1 -Url http://10.1.24.217:9091 -Token glsa_xxx -ArchiveOld OoYjJw-iz,P6vQvbLmz,o33aObLik
#>
[CmdletBinding(SupportsShouldProcess = $true, DefaultParameterSetName = 'Token')]
param(
    [Parameter(Mandatory)] [string] $Url,
    [Parameter(ParameterSetName = 'Token', Mandatory)] [string] $Token,
    [Parameter(ParameterSetName = 'Cred', Mandatory)] [pscredential] $Credential,
    [string] $Path,
    [string[]] $Only,
    [string[]] $Exclude,
    [string] $SetHome,
    [string[]] $ArchiveOld,
    [switch] $ImportAlertRules,
    [switch] $ReplaceLegacyAlertDashboards,
    [string] $ReportPath,
    [string] $Message = "gold-standard import $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
)
$ErrorActionPreference = 'Stop'
$Url = $Url.TrimEnd('/')
if (-not $Path) { $Path = Join-Path $PSScriptRoot 'gold-dashboards' }
if (-not (Test-Path $Path)) { throw "Path not found: $Path" }
$script:Version = '1.0.0'

# ---- auth + http ---------------------------------------------------------------------------
$H = @{ 'Accept' = 'application/json' }
if ($PSCmdlet.ParameterSetName -eq 'Token') { $H['Authorization'] = "Bearer $Token" }
else {
    $pair = "$($Credential.UserName):$($Credential.GetNetworkCredential().Password)"
    $H['Authorization'] = 'Basic ' + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($pair))
}
function Invoke-G {
    param([string]$Method, [string]$ApiPath, $Body, [hashtable]$ExtraHeaders, [switch]$Raw, [switch]$AllowNotFound)
    $hdr = @{} + $H; if ($ExtraHeaders) { $ExtraHeaders.GetEnumerator() | ForEach-Object { $hdr[$_.Key] = $_.Value } }
    $args = @{ Uri = "$Url$ApiPath"; Method = $Method; Headers = $hdr; TimeoutSec = 120; ErrorAction = 'Stop' }
    if ($null -ne $Body) {
        $json = if ($Body -is [string]) { $Body } else { $Body | ConvertTo-Json -Depth 100 -Compress }
        $args['Body'] = [Text.Encoding]::UTF8.GetBytes($json)
        $args['ContentType'] = 'application/json; charset=utf-8'
    }
    try {
        if ($Raw) { return (Invoke-WebRequest @args -UseBasicParsing).Content }
        return Invoke-RestMethod @args
    } catch {
        $resp = $_.Exception.Response
        $code = if ($resp) { [int]$resp.StatusCode } else { 0 }
        $detail = ''
        try {
            if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $detail = $_.ErrorDetails.Message }
            elseif ($resp -and ($resp | Get-Member -Name Content -ErrorAction SilentlyContinue)) { $detail = $resp.Content.ReadAsStringAsync().Result }
            elseif ($resp -and ($resp | Get-Member -Name GetResponseStream -ErrorAction SilentlyContinue)) { $sr = New-Object IO.StreamReader($resp.GetResponseStream()); $detail = $sr.ReadToEnd() }
        } catch {}
        if ($AllowNotFound -and $code -eq 404) { return $null }
        throw "HTTP $code $Method $ApiPath : $($detail.Substring(0, [Math]::Min(400, $detail.Length)))"
    }
}
function Read-Json([string]$file) {
    # strip BOM defensively; PS 5.1's Get-Content -Raw handles UTF-8 BOM but exports may be UTF-16
    $bytes = [IO.File]::ReadAllBytes($file)
    $text = if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) { [Text.Encoding]::Unicode.GetString($bytes) }
            else { [Text.Encoding]::UTF8.GetString($bytes) }
    return $text.TrimStart([char]0xFEFF)
}
function Get-DashboardTree($obj) {   # all panels incl. nested rows
    $out = @()
    foreach ($p in @($obj.panels)) { if ($p) { $out += $p; foreach ($c in @($p.panels)) { if ($c) { $out += $c } } } }
    return $out
}

# ---- who are we talking to -----------------------------------------------------------------
$health = Invoke-G GET '/api/health'
$org = Invoke-G GET '/api/org'
$me = try { Invoke-G GET '/api/user' } catch { $null }
$dss = @(Invoke-G GET '/api/datasources')
$prom = @($dss | Where-Object { $_.type -eq 'prometheus' })
$promDefault = $prom | Where-Object { $_.isDefault } | Select-Object -First 1
if (-not $promDefault) { $promDefault = $prom | Select-Object -First 1 }
$fs = try { Invoke-G GET '/api/frontend/settings' } catch { $null }
$unified = $false; if ($fs -and $fs.unifiedAlertingEnabled) { $unified = [bool]$fs.unifiedAlertingEnabled }
$isAdmin = ($me -and $me.isGrafanaAdmin) -or (-not $me)   # service accounts have no /api/user
Write-Host ("Grafana {0}  org '{1}'  auth {2}  unified alerting: {3}" -f $health.version, $org.name, $PSCmdlet.ParameterSetName, $unified) -ForegroundColor Cyan
if ($prom.Count -eq 0) { Write-Warning "No Prometheus datasource on this Grafana - dashboards will import but show 'datasource not found' until one exists." }
else { Write-Host ("Prometheus datasource(s): {0}   (default for `${{DS_PROMETHEUS}}: {1})" -f (($prom | ForEach-Object { $_.name }) -join ', '), $promDefault.name) -ForegroundColor DarkGray }

# ---- discover files ------------------------------------------------------------------------
$manifestFile = Join-Path $Path 'manifest.json'
$items = @()
if (Test-Path $manifestFile) {
    $man = Read-Json $manifestFile | ConvertFrom-Json
    foreach ($d in $man.dashboards) {
        $items += [pscustomobject]@{ Uid = $d.uid; Title = $d.title; FolderUid = $d.folderUid; FolderTitle = $d.folderTitle; File = (Join-Path $Path ($d.file -replace '/', [IO.Path]::DirectorySeparatorChar)) }
    }
    $folders = @($man.folders | ForEach-Object { [pscustomobject]@{ Uid = $_.uid; Title = $_.title } })
} else {
    # generic: any *.json under Path whose top-level has .dashboard (Export-GrafanaContent bundles)
    $folders = @()
    foreach ($f in Get-ChildItem -Path $Path -Recurse -Filter *.json -File) {
        try { $j = Read-Json $f.FullName | ConvertFrom-Json } catch { continue }
        if (-not $j.dashboard -or -not $j.dashboard.uid) { continue }
        $fu = $j.folderUid; $ft = $j.folderTitle
        if (-not $ft -and $j.meta -and $j.meta.folderTitle) { $ft = $j.meta.folderTitle }
        if (-not $fu -and $j.meta -and $j.meta.folderUid) { $fu = $j.meta.folderUid }
        if ($ft -eq 'General' -or -not $ft) { $fu = ''; $ft = 'General' }
        $items += [pscustomobject]@{ Uid = $j.dashboard.uid; Title = $j.dashboard.title; FolderUid = $fu; FolderTitle = $ft; File = $f.FullName }
        if ($fu -and -not ($folders | Where-Object { $_.Uid -eq $fu })) { $folders += [pscustomobject]@{ Uid = $fu; Title = $ft } }
    }
}
if ($Only)    { $Only    = @($Only    | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
if ($Exclude) { $Exclude = @($Exclude | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
if ($ArchiveOld) { $ArchiveOld = @($ArchiveOld | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
if ($Only) { $items = @($items | Where-Object { $Only -contains $_.Uid }) }
if ($Exclude) { $items = @($items | Where-Object { $Exclude -notcontains $_.Uid }) }
$needed = @($items | ForEach-Object { $_.FolderUid } | Where-Object { $_ } | Sort-Object -Unique)
$folders = @($folders | Where-Object { $needed -contains $_.Uid })
Write-Host ("{0} dashboard(s) in {1} folder(s) to import from {2}" -f $items.Count, $folders.Count, $Path)

# ---- folders -------------------------------------------------------------------------------
$existingFolders = @(Invoke-G GET '/api/folders?limit=1000')
$folderMap = @{}
foreach ($f in $folders) {
    if (-not $f.Uid) { continue }
    $ex = Invoke-G GET "/api/folders/$($f.Uid)" -AllowNotFound
    if (-not $ex) {
        # a folder with the same TITLE but different uid? reuse it rather than create a twin
        $sameTitle = $existingFolders | Where-Object { $_.title -eq $f.Title } | Select-Object -First 1
        if ($sameTitle) { Write-Host ("  folder '{0}' exists with uid {1} - reusing" -f $f.Title, $sameTitle.uid) -ForegroundColor DarkGray; $folderMap[$f.Uid] = $sameTitle.uid; continue }
        if ($PSCmdlet.ShouldProcess("folder '$($f.Title)' ($($f.Uid))", 'Create')) {
            $null = Invoke-G POST '/api/folders' @{ uid = $f.Uid; title = $f.Title }
            Write-Host ("  + folder '{0}'" -f $f.Title) -ForegroundColor Green
        }
        $folderMap[$f.Uid] = $f.Uid
    } else {
        $folderMap[$f.Uid] = $ex.uid
        if ($ex.title -ne $f.Title) {
            if ($PSCmdlet.ShouldProcess("folder $($f.Uid)", "Rename '$($ex.title)' -> '$($f.Title)'")) {
                $null = Invoke-G PUT "/api/folders/$($f.Uid)" @{ title = $f.Title; overwrite = $true }
            }
        }
    }
}

# ---- dashboards ----------------------------------------------------------------------------
$results = @()
foreach ($it in $items) {
    $raw = Read-Json $it.File
    $obj = $raw | ConvertFrom-Json
    $dash = $obj.dashboard
    if (-not $dash) { $results += [pscustomobject]@{ Uid = $it.Uid; Title = $it.Title; Folder = $it.FolderTitle; Action = 'skip'; Detail = 'no .dashboard in file' }; continue }
    $panels = Get-DashboardTree $dash
    $angular = @($panels | Where-Object { $_.type -in 'graph', 'singlestat', 'table-old', 'grafana-piechart-panel', 'grafana-worldmap-panel', 'vonage-status-panel', 'natel-discrete-panel', 'briangann-gauge-panel' })
    $legacyAlertsIncoming = @($panels | Where-Object { $_.alert })
    $existing = Invoke-G GET "/api/dashboards/uid/$($it.Uid)" -AllowNotFound
    $action = if ($existing) { 'update' } else { 'create' }
    if ($existing) {
        $exAlerts = @(Get-DashboardTree $existing.dashboard | Where-Object { $_.alert })
        if ($exAlerts.Count -gt 0 -and $legacyAlertsIncoming.Count -eq 0 -and -not $ReplaceLegacyAlertDashboards) {
            $results += [pscustomobject]@{ Uid = $it.Uid; Title = $it.Title; Folder = $it.FolderTitle; Action = 'PROTECTED'; Detail = "existing dashboard has $($exAlerts.Count) legacy panel alert(s); use -ReplaceLegacyAlertDashboards" }
            Write-Warning ("  {0}: existing has legacy alerts - not overwritten (-ReplaceLegacyAlertDashboards to force)" -f $it.Title); continue
        }
    }
    $folderUid = if ($it.FolderUid -and $folderMap.ContainsKey($it.FolderUid)) { $folderMap[$it.FolderUid] } else { $it.FolderUid }
    # build the POST body from the raw text where possible (no PowerShell JSON round-trip = no depth/precision surprises)
    $dashJson = ($dash | ConvertTo-Json -Depth 100 -Compress)
    if ($raw -match '"dashboard"\s*:') {
        # take the raw dashboard object text if the file is exactly {"dashboard":{...}, ...}
        try {
            $m = [regex]::Match($raw, '"dashboard"\s*:\s*(\{)', 'Singleline')
            if ($m.Success) {
                $start = $m.Groups[1].Index; $depth = 0; $inStr = $false; $esc = $false; $end = -1
                for ($i = $start; $i -lt $raw.Length; $i++) {
                    $ch = $raw[$i]
                    if ($inStr) { if ($esc) { $esc = $false } elseif ($ch -eq '\') { $esc = $true } elseif ($ch -eq '"') { $inStr = $false }; continue }
                    if ($ch -eq '"') { $inStr = $true } elseif ($ch -eq '{') { $depth++ } elseif ($ch -eq '}') { $depth--; if ($depth -eq 0) { $end = $i; break } }
                }
                if ($end -gt $start) { $dashJson = $raw.Substring($start, $end - $start + 1) }
            }
        } catch {}
    }
    # force id null (a source id would collide) - safe textual edit on the top-level object only
    $dashJson = [regex]::Replace($dashJson, '^\{\s*"id"\s*:\s*\d+\s*,', '{"id":null,', 1)
    $dashJson = [regex]::Replace($dashJson, '^\{\s*"id"\s*:\s*\d+\s*\}', '{"id":null}', 1)
    if ($dashJson -notmatch '^\{\s*"id"\s*:') { $dashJson = '{"id":null,' + $dashJson.Substring(1) }
    $body = '{"dashboard":' + $dashJson + ',"folderUid":' + (ConvertTo-Json $folderUid) + ',"overwrite":true,"message":' + (ConvertTo-Json $Message) + '}'
    if ($PSCmdlet.ShouldProcess("$($it.Title) [$($it.Uid)] -> folder '$($it.FolderTitle)'", $action)) {
        try {
            $r = Invoke-G POST '/api/dashboards/db' $body
            $detail = "v$($r.version) $($r.url)"
            if ($angular.Count) { $detail += " | WARNING $($angular.Count) Angular/plugin panel(s)" }
            if ($legacyAlertsIncoming.Count) { $detail += " | carries $($legacyAlertsIncoming.Count) legacy alert(s)" }
            $results += [pscustomobject]@{ Uid = $it.Uid; Title = $it.Title; Folder = $it.FolderTitle; Action = $action; Detail = $detail }
            Write-Host ("  {0,-7} {1,-34} {2}" -f $action, $it.Title, $detail) -ForegroundColor Green
        } catch {
            $err = "$_"
            if ($err -match 'folder' -and $err -match 'not found|invalid') {
                # older Grafana (folderId) or bad folder ref: retry into General
                try { $r = Invoke-G POST '/api/dashboards/db' ('{"dashboard":' + $dashJson + ',"overwrite":true,"message":' + (ConvertTo-Json $Message) + '}')
                      $results += [pscustomobject]@{ Uid = $it.Uid; Title = $it.Title; Folder = 'General (fallback)'; Action = $action; Detail = "v$($r.version) $($r.url)" }
                      Write-Warning ("  {0}: folder problem, imported into General" -f $it.Title); continue } catch { $err = "$_" }
            }
            $results += [pscustomobject]@{ Uid = $it.Uid; Title = $it.Title; Folder = $it.FolderTitle; Action = 'FAILED'; Detail = $err }
            Write-Host ("  FAILED  {0}: {1}" -f $it.Title, $err) -ForegroundColor Red
        }
    } else {
        $results += [pscustomobject]@{ Uid = $it.Uid; Title = $it.Title; Folder = $it.FolderTitle; Action = "whatif-$action"; Detail = "$($panels.Count) panels" }
    }
}

# ---- verify --------------------------------------------------------------------------------
if (-not $WhatIfPreference) {
    $bad = 0
    foreach ($r in $results | Where-Object { $_.Action -in 'create', 'update' }) {
        $chk = Invoke-G GET "/api/dashboards/uid/$($r.Uid)" -AllowNotFound
        if (-not $chk) { $bad++; Write-Warning "verify: $($r.Uid) not readable after import" }
    }
    if ($bad -eq 0) { Write-Host "verify: every imported dashboard reads back by uid" -ForegroundColor DarkGray }
}

# ---- home dashboard ------------------------------------------------------------------------
if ($SetHome) {
    if ($PSCmdlet.ShouldProcess("org preferences", "home dashboard = $SetHome")) {
        try { $null = Invoke-G PUT '/api/org/preferences' @{ homeDashboardUID = $SetHome }; Write-Host "home dashboard set to $SetHome" -ForegroundColor Green }
        catch {
            # pre-9.x: needs numeric id
            $d = Invoke-G GET "/api/dashboards/uid/$SetHome"
            $null = Invoke-G PUT '/api/org/preferences' @{ homeDashboardId = $d.dashboard.id }; Write-Host "home dashboard set to $SetHome (by id)" -ForegroundColor Green
        }
    }
}

# ---- archive superseded dashboards --------------------------------------------------------
if ($ArchiveOld) {
    $archUid = 'gs-retired'; $archTitle = '_Retired - superseded by gold standard'
    $ex = Invoke-G GET "/api/folders/$archUid" -AllowNotFound
    if (-not $ex -and $PSCmdlet.ShouldProcess("folder '$archTitle'", 'Create')) { $null = Invoke-G POST '/api/folders' @{ uid = $archUid; title = $archTitle } }
    foreach ($u in $ArchiveOld) {
        $d = Invoke-G GET "/api/dashboards/uid/$u" -AllowNotFound
        if (-not $d) { Write-Warning "archive: $u not found"; continue }
        if ($d.meta.folderUid -eq $archUid) { Write-Host "  archive: '$($d.dashboard.title)' already retired" -ForegroundColor DarkGray; continue }
        $alerts = @(Get-DashboardTree $d.dashboard | Where-Object { $_.alert })
        if ($PSCmdlet.ShouldProcess("'$($d.dashboard.title)' [$u]", "Move to '$archTitle'")) {
            $null = Invoke-G POST '/api/dashboards/db' @{ dashboard = $d.dashboard; folderUid = $archUid; overwrite = $true; message = 'retired: superseded by gold-standard set' }
            $note = if ($alerts.Count) { " (NOTE: carries $($alerts.Count) legacy alert(s) - they keep evaluating until unified alerting cutover)" } else { '' }
            Write-Host ("  archived '{0}'{1}" -f $d.dashboard.title, $note) -ForegroundColor Yellow
            $results += [pscustomobject]@{ Uid = $u; Title = $d.dashboard.title; Folder = $archTitle; Action = 'archived'; Detail = $note.Trim() }
        }
    }
}

# ---- unified alert rules -------------------------------------------------------------------
if ($ImportAlertRules) {
    $rulesFile = Join-Path $Path 'alerting\gold-alert-rules.json'
    if (-not (Test-Path $rulesFile)) { $rulesFile = Join-Path (Split-Path $Path -Parent) 'gold-dashboards\alerting\gold-alert-rules.json' }
    if (-not (Test-Path $rulesFile)) { Write-Warning "alert rules file not found ($rulesFile)" }
    elseif (-not $unified) { Write-Warning "unified alerting is OFF on this Grafana - alert rules NOT imported (enable [unified_alerting] first; legacy alert dashboards stay in charge until then)" }
    elseif (-not $promDefault) { Write-Warning "no Prometheus datasource - alert rules need one" }
    else {
        $rules = (Read-Json $rulesFile | ConvertFrom-Json)
        $rulesJson = Read-Json $rulesFile
        $folderUid = if ($folderMap.ContainsKey('gs-alerting')) { $folderMap['gs-alerting'] } else { 'gs-alerting' }
        $existingRules = @(Invoke-G GET '/api/v1/provisioning/alert-rules')
        foreach ($rule in $rules) {
            $j = ($rule | ConvertTo-Json -Depth 50 -Compress) -replace '\$\{DS_PROMETHEUS\}', $promDefault.uid -replace '"folderUID"\s*:\s*"[^"]*"', ('"folderUID":"' + $folderUid + '"')
            $exists = $existingRules | Where-Object { $_.uid -eq $rule.uid }
            if ($PSCmdlet.ShouldProcess("alert rule '$($rule.title)'", $(if ($exists) { 'update' } else { 'create' }))) {
                try {
                    if ($exists) { $null = Invoke-G PUT "/api/v1/provisioning/alert-rules/$($rule.uid)" $j @{ 'X-Disable-Provenance' = 'true' } }
                    else { $null = Invoke-G POST '/api/v1/provisioning/alert-rules' $j @{ 'X-Disable-Provenance' = 'true' } }
                    Write-Host ("  rule {0,-6} {1}" -f $(if ($exists) { 'update' } else { 'create' }), $rule.title) -ForegroundColor Green
                    $results += [pscustomobject]@{ Uid = $rule.uid; Title = $rule.title; Folder = 'alert rule'; Action = $(if ($exists) { 'update' } else { 'create' }); Detail = $rule.ruleGroup }
                } catch { Write-Host ("  rule FAILED {0}: {1}" -f $rule.title, $_) -ForegroundColor Red; $results += [pscustomobject]@{ Uid = $rule.uid; Title = $rule.title; Folder = 'alert rule'; Action = 'FAILED'; Detail = "$_" } }
            }
        }
    }
}

# ---- summary -------------------------------------------------------------------------------
Write-Host ''
$results | Format-Table Action, Title, Folder, Detail -AutoSize | Out-String -Width 220 | Write-Host
$counts = $results | Group-Object Action | ForEach-Object { "$($_.Name)=$($_.Count)" }
Write-Host ("Done: {0}" -f ($counts -join '  ')) -ForegroundColor Cyan
if ($ReportPath) { $results | Export-Csv -Path $ReportPath -NoTypeInformation -Encoding UTF8; Write-Host "report: $ReportPath" }
if ($results | Where-Object { $_.Action -eq 'FAILED' }) { exit 1 }
