#Requires -Version 7.0
<#
  setup_entra_app.ps1 — provision the Entra app + security group + 23h59m access
  token lifetime for itglue-mcp, via Microsoft Graph PowerShell (Mg* cmdlets).

  Adapted from INTQMCPServer/scripts/setup_entra_app.ps1 (house standard), with
  Part C added: the token lifetime policy, folded in here rather than left as a
  separate script (cf. lxd-expert-mcp/scripts/Set-McpTokenLifetime.ps1).

  Automates docs/ENTRA_SETUP_CHECKLIST.md:
    A1 create app (single tenant)      A2 App ID URI = the /mcp URL
    A3 expose scope access_as_user     A4 client secret (printed ONCE)
    A5 both redirect URIs              A6 requestedAccessTokenVersion = 2
    B1 security group + members        B2 assignment required
    B3 assign group to the app
    C1 token lifetime policy 23:59:00  C2 assign it to this app's SP
    D  post-flight verification + Conditional Access advisory + env roster file

  Note on precedent: O365Log_MCPServer's Setup-EntraApp.ps1 provisions the
  OUTBOUND certificate app (app-only Graph permissions) — a different job. Its
  inbound gate is a shared bearer token / Cloudflare Access, and its native
  resource-server flow is only DOCUMENTED (ENTRA_SSO_PLAYBOOK.md "Model C"),
  never scripted. This script implements that Model C recipe end to end, and
  borrows the good habits from the O365 script: module preflight, a persisted
  env roster file, and non-fatal handling of the steps that commonly fail.

  RUN AS an Entra admin (Application Administrator + Groups Administrator +
  the ability to consent Policy.ReadWrite.ApplicationConfiguration — Global
  Admin covers all of it). This CHANGES auth on shared infra.

  DRY RUN BY DEFAULT. Nothing is created until you pass -Apply.

  The client secret it prints goes into Claude's connector Advanced settings,
  NOT the server env, NOT into chat, NOT into git.

  Prereqs:
    Install-Module Microsoft.Graph.Applications, Microsoft.Graph.Groups,
                   Microsoft.Graph.Users, Microsoft.Graph.Identity.SignIns `
                   -Scope CurrentUser
#>
[CmdletBinding()]
param(
    # Pin the tenant so the app lands in the directory users actually sign in
    # with. Leave blank to use whatever Connect-MgGraph picks.
    [string] $TenantId = '',

    # Omit to preview. Pass -Apply to make changes.
    [switch] $Apply,

    [string] $AppName   = 'IT Glue MCP (read-only documentation lookups)',
    [string] $McpUrl    = 'https://itglue-mcp.example.com/mcp',
    [string] $ScopeName = 'access_as_user',
    [string] $GroupName = 'ITGlue-MCP-Users',
    [string] $GroupNick = 'itglue-mcp-users',

    # Access-token lifetime. Entra's configurable range is 10 minutes to
    # 24 hours; 23:59:00 is the practical maximum and is what John asked for so
    # the team is not re-authenticating during a working day.
    [string] $TokenLifetime = '23:59:00',
    [string] $TokenPolicyName = 'MCP-AccessToken-24h',

    [string[]] $Members = @(
        'approver@example.com',
        'approver@example.com',
        'approver@example.com',
        'approver@example.com',
        'approver@example.com'
    ),

    # Where to write the non-secret env roster for the Portainer stack. Follows
    # the O365 pattern of persisting the output to a file rather than trusting
    # console scrollback. The CLIENT SECRET is deliberately NOT written here.
    [string] $OutDir = 'C:\secrets\itglue-mcp'
)

$ErrorActionPreference = 'Stop'

$RedirectUris = @(
    'https://claude.ai/api/mcp/auth_callback',
    'https://claude.com/api/mcp/auth_callback'
)
$DefaultAccessRoleId = '00000000-0000-0000-0000-000000000000'  # "default access"

function Write-Step($msg) { Write-Host "`n=== $msg ===" -ForegroundColor Cyan }

# Set once the app registration exists, so the trap below knows there is
# something to clean up. Avoids wrapping the whole script in a try block.
$script:CreatedAppObjectId = $null

trap {
    if ($script:CreatedAppObjectId) {
        Write-Host "`n!! FAILED PART-WAY THROUGH — an app registration was already created." -ForegroundColor Red
        Write-Host "   The duplicate guard will block a retry until you remove it. Run:" -ForegroundColor Yellow
        Write-Host "     Remove-MgApplication -ApplicationId $($script:CreatedAppObjectId)" -ForegroundColor Yellow
        Write-Host "   (The security group and token lifetime policy are reused on retry, so" -ForegroundColor Yellow
        Write-Host "    they do NOT need deleting.)`n" -ForegroundColor Yellow
    }
    break   # re-throw; do not swallow the error
}

# --- sanity: lifetime must parse and sit inside Entra's allowed range --------
try { $ts = [TimeSpan]::Parse($TokenLifetime) }
catch { throw "TokenLifetime '$TokenLifetime' is not a valid hh:mm:ss TimeSpan." }
if ($ts.TotalMinutes -lt 10 -or $ts.TotalHours -gt 24) {
    throw "TokenLifetime must be between 00:10:00 and 24:00:00 (Entra limit). Got $TokenLifetime."
}

# ---------------------------------------------------------------------------
# Module preflight — fail with the install command, not a cmdlet-not-found
# ---------------------------------------------------------------------------
Write-Step 'Checking modules'
$needed = @(
    'Microsoft.Graph.Applications',      # New-MgApplication, Add-MgApplicationPassword
    'Microsoft.Graph.Groups',            # New-MgGroup, New-MgGroupMember
    'Microsoft.Graph.Users',             # Get-MgUser
    'Microsoft.Graph.Identity.SignIns'   # *-MgPolicyTokenLifetimePolicy (Part C)
)
$missing = $needed | Where-Object { -not (Get-Module -ListAvailable -Name $_) }
if ($missing) {
    throw ("Missing PowerShell modules: $($missing -join ', ')`n" +
           "Install them with:`n  Install-Module $($needed -join ', ') -Scope CurrentUser")
}
Write-Host "All required modules present." -ForegroundColor Green

# ---------------------------------------------------------------------------
# Connect
# ---------------------------------------------------------------------------
$connectArgs = @{ Scopes = @(
    'Application.ReadWrite.All',
    'Group.ReadWrite.All',
    'AppRoleAssignment.ReadWrite.All',
    'User.Read.All',
    'Policy.ReadWrite.ApplicationConfiguration',
    'Policy.Read.All'
) }
if ($TenantId) { $connectArgs['TenantId'] = $TenantId }
Connect-MgGraph @connectArgs -NoWelcome | Out-Null

$ctx = Get-MgContext
$resolvedTenant = $ctx.TenantId
Write-Host "Connected to tenant $resolvedTenant as $($ctx.Account)" -ForegroundColor Cyan
if ($TenantId -and $resolvedTenant -ne $TenantId) {
    throw "Connected tenant ($resolvedTenant) != requested -TenantId ($TenantId). Aborting so the app doesn't land in the wrong directory."
}

$existingApp = Get-MgApplication -Filter "displayName eq '$AppName'" -ErrorAction SilentlyContinue

# ---------------------------------------------------------------------------
# DRY RUN
# ---------------------------------------------------------------------------
if (-not $Apply) {
    Write-Host "`n[DRY RUN] Planned actions — nothing will be changed:" -ForegroundColor Magenta
    if ($existingApp) {
        Write-Host "  !! An app named '$AppName' ALREADY EXISTS (appId $($existingApp.AppId))." -ForegroundColor Yellow
        Write-Host "     -Apply would ABORT. Delete or rename it first." -ForegroundColor Yellow
    } else {
        Write-Host "  A1  Create single-tenant app '$AppName'"
        Write-Host "  A2  App ID URI  = $McpUrl"
        Write-Host "  A3  Expose scope '$ScopeName' (admins and users may consent)"
        Write-Host "  A4  Create a 24-month client secret (printed once)"
        Write-Host "  A5  Redirect URIs: $($RedirectUris -join ', ')"
        Write-Host "  A6  requestedAccessTokenVersion = 2"
    }
    Write-Host "  B1  Ensure security group '$GroupName' with members:"
    $Members | ForEach-Object { Write-Host "        $_" }
    Write-Host "  B2  Service principal with 'Assignment required' = Yes"
    Write-Host "  B3  Assign the group to the app (default-access role)"
    Write-Host "  C1  Ensure token lifetime policy '$TokenPolicyName' = $TokenLifetime"
    Write-Host "  C2  Assign that policy to this app's service principal"
    Write-Host "  D   Read every setting back from Entra and verify it landed"
    Write-Host "  D   Warn if a Conditional Access sign-in-frequency policy would override $TokenLifetime"
    Write-Host "  D   Write the non-secret env roster to $OutDir\itglue-mcp.env"
    Write-Host "`nRe-run with -Apply to execute." -ForegroundColor Magenta
    Disconnect-MgGraph | Out-Null
    return
}

# Guard against duplicates
if ($existingApp) {
    throw "An app named '$AppName' already exists (appId $($existingApp.AppId)). Delete it or rename before re-running."
}

# ---------------------------------------------------------------------------
# A1 + A5: create the app (single tenant) with redirect URIs
#
# From here on the script has created real objects. Because the duplicate guard
# above aborts on a same-named app, a mid-script failure would otherwise leave a
# half-built app that blocks every retry with "already exists". The trap below
# prints the exact cleanup command so a retry is one paste away.
# ---------------------------------------------------------------------------
Write-Step 'A1/A5  App registration'
$app = New-MgApplication -DisplayName $AppName -SignInAudience 'AzureADMyOrg' `
    -Web @{ RedirectUris = $RedirectUris }
$script:CreatedAppObjectId = $app.Id
Write-Host "Created app. Client ID = $($app.AppId)" -ForegroundColor Green

# ---------------------------------------------------------------------------
# A2 + A3 + A6: App ID URI, exposed scope, token version — one Update
#
# Playbook rule 2: the App ID URI MUST be the exact /mcp URL, not the default
# api://<client-id>, or sign-in fails with AADSTS9010010. example.com is a
# verified domain so an https App ID URI is accepted.
# ---------------------------------------------------------------------------
Write-Step 'A2/A3/A6  App ID URI, exposed scope, token version 2'
$scope = @{
    id                      = [guid]::NewGuid().ToString()
    value                   = $ScopeName
    type                    = 'User'          # "Admins and users" can consent
    isEnabled               = $true
    adminConsentDisplayName = 'Access IT Glue MCP as the signed-in user'
    adminConsentDescription = 'Allows the connector to run READ-ONLY IT Glue documentation lookups (organizations, devices, sites, contacts, documents, and credential LINKS — never credential values) on behalf of the signed-in user.'
    userConsentDisplayName  = 'Access IT Glue MCP'
    userConsentDescription  = 'Allow the connector to look up IT Glue documentation on your behalf. It cannot change anything and cannot read passwords.'
}
Update-MgApplication -ApplicationId $app.Id `
    -IdentifierUris @($McpUrl) `
    -Api @{ RequestedAccessTokenVersion = 2; Oauth2PermissionScopes = @($scope) }
Write-Host "Set App ID URI=$McpUrl, scope=$ScopeName, tokenVersion=2" -ForegroundColor Green

# ---------------------------------------------------------------------------
# A4: client secret (24 months) — printed ONCE
# ---------------------------------------------------------------------------
Write-Step 'A4  Client secret'
$pw = Add-MgApplicationPassword -ApplicationId $app.Id -PasswordCredential @{
    DisplayName = 'claude-connector'
    EndDateTime = (Get-Date).AddMonths(24)
}
Write-Host 'Created (value printed at the end, once).' -ForegroundColor Green

# ---------------------------------------------------------------------------
# B2: enterprise app (service principal) + assignment required
# ---------------------------------------------------------------------------
Write-Step 'B2  Service principal + Assignment required'
$sp = New-MgServicePrincipal -AppId $app.AppId
Start-Sleep -Seconds 5   # let the SP replicate before we assign things to it
Update-MgServicePrincipal -ServicePrincipalId $sp.Id -AppRoleAssignmentRequired:$true
Write-Host "Service principal $($sp.Id); Assignment required = Yes" -ForegroundColor Green

# ---------------------------------------------------------------------------
# B1: security group + members
# ---------------------------------------------------------------------------
Write-Step "B1  Security group '$GroupName'"
$group = Get-MgGroup -Filter "displayName eq '$GroupName'" -ErrorAction SilentlyContinue
if (-not $group) {
    $group = New-MgGroup -DisplayName $GroupName -MailEnabled:$false `
        -MailNickname $GroupNick -SecurityEnabled:$true `
        -Description 'May use the read-only IT Glue MCP server (itglue-mcp).'
    Write-Host "Created group $GroupName ($($group.Id))" -ForegroundColor Green
} else {
    Write-Host "Reusing existing group $GroupName ($($group.Id))" -ForegroundColor Yellow
}
foreach ($upn in $Members) {
    try {
        $u = Get-MgUser -UserId $upn -ErrorAction Stop
        New-MgGroupMember -GroupId $group.Id -DirectoryObjectId $u.Id -ErrorAction Stop
        Write-Host "     added $upn"
    } catch {
        Write-Host "     (skip $upn — already a member, or not found in this tenant)" -ForegroundColor Yellow
    }
}

# ---------------------------------------------------------------------------
# B3: assign the group to the app
#
# NOTE: assigning a GROUP to an enterprise app requires Entra ID P1/P2. On the
# free tier this call fails — the catch falls back to assigning each USER
# individually, which works on any tier.
# ---------------------------------------------------------------------------
Write-Step 'B3  Assign the group to the app'
try {
    New-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $sp.Id -BodyParameter @{
        principalId = $group.Id
        resourceId  = $sp.Id
        appRoleId   = $DefaultAccessRoleId
    } -ErrorAction Stop | Out-Null
    Write-Host "Assigned group $GroupName to the app" -ForegroundColor Green
} catch {
    Write-Warning "Group assignment failed ($($_.Exception.Message))."
    Write-Host 'Falling back to per-USER assignment (works without Entra ID P1).' -ForegroundColor Yellow
    foreach ($upn in $Members) {
        try {
            $u = Get-MgUser -UserId $upn -ErrorAction Stop
            New-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $sp.Id -BodyParameter @{
                principalId = $u.Id
                resourceId  = $sp.Id
                appRoleId   = $DefaultAccessRoleId
            } -ErrorAction Stop | Out-Null
            Write-Host "     assigned $upn"
        } catch {
            Write-Host "     (skip $upn — $($_.Exception.Message))" -ForegroundColor Yellow
        }
    }
}

# ---------------------------------------------------------------------------
# C1 + C2: access token lifetime = 23:59:00
#
# Entra's default access token lifetime is 60-90 minutes (randomised). Without
# this, the team re-authenticates several times a day. A Token Lifetime Policy
# assigned to this app's service principal raises it to just under 24 hours.
#
# Note the division of labour: this controls the ACCESS token. Refresh-token and
# session lifetimes have not been configurable since 2021 — that side is handled
# by advertising `offline_access` in the server's protected-resource metadata
# (ITGLUE_ADVERTISE_OFFLINE_ACCESS=true, the default), so Claude holds a refresh
# token and renews silently. You want both.
# ---------------------------------------------------------------------------
Write-Step "C1  Token lifetime policy '$TokenPolicyName' = $TokenLifetime"
$definition = @("{`"TokenLifetimePolicy`":{`"Version`":1,`"AccessTokenLifetime`":`"$TokenLifetime`"}}")

$policy = Get-MgPolicyTokenLifetimePolicy -All -ErrorAction SilentlyContinue |
    Where-Object DisplayName -eq $TokenPolicyName | Select-Object -First 1

if ($policy) {
    Write-Host "Reusing existing policy ($($policy.Id)); updating its definition to $TokenLifetime."
    Update-MgPolicyTokenLifetimePolicy -TokenLifetimePolicyId $policy.Id -Definition $definition
} else {
    $policy = New-MgPolicyTokenLifetimePolicy -DisplayName $TokenPolicyName `
        -Definition $definition -IsOrganizationDefault:$false
    Write-Host "Created policy $($policy.Id)." -ForegroundColor Green
}

Write-Step 'C2  Assign the policy to this app'
# One token lifetime policy per SP: clear any other, then attach ours.
$existingTlp = Get-MgServicePrincipalTokenLifetimePolicy -ServicePrincipalId $sp.Id -ErrorAction SilentlyContinue
foreach ($e in $existingTlp) {
    if ($e.Id -ne $policy.Id) {
        Write-Host "   removing pre-existing TLP $($e.Id)"
        Remove-MgServicePrincipalTokenLifetimePolicyByRef -ServicePrincipalId $sp.Id -TokenLifetimePolicyId $e.Id
    }
}
if ($existingTlp.Id -contains $policy.Id) {
    Write-Host '   already assigned.'
} else {
    New-MgServicePrincipalTokenLifetimePolicyByRef -ServicePrincipalId $sp.Id `
        -OdataId "https://graph.microsoft.com/v1.0/policies/tokenLifetimePolicies/$($policy.Id)"
    Write-Host "   assigned $TokenPolicyName ($TokenLifetime)" -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# D — POST-FLIGHT VERIFICATION
#
# Read the state back from Entra rather than trusting that the writes landed.
# Each check maps to a specific AADSTS failure we would otherwise debug later
# (see docs/ENTRA_SETUP_CHECKLIST.md for the failure catalog).
# ---------------------------------------------------------------------------
Write-Step 'D  Verifying what Entra actually stored'
$verifyFailed = @()
$appCheck = Get-MgApplication -ApplicationId $app.Id
$spCheck  = Get-MgServicePrincipal -ServicePrincipalId $sp.Id

function Assert-Entra($label, $ok, $detail) {
    if ($ok) { Write-Host "   OK    $label" -ForegroundColor Green }
    else {
        Write-Host "   WRONG $label -> $detail" -ForegroundColor Red
        $script:verifyFailed += $label
    }
}

Assert-Entra 'App ID URI == the /mcp URL (else AADSTS9010010)' `
    ($appCheck.IdentifierUris -contains $McpUrl) "$($appCheck.IdentifierUris -join ', ')"
Assert-Entra 'requestedAccessTokenVersion == 2 (else post-sign-in 401)' `
    ($appCheck.Api.RequestedAccessTokenVersion -eq 2) "$($appCheck.Api.RequestedAccessTokenVersion)"
Assert-Entra "exposed scope '$ScopeName' present and enabled (else AADSTS70011)" `
    ([bool]($appCheck.Api.Oauth2PermissionScopes | Where-Object { $_.Value -eq $ScopeName -and $_.IsEnabled })) `
    "$(($appCheck.Api.Oauth2PermissionScopes | ForEach-Object Value) -join ', ')"
Assert-Entra 'both Claude redirect URIs registered (else AADSTS50011)' `
    (($RedirectUris | Where-Object { $appCheck.Web.RedirectUris -contains $_ }).Count -eq $RedirectUris.Count) `
    "$($appCheck.Web.RedirectUris -join ', ')"
Assert-Entra 'single tenant (AzureADMyOrg)' `
    ($appCheck.SignInAudience -eq 'AzureADMyOrg') "$($appCheck.SignInAudience)"
Assert-Entra 'Assignment required == Yes (the group gate)' `
    ($spCheck.AppRoleAssignmentRequired -eq $true) "$($spCheck.AppRoleAssignmentRequired)"

$assigned = Get-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $sp.Id -All
Assert-Entra 'at least one principal assigned (else nobody can sign in)' `
    ($assigned.Count -ge 1) "$($assigned.Count) assignment(s)"

$tlpCheck = Get-MgServicePrincipalTokenLifetimePolicy -ServicePrincipalId $sp.Id -ErrorAction SilentlyContinue
Assert-Entra "token lifetime policy attached ($TokenLifetime)" `
    ([bool]($tlpCheck | Where-Object { $_.Id -eq $policy.Id })) `
    "$(($tlpCheck | ForEach-Object Id) -join ', ')"
if ($tlpCheck) {
    $def = ($tlpCheck | Where-Object { $_.Id -eq $policy.Id }).Definition -join ''
    Assert-Entra "policy definition contains $TokenLifetime" ($def -match [regex]::Escape($TokenLifetime)) $def
}

# Advisory only: a Conditional Access sign-in-frequency policy silently overrides
# the token lifetime above. This is the #1 reason "we set 24h and users are still
# prompted daily". Read-only check; never fatal.
try {
    $caPolicies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop |
        Where-Object { $_.State -ne 'disabled' -and $_.SessionControls.SignInFrequency.IsEnabled }
    if ($caPolicies) {
        Write-Host "`n   ADVISORY: Conditional Access policies with sign-in frequency enabled:" -ForegroundColor Yellow
        foreach ($p in $caPolicies) {
            $apps = $p.Conditions.Applications.IncludeApplications -join ','
            Write-Host ("     - {0} [{1}]  includeApplications: {2}" -f $p.DisplayName, $p.State, $apps) -ForegroundColor Yellow
        }
        Write-Host "   If one of these covers this app (or 'All'), it OVERRIDES the $TokenLifetime" -ForegroundColor Yellow
        Write-Host "   lifetime and users will still be re-prompted. Exclude the app — see" -ForegroundColor Yellow
        Write-Host "   Notify-mcp/scripts/Set-McpSignInFrequencyExclusion.ps1 for the pattern." -ForegroundColor Yellow
    } else {
        Write-Host "   OK    no enabled Conditional Access sign-in-frequency policy found" -ForegroundColor Green
    }
} catch {
    Write-Host "   (skipped Conditional Access check: $($_.Exception.Message))" -ForegroundColor DarkGray
}

if ($verifyFailed) {
    Write-Host "`n!! $($verifyFailed.Count) verification check(s) FAILED — fix before connecting Claude:" -ForegroundColor Red
    $verifyFailed | ForEach-Object { Write-Host "     $_" -ForegroundColor Red }
} else {
    Write-Host "`nAll post-flight checks passed." -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# Output — persist the non-secret roster to a file (O365 script pattern), so
# the values survive console scrollback. The SECRET is printed only.
# ---------------------------------------------------------------------------
$publicUrl = $McpUrl -replace '/mcp$', ''
$envLines = @"
# itglue-mcp — Portainer stack env. Generated by scripts/setup_entra_app.ps1.
# Tenant/client IDs are safe to share. The CLIENT SECRET is NOT in this file:
# it was printed once to the console and belongs in Claude's connector
# Advanced settings, not the server environment.
ENTRA_TENANT_ID=$resolvedTenant
ENTRA_CLIENT_ID=$($app.AppId)
ENTRA_IDENTIFIER_URI=$McpUrl
MCP_BASE_URL=$publicUrl
ENTRA_SCOPE_NAME=$ScopeName
ENTRA_REQUIRED_SCOPES=$ScopeName
ITGLUE_ADVERTISE_OFFLINE_ACCESS=true
MCP_HOST_PORT=8111
MCP_AUTH_ENABLED=true

# Add by hand — NOT provisioned by this script:
# ITGLUE_API_KEY=
ITGLUE_SUBDOMAIN_URL=https://your-company.itglue.com
ITGLUE_INCLUDE_USERNAME=false
"@
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }
$envFile = Join-Path $OutDir 'itglue-mcp.env'
Set-Content -Path $envFile -Value $envLines -Encoding UTF8

Write-Host "`n================ DONE — Portainer stack env vars ================" -ForegroundColor Cyan
Write-Host $envLines
Write-Host "Also written to: $envFile" -ForegroundColor Green
Write-Host "`n(ITGLUE_API_KEY is NOT set by this script — add it to the stack env by hand.)" -ForegroundColor Yellow

Write-Host "`n---- CLIENT SECRET — paste into Claude connector Advanced settings ----" -ForegroundColor Magenta
Write-Host '     NOT the server env. NOT chat. NOT git. Shown once.' -ForegroundColor Magenta
Write-Host $pw.SecretText -ForegroundColor Magenta

Write-Host "`nAccess tokens for this app now live $TokenLifetime." -ForegroundColor Cyan
Write-Host "Group '$GroupName' controls who may connect — add or remove members there." -ForegroundColor Cyan
Write-Host "The tenant and client IDs above are safe to share; the secret is not." -ForegroundColor Cyan

Disconnect-MgGraph | Out-Null
