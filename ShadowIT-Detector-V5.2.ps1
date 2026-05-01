# ================================================================================================================================
#
#  ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗    ██╗████████╗    ██████╗ ███████╗████████╗███████╗ ██████╗████████╗ ██████╗ ██████╗
#  ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║    ██║╚══██╔══╝    ██╔══██╗██╔════╝╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗
#  ███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║    ██║   ██║       ██║  ██║█████╗     ██║   █████╗  ██║        ██║   ██║   ██║██████╔╝
#  ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║    ██║   ██║       ██║  ██║██╔══╝     ██║   ██╔══╝  ██║        ██║   ██║   ██║██╔══██╗
#  ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝    ██║   ██║       ██████╔╝███████╗   ██║   ███████╗╚██████╗   ██║   ╚██████╔╝██║  ██║
#  ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝    ╚═╝   ╚═╝       ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝
#
#  VERSION    : 5.2 (Flush dynamique, Double-Checked Locking, Mutex optimisés)
#  AUTEUR     : Aimen Boudalia
#  DATE       : 01/05/2026
#
#  PRÉREQUIS : PowerShell 7.2+
#  USAGE     : .\ShadowIT-Detector-V5.2.ps1 [-ManagedIdentity] [-WhatIf] [-RemediateHighRisk] [etc.]
#
# ================================================================================================================================


#region ═════════════════════════ DÉCLARATION CMDLET & PARAMÈTRES ════════════════════

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "High")]
param(
    [switch]$ManagedIdentity,
    [string]$ClientId = $(if ($env:GRAPH_CLIENT_ID) { $env:GRAPH_CLIENT_ID } else { "" }),
    [string]$TenantId = $(if ($env:GRAPH_TENANT_ID) { $env:GRAPH_TENANT_ID } else { "" }),
    [string]$CertificateThumbprint = $(if ($env:GRAPH_CERT_THUMBPRINT) { $env:GRAPH_CERT_THUMBPRINT } else { "" }),

    [string]$OutputDir          = $PSScriptRoot,
    [string]$WhitelistPath      = "$PSScriptRoot\whitelist.csv",
    [string]$ExpectedDriftPath  = "$PSScriptRoot\ExpectedDrift.csv",
    [string]$StatePath          = "$PSScriptRoot\ShadowIT_State.json",
    [string]$ExecutionLogPath   = "$PSScriptRoot\ShadowIT_Execution.log",

    [int]$InactivityThresholdDays  = 90,
    [int]$SecretExpiryWarningDays  = 30,
    [int]$TeamsAlertScoreThreshold = 40,
    [int]$SignInCacheWindowDays    = 30,
    [int]$QuarantineHours          = 48,

    [int]$ThrottleLimit    = 15,
    [int]$MaxRetryAttempts = 3,

    [string]$SocAdminGroupId = $(if ($env:SOC_ADMIN_GROUP_ID) { $env:SOC_ADMIN_GROUP_ID } else { "00000000-0000-0000-0000-000000000000" }),
    [int]$RemediationScoreThreshold = 70,
    [switch]$RemediateHighRisk,
    [switch]$Force,

    [int]$MaxExecutionMinutes = 150
)
if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Error "Shadow IT Detector V5 requiert PowerShell 7.2+. Version détectée : $($PSVersionTable.PSVersion)."
    exit 1
}

#endregion

#region ═════════════════════════ CONFIGURATION GLOBALE ═══════════════════════════════

$TeamsWebhookUrl    = $env:TEAMS_WEBHOOK_URL
$MicrosoftTenantId  = "f8cdef31-a31e-4b4a-93e4-5f571e91255a"
$TagQuarantinePrefix= "SOC_QUARANTINE_"
$TagDisabledValue   = "SOC_DISABLED_BY_AUDIT"
$RunTimestamp       = Get-Date -Format "yyyyMMdd_HHmmss"
$RunDate            = Get-Date

$HtmlReportPath     = Join-Path $OutputDir "ShadowIT_Report_$RunTimestamp.html"
$CsvReportPath      = Join-Path $OutputDir "ShadowIT_Report_$RunTimestamp.csv"
$SiemReportPath     = Join-Path $OutputDir "ShadowIT_SIEM_$RunTimestamp.json"
$FlushTempDir       = Join-Path $OutputDir "FlushTemp_$RunTimestamp"

# === DÉTECTION WHATIF (pour le bloc parallèle où ShouldProcess est indisponible) ===
$IsWhatIf = ($WhatIfPreference -ne [System.Management.Automation.ActionPreference]::SilentlyContinue) -or $PSBoundParameters.ContainsKey('WhatIf')
if ($IsWhatIf) {
    Write-Host "[⚠️] MODE WHATIF ACTIVÉ — Aucune modification réelle ne sera effectuée." -ForegroundColor Yellow
}

# === TIERS DE PERMISSIONS POUR SCORING ===
$Tier1Patterns = @(
    "Directory.*", "RoleManagement.*", "Policy.*",
    "Application.ReadWrite.*", "Application.ReadWrite.All", "Application.ReadWrite.OwnedBy",
    "AuditLog.Read.All", "SecurityEvents.*", "IdentityRiskyUser.*", "DeviceManagement*"
)

$Tier2Patterns = @(
    "Mail.*", "MailboxSettings.*", "Files.*", "Sites.*",
    "Chat.*", "Team.*", "Channel.*", "Calendars.*", "Contacts.*", "Notes.*", "Tasks.*"
)

# [FLUSH] Compteurs partagés entre runspaces

$FlushThreshold  = 10000
$SharedCounter   = [long[]]::new(1)
$SharedNextFlush = [long[]]::new(1)
$SharedNextFlush[0] = [long]$FlushThreshold

$u_SharedCounter   = $SharedCounter
$u_SharedNextFlush = $SharedNextFlush
$u_FlushThreshold  = [long]$FlushThreshold

#endregion

#region ═════════════════════════ FONCTIONS UTILITAIRES (Scope Principal) ════════════

function Write-LogMain {
    param(
        [string]$Message,
        [ValidateSet("INFO","OK","WARN","ERROR","SECTION","ACTION","GATE","PERF")]
        [string]$Level = "INFO"
    )

    $ts     = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $prefix = switch ($Level) {
        "INFO"    { "[*]" }
        "OK"      { "[+]" }
        "WARN"    { "[!]" }
        "ERROR"   { "[✗]" }
        "SECTION" { "───" }
        "ACTION"  { "[⚡]" }
        "GATE"    { "[🔒]" }
        "PERF"    { "[📊]" }
    }
    $color  = switch ($Level) {
        "INFO"    { "Cyan" }
        "OK"      { "Green" }
        "WARN"    { "Yellow" }
        "ERROR"   { "Red" }
        "SECTION" { "DarkCyan" }
        "ACTION"  { "Magenta" }
        "GATE"    { "White" }
        "PERF"    { "DarkYellow" }
    }

    Write-Host "$($ts.Substring(11)) $prefix $Message" -ForegroundColor $color

    try {
        Add-Content -Path $ExecutionLogPath -Value "$ts | $($Level.PadRight(7)) | $Message" -Encoding UTF8 -ErrorAction SilentlyContinue
    }
    catch {
        # Silencieux ne pas bloquer le script pour un échec de log
    }
}

function Invoke-GraphWithRetry {
    param(
        [scriptblock]$ScriptBlock,
        [int]$MaxAttempts  = 3,
        [string]$Operation = "Graph API"
    )
    $attempt   = 0
    $baseDelay = 2

    while ($attempt -lt $MaxAttempts) {
        $attempt++
        try {
            return (& $ScriptBlock)
        }
        catch {
            $errMsg     = $_.Exception.Message
            $statusCode = $null
            
            try { $statusCode = [int]$_.Exception.Response.StatusCode } catch {}

            
            if ($statusCode -in @(400, 401, 403, 404)) { throw $_ }

            # Tentatives épuisées
            if ($attempt -ge $MaxAttempts) { throw $_ }

           
            $isTransient = ($statusCode -ge 500) -or
                           ($statusCode -eq 429) -or
                           ($errMsg -like "*429*") -or
                           ($errMsg -like "*throttl*") -or
                           ($errMsg -like "*TooManyRequests*") -or
                           ($errMsg -like "*timeout*") -or
                           ($errMsg -like "*temporarily unavailable*") -or
                           ($errMsg -like "*request was canceled*") -or
                           ($_.Exception -is [System.Threading.Tasks.TaskCanceledException]) -or
                           ($_.Exception -is [System.OperationCanceledException])

            # Erreur non classifiée et non permanente → retry par défaut
            $retryAfter = $null
            try { $retryAfter = [int]$_.Exception.Response.Headers.GetValues("Retry-After")[0] } catch {}
            $delay = if ($retryAfter -and $retryAfter -gt 0) { $retryAfter } else { [Math]::Pow(2, $attempt) * $baseDelay }

            Write-Verbose "[$Operation] Retry $attempt/$MaxAttempts — HTTP:$statusCode — attente ${delay}s"
            Start-Sleep -Seconds $delay
        }
    }
}

function Get-RiskLabel {
    param([int]$Score, [bool]$IsWhitelisted)

    if ($IsWhitelisted) { return "RISQUE ACCEPTÉ" }
    if ($Score -ge 70)  { return "CRITIQUE" }
    if ($Score -ge 40)  { return "ÉLEVÉ" }
    if ($Score -ge 20)  { return "MOYEN" }
    return "FAIBLE"
}

function Get-RiskColor {
    param([string]$Label)

    switch ($Label) {
        "CRITIQUE"       { return "#FF3B30" }
        "ÉLEVÉ"          { return "#FF9500" }
        "MOYEN"          { return "#FFD60A" }
        "RISQUE ACCEPTÉ" { return "#34C759" }
        default          { return "#64748b" }
    }
}

function Get-RiskTextColor {
    param([string]$Label)

    if ($Label -eq "MOYEN") { return "#000" }
    return "#fff"
}

#endregion

#region ═════════════════════════ BANNIÈRE & INIT LOG ═════════════════════════════════

Clear-Host
Write-Host ""
Write-Host "  ╔═══════════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor DarkCyan
Write-Host "  ║                                                                                   ║" -ForegroundColor DarkCyan
Write-Host "  ║  🏭                  SHADOW IT DETECTOR V5.2                                      ║" -ForegroundColor Cyan
Write-Host "  ║                                                                                   ║" -ForegroundColor DarkCyan
Write-Host "  ╚═══════════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor DarkCyan
Write-Host ""

$logHeader = @"
================================================================
  SHADOW IT DETECTOR V5.2 — Exécution du $($RunDate.ToString('yyyy-MM-dd HH:mm:ss'))
  PID : $PID | Utilisateur : $env:USERNAME | Machine : $env:COMPUTERNAME
  PowerShell : $($PSVersionTable.PSVersion) | ThrottleLimit : $ThrottleLimit | WhatIf : $IsWhatIf
================================================================
"@

try {
    Add-Content -Path $ExecutionLogPath -Value $logHeader -Encoding UTF8 -ErrorAction SilentlyContinue
}
catch {
    # Silencieux ne pas bloquer le script pour un échec de log
}

Write-LogMain "Log d'exécution : $ExecutionLogPath" -Level INFO
Write-LogMain "PowerShell $($PSVersionTable.PSVersion) — ThrottleLimit : $ThrottleLimit runspaces" -Level PERF

if ($IsWhatIf) {
    Write-LogMain "MODE WHATIF ACTIVÉ — aucune modification réelle." -Level WARN
}

# Note : Azure Automation SIGKILL (timeout infra) ne déclenche PAS le trap
trap {
    Write-LogMain "ERREUR FATALE : $($_.Exception.Message)" -Level ERROR
    if ((Test-Path variable:FlushTempDir) -and $FlushTempDir -and (Test-Path $FlushTempDir)) {
        try { Remove-Item $FlushTempDir -Recurse -Force -ErrorAction SilentlyContinue } catch {}
    }
    try { Disconnect-MgGraph | Out-Null } catch {}
    break
}

#endregion

#region ═════════════════════════ ÉTAPE 1 : AUTHENTIFICATION M2M ══════════════════════

Write-LogMain "AUTHENTIFICATION MICROSOFT GRAPH (V5.2 — MACHINE-TO-MACHINE)" -Level SECTION

$RequiredScopes = @(
    "Application.Read.All",
    "Directory.Read.All",
    "AuditLog.Read.All",
    "RoleManagement.Read.Directory",
    "User.Read",
    "GroupMember.Read.All"
)

if ($RemediateHighRisk) {
    $RequiredScopes += "Application.ReadWrite.All"
    Write-LogMain "Scope Application.ReadWrite.All ajouté (mode remédiation demandé)." -Level WARN
}

$AuthMode = "Interactive"

try {
    if ($ManagedIdentity) {
        $AuthMode = "ManagedIdentity"
        Write-LogMain "[AUTH] Mode Managed Identity — connexion non-interactive..." -Level INFO
        Connect-MgGraph -Identity -ErrorAction Stop | Out-Null
        Write-LogMain "Connecté via Managed Identity." -Level OK
    }
    elseif ($ClientId -and $TenantId -and $CertificateThumbprint) {
        $AuthMode = "Certificate"
        Write-LogMain "[AUTH] Mode Certificat — ClientId: $ClientId | Tenant: $TenantId" -Level INFO

        # Recherche du certificat dans le magasin LocalMachine puis CurrentUser
        $cert = Get-ChildItem -Path "Cert:\LocalMachine\My\$CertificateThumbprint" -ErrorAction SilentlyContinue
        if (-not $cert) {
            $cert = Get-ChildItem -Path "Cert:\CurrentUser\My\$CertificateThumbprint" -ErrorAction SilentlyContinue
        }

        if (-not $cert) {
            Write-LogMain "ERREUR : Certificat thumbprint '$CertificateThumbprint' introuvable." -Level ERROR
            exit 1
        }

        Connect-MgGraph -ClientId $ClientId -TenantId $TenantId -CertificateThumbprint $CertificateThumbprint -ErrorAction Stop | Out-Null
        Write-LogMain "Connecté via Service Principal + Certificat." -Level OK
    }
    else {
        $AuthMode = "Interactive"
        Write-LogMain "[AUTH] Mode Interactif (fallback) — browser/device code requis." -Level WARN
        Connect-MgGraph -Scopes $RequiredScopes -ErrorAction Stop | Out-Null
        Write-LogMain "Connecté de manière interactive." -Level OK
    }

    $GraphContext = Get-MgContext
    Write-LogMain "Tenant  : $($GraphContext.TenantId)"  -Level INFO

    # Affichage du nom de l'application ou du compte utilisateur
    $appDisplay = if ($GraphContext.AppName) { $GraphContext.AppName } else { $GraphContext.Account }
    Write-LogMain "App     : $appDisplay" -Level INFO

    Write-LogMain "Mode    : $AuthMode" -Level INFO
}
catch {
    Write-LogMain "ÉCHEC D'AUTHENTIFICATION : $($_.Exception.Message)" -Level ERROR
    exit 1
}

#endregion
# ================================================================================================================================
# ÉTAPE 2 : DOUBLE GATE REMÉDIATION
# ================================================================================================================================

#region ═════════════════════════ ÉTAPE 2 : DOUBLE GATE REMÉDIATION ═══════════════════

if ($RemediateHighRisk) {
    Write-LogMain "VÉRIFICATION DES GATES DE SÉCURITÉ (RBAC + NUKE GUARD V5.2)" -Level SECTION
    $RemediationAuthorized = $false

    Write-LogMain "[GATE 1/2] Vérification RBAC — groupe SOC Admin ($SocAdminGroupId)..." -Level GATE
    if ($SocAdminGroupId -eq "00000000-0000-0000-0000-000000000000") {
        Write-LogMain "GATE 1 ÉCHOUÉ — SocAdminGroupId non configuré. Basculement en mode Audit." -Level ERROR
        $RemediateHighRisk = $false
    }
    else {
        try {
            if ($AuthMode -in @("ManagedIdentity", "Certificate")) {

                $availableScopes = (Get-MgContext).Scopes
                if ($availableScopes -notcontains "Directory.Read.All" -and $availableScopes -notcontains "Application.Read.All") {
                    Write-LogMain "GATE 1 WARN — Scope Directory.Read.All requis pour checkMemberGroups (vérifiez les App Permissions Entra)." -Level WARN
                }

                #            checkMemberGroups attend l'ObjectId (Id objet Directory) — ce sont deux valeurs DIFFÉRENTES
                $clientAppId = (Get-MgContext).ClientId
                if (-not $clientAppId) {
                    Write-LogMain "GATE 1 ÉCHOUÉ — ClientId non disponible dans le contexte Graph (Managed Identity non configurée ?)." -Level ERROR
                    $RemediateHighRisk = $false
                }
                else {
                    # Résolution AppId → ObjectId via Get-MgServicePrincipal
                    $currentSP = $null
                    try {
                        $currentSP = Invoke-GraphWithRetry -MaxAttempts $MaxRetryAttempts -Operation "ResolveSP_ObjectId" -ScriptBlock {
                            Get-MgServicePrincipal -Filter "appId eq '$clientAppId'" -Property Id, DisplayName -ErrorAction Stop |
                                Select-Object -First 1
                        }
                    }
                    catch {
                        Write-LogMain "GATE 1 ERREUR — Résolution ObjectId échouée pour AppId '$clientAppId' : $($_.Exception.Message)" -Level ERROR
                        $RemediateHighRisk = $false
                    }

                    if ($RemediateHighRisk -and (-not $currentSP -or -not $currentSP.Id)) {
                        Write-LogMain "GATE 1 ÉCHOUÉ — Aucun ServicePrincipal trouvé pour AppId '$clientAppId'." -Level ERROR
                        $RemediateHighRisk = $false
                    }

                    if ($RemediateHighRisk) {
                        $spObjectId = $currentSP.Id
                        Write-LogMain "[GATE 1/2] checkMemberGroups — SP '$($currentSP.DisplayName)' (ObjectId: $spObjectId)..." -Level GATE

                        try {
                            
                            $memberCheckBody = @{ groupIds = @($SocAdminGroupId) } | ConvertTo-Json -Compress
                            $memberCheck = Invoke-GraphWithRetry -MaxAttempts $MaxRetryAttempts -Operation "CheckMemberGroups" -ScriptBlock {
                                Invoke-MgGraphRequest -Method POST `
                                    -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$spObjectId/checkMemberGroups" `
                                    -Body $memberCheckBody `
                                    -ContentType "application/json" `
                                    -ErrorAction Stop
                            }

                            if ($memberCheck.value -contains $SocAdminGroupId) {
                                Write-LogMain "GATE 1 PASSÉ ✓ — SP '$($currentSP.DisplayName)' est membre du groupe SOC Admin '$SocAdminGroupId'." -Level OK
                            }
                            else {
                                Write-LogMain "GATE 1 ÉCHOUÉ — SP '$($currentSP.DisplayName)' N'EST PAS membre du groupe '$SocAdminGroupId'." -Level ERROR
                                $RemediateHighRisk = $false
                            }
                        }
                        catch {
                            Write-LogMain "GATE 1 ERREUR — checkMemberGroups : $($_.Exception.Message)" -Level ERROR
                            $RemediateHighRisk = $false
                        }
                    }
                }
            }
            else {
                # Mode interactif : vérification de l'appartenance au groupe
                $CurrentUser = Invoke-GraphWithRetry -MaxAttempts $MaxRetryAttempts -Operation "Get-MgUser" -ScriptBlock {
                    Get-MgUser -Filter "userPrincipalName eq '$($GraphContext.Account)'" -Property Id, DisplayName -ErrorAction Stop
                }
                $UserGroups = Invoke-GraphWithRetry -MaxAttempts $MaxRetryAttempts -Operation "Get-MgUserMemberOf" -ScriptBlock {
                    Get-MgUserMemberOf -UserId $CurrentUser.Id -All -ErrorAction Stop
                }
                if ($UserGroups | Where-Object { $_.Id -eq $SocAdminGroupId }) {
                    Write-LogMain "GATE 1 PASSÉ ✓ — '$($GraphContext.Account)' est membre du groupe SOC Admin." -Level OK
                }
                else {
                    Write-LogMain "GATE 1 ÉCHOUÉ — n'est pas membre du groupe SOC Admin." -Level ERROR
                    $RemediateHighRisk = $false
                }
            }
        }
        catch {
            Write-LogMain "GATE 1 ERREUR — $($_.Exception.Message)" -Level ERROR
            $RemediateHighRisk = $false
        }
    }

    if ($RemediateHighRisk) {
        Write-LogMain "[GATE 2/2] Confirmation de remédiation..." -Level GATE
        if ($AuthMode -in @("ManagedIdentity", "Certificate")) {
            if ($env:SOC_REMEDIATION_CONFIRMED -ceq "true") {
                $RemediationAuthorized = $true
                Write-LogMain "GATE 2 PASSÉ ✓ (mode M2M — SOC_REMEDIATION_CONFIRMED=true)." -Level OK
            }
            elseif ($Force) {
                $RemediationAuthorized = $true
                Write-LogMain "GATE 2 PASSÉ ✓ (mode M2M — flag -Force explicite)." -Level WARN
            }
            else {
                Write-LogMain "GATE 2 ÉCHOUÉ — SOC_REMEDIATION_CONFIRMED non définie." -Level ERROR
                $RemediateHighRisk = $false
            }
        }
        else {
            Write-Host "`n  ⚠️ AVERTISSEMENT : REMÉDIATION PRODUCTION (Score ≥ $RemediationScoreThreshold)`n" -ForegroundColor Red
            $Confirmation = Read-Host "  Tapez exactement 'CONFIRMER' pour continuer"
            if ($Confirmation -ceq "CONFIRMER") {
                $RemediationAuthorized = $true
                Write-LogMain "GATE 2 PASSÉ ✓ — Confirmation manuelle reçue." -Level OK
            }
            else {
                Write-LogMain "GATE 2 ÉCHOUÉ — Saisie incorrecte. Basculement en mode Audit." -Level WARN
                $RemediateHighRisk = $false
            }
        }
    }
    if (-not $RemediationAuthorized) { $RemediateHighRisk = $false }
}

#endregion

# ================================================================================================================================
# ÉTAPE 3 : CHARGEMENT FICHIERS DE RÉFÉRENCE
# ================================================================================================================================

#region ═════════════════════════ ÉTAPE 3 : CHARGEMENT FICHIERS DE RÉFÉRENCE ══════════

Write-LogMain "CHARGEMENT DES FICHIERS DE RÉFÉRENCE" -Level SECTION

$WhitelistedAppIds = @()
if (Test-Path $WhitelistPath) {
    try {
        $WhitelistedAppIds = (Import-Csv $WhitelistPath -ErrorAction Stop).AppId
        Write-LogMain "Whitelist chargée : $($WhitelistedAppIds.Count) entrée(s)." -Level OK
    }
    catch {
        Write-LogMain "Erreur whitelist : $($_.Exception.Message)" -Level WARN
    }
}
else {
    Write-LogMain "Aucune whitelist trouvée ($WhitelistPath)." -Level WARN
}

$ExpectedDriftAppIds = @()
if (Test-Path $ExpectedDriftPath) {
    try {
        $ExpectedDriftAppIds = (Import-Csv $ExpectedDriftPath -ErrorAction Stop).AppId
        Write-LogMain "Expected Drift chargé : $($ExpectedDriftAppIds.Count) app(s)." -Level OK
    }
    catch {
        Write-LogMain "Erreur Expected Drift : $($_.Exception.Message)" -Level WARN
    }
}
else {
    Write-LogMain "Aucun fichier Expected Drift trouvé ($ExpectedDriftPath)." -Level WARN
}

$PreviousStateIndex = @{}
if (Test-Path $StatePath) {
    try {
        $PreviousState = (Get-Content $StatePath -Raw) | ConvertFrom-Json
        foreach ($entry in $PreviousState) {
            $PreviousStateIndex[$entry.AppId] = $entry
        }
        Write-LogMain "État précédent chargé : $($PreviousStateIndex.Count) entrée(s)." -Level OK
    }
    catch {
        Write-LogMain "Erreur état précédent : $($_.Exception.Message)" -Level WARN
    }
}
else {
    Write-LogMain "Premier lancement — baseline Drift sera générée en fin d'exécution." -Level WARN
}

#endregion

# ================================================================================================================================
# ÉTAPE 4 : COLLECTE GRAPH BULK
# ================================================================================================================================

#region ═════════════════════════ ÉTAPE 4 : COLLECTE GRAPH BULK ═══════════════════════

Write-LogMain "COLLECTE MICROSOFT GRAPH — DONNÉES BULK (PRÉ-CHARGEMENT)" -Level SECTION
$CollectStart = Get-Date

# -----------------------------------------------------------------
# Récupération de tous les Service Principals
# -----------------------------------------------------------------
Write-LogMain "Récupération de tous les Service Principals..." -Level INFO
try {
    $AllSPs = Invoke-GraphWithRetry -MaxAttempts $MaxRetryAttempts -Operation "Get-MgServicePrincipal" -ScriptBlock {
        Get-MgServicePrincipal -All -Property Id, DisplayName, AppId, AppOwnerOrganizationId, AccountEnabled,
                               CreatedDateTime, ServicePrincipalType, VerifiedPublisher,
                               PasswordCredentials, KeyCredentials, AppRoles, Tags -ErrorAction Stop
    }
    Write-LogMain "$($AllSPs.Count) Service Principal(s) récupéré(s)." -Level OK
}
catch {
    Write-LogMain "ERREUR CRITIQUE SP : $($_.Exception.Message)" -Level ERROR
    exit 1
}


$SPById = @{}
foreach ($sp in $AllSPs) {
    $SPById[$sp.Id] = [PSCustomObject]@{
        Id       = $sp.Id
        AppId    = $sp.AppId    
        AppRoles = $sp.AppRoles # nécessaire pour résoudre les AppRoleAssignments dans les runspaces
    }
}

# -----------------------------------------------------------------
# Récupération des OAuth2 Permission Grants (délégués)
# -----------------------------------------------------------------
Write-LogMain "Récupération des OAuth2 Permission Grants..." -Level INFO
$AllOAuth2Grants = @()
try {
    $AllOAuth2Grants = Invoke-GraphWithRetry -MaxAttempts $MaxRetryAttempts -Operation "Get-MgOauth2PermissionGrant" -ScriptBlock {
        Get-MgOauth2PermissionGrant -All -ErrorAction Stop
    }
    Write-LogMain "$($AllOAuth2Grants.Count) grant(s) délégué(s) récupéré(s)." -Level OK
}
catch {
    Write-LogMain "OAuth2Grants inaccessibles : $($_.Exception.Message) — poursuite sans." -Level WARN
}

# Indexation des grants par ClientId (ObjectId du SP) pour lookup primaire
$GrantsByClientId = @{}
foreach ($grant in $AllOAuth2Grants) {
    if ($grant.ClientId) {
        if (-not $GrantsByClientId.ContainsKey($grant.ClientId)) {
            $GrantsByClientId[$grant.ClientId] = [System.Collections.Generic.List[object]]::new()
        }
        $GrantsByClientId[$grant.ClientId].Add($grant)
    }
}


# $grant.ClientId = ObjectId du SP client ; $SP.AppId = GUID applicatif (valeurs différentes en multi-tenant)
# Construction de l'index secondaire AppId → grants via cross-référence $SPById
foreach ($grant in $AllOAuth2Grants) {
    if ($grant.ClientId -and $SPById.ContainsKey($grant.ClientId)) {
        $grantAppId = $SPById[$grant.ClientId].AppId
        # Index secondaire uniquement si AppId ≠ ClientId (ObjectId) — cas multi-tenant
        if ($grantAppId -and $grantAppId -ne $grant.ClientId) {
            if (-not $GrantsByClientId.ContainsKey($grantAppId)) {
                $GrantsByClientId[$grantAppId] = [System.Collections.Generic.List[object]]::new()
            }
            $GrantsByClientId[$grantAppId].Add($grant)
        }
    }
}

# -----------------------------------------------------------------
# Pré-chargement du cache Sign-Ins (fenêtre glissante)
# -----------------------------------------------------------------
Write-LogMain "Pré-chargement du cache Sign-Ins (fenêtre : $SignInCacheWindowDays jours)..." -Level INFO
$SignInCache = @{}
try {
    $SignInFromDate = $RunDate.AddDays(-$SignInCacheWindowDays).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    $SignInFilter = "createdDateTime ge $SignInFromDate"
    $RawSignIns = Invoke-GraphWithRetry -MaxAttempts $MaxRetryAttempts -Operation "Get-MgAuditLogSignIn" -ScriptBlock {
        Get-MgAuditLogSignIn -Filter $SignInFilter -Property AppId, CreatedDateTime -All -ErrorAction Stop
    }
    foreach ($si in $RawSignIns) {
        if ($si.AppId -and (-not $SignInCache[$si.AppId] -or $si.CreatedDateTime -gt $SignInCache[$si.AppId])) {
            $SignInCache[$si.AppId] = $si.CreatedDateTime
        }
    }
    Write-LogMain "Cache Sign-Ins : $($SignInCache.Count) app(s) actives sur $SignInCacheWindowDays jours." -Level OK
}
catch {
    Write-LogMain "Cache Sign-Ins inaccessible : $($_.Exception.Message) — poursuite sans." -Level WARN
}

$CollectDuration = [Math]::Round(((Get-Date) - $CollectStart).TotalSeconds)
Write-LogMain "Collecte bulk terminée en ${CollectDuration}s." -Level PERF

# -----------------------------------------------------------------
# Activation du flush mémoire si nécessaire
# -----------------------------------------------------------------
$NeedsMemoryFlush = $AllSPs.Count -gt $FlushThreshold
if ($NeedsMemoryFlush) {
    Write-LogMain "Flush mémoire activé : $($AllSPs.Count) SP > $FlushThreshold — des fichiers temporaires seront créés." -Level WARN
    if (-not (Test-Path $FlushTempDir)) {
        New-Item -ItemType Directory -Path $FlushTempDir -Force | Out-Null
    }

    Get-ChildItem -Path $OutputDir -Filter "FlushTemp_*" -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -ne "FlushTemp_$RunTimestamp" } |
        ForEach-Object {
            try {
                Remove-Item $_.FullName -Recurse -Force -ErrorAction SilentlyContinue
                Write-LogMain "FlushTemp orphelin supprimé : $($_.Name)" -Level WARN
            } catch {}
        }
}

#endregion

# ================================================================================================================================
# PRÉPARATION DE L'ANALYSE PARALLÈLE
# ================================================================================================================================

#region ═════════════════════════ INITIALISATION ANALYSE PARALLÈLE ═════════════════════

Write-LogMain "ANALYSE PARALLÈLE — ThrottleLimit $ThrottleLimit / Smart Alerts V5.2" -Level SECTION
$AnalysisStart = Get-Date

$ExecutionStartTime    = $RunDate
$ShouldStop            = [bool[]]::new(1)
$ShouldStop[0]         = $false
$u_ShouldStop          = $ShouldStop
$u_MaxExecutionMinutes = $MaxExecutionMinutes

# === COLLECTIONS THREAD-SAFE (ConcurrentBag) ===
$ReportBag        = [System.Collections.Concurrent.ConcurrentBag[PSCustomObject]]::new()
$DriftAlertsBag   = [System.Collections.Concurrent.ConcurrentBag[PSCustomObject]]::new()
$QuarantineLogBag = [System.Collections.Concurrent.ConcurrentBag[PSCustomObject]]::new()
$RemediationLogBag= [System.Collections.Concurrent.ConcurrentBag[PSCustomObject]]::new()
$NewStateBag      = [System.Collections.Concurrent.ConcurrentBag[PSCustomObject]]::new()

# === VARIABLES À PASSER DANS LE BLOC PARALLÈLE (préfixe u_ pour éviter les collisions) ===
$u_MicrosoftTenantId        = $MicrosoftTenantId
$u_WhitelistedAppIds        = $WhitelistedAppIds
$u_ExpectedDriftAppIds      = $ExpectedDriftAppIds
$u_PreviousStateIndex       = $PreviousStateIndex
$u_SignInCache              = $SignInCache
$u_GrantsByClientId         = $GrantsByClientId
$u_SPById                   = $SPById
$u_Tier1Patterns            = $Tier1Patterns
$u_Tier2Patterns            = $Tier2Patterns
$u_TagQuarantinePrefix      = $TagQuarantinePrefix
$u_TagDisabledValue         = $TagDisabledValue
$u_InactivityThresholdDays  = $InactivityThresholdDays
$u_SecretExpiryWarningDays  = $SecretExpiryWarningDays
$u_SignInCacheWindowDays    = $SignInCacheWindowDays
$u_TeamsAlertScoreThreshold = $TeamsAlertScoreThreshold
$u_DoRemediate              = $RemediateHighRisk
$u_RemediationScoreThreshold= $RemediationScoreThreshold
$u_QuarantineHours          = $QuarantineHours
$u_MaxRetryAttempts         = $MaxRetryAttempts
$u_RunDate                  = $RunDate
$u_GraphContextAccount      = if ($GraphContext.AppName) { $GraphContext.AppName } else { $GraphContext.Account }
$u_ExecutionLogPath         = $ExecutionLogPath
$u_IsWhatIf                 = $IsWhatIf
$u_NeedsMemoryFlush         = $NeedsMemoryFlush
$u_FlushTempDir             = $FlushTempDir

Write-LogMain "Lancement de l'analyse parallèle sur $($AllSPs.Count) Service Principals..." -Level INFO

#endregion
$AllSPs | ForEach-Object -Parallel {

    $SP = $_

    # Récupération des variables depuis le scope principal
    $MicTenantId        = $using:u_MicrosoftTenantId
    $WhitelistIds       = $using:u_WhitelistedAppIds
    $ExpectedDriftIds   = $using:u_ExpectedDriftAppIds
    $PrevStateIdx       = $using:u_PreviousStateIndex
    $SICache            = $using:u_SignInCache
    $GrantsIdx          = $using:u_GrantsByClientId
    $SPIndex            = $using:u_SPById
    $T1Patterns         = $using:u_Tier1Patterns
    $T2Patterns         = $using:u_Tier2Patterns
    $QPrefix            = $using:u_TagQuarantinePrefix
    $QDisabled          = $using:u_TagDisabledValue
    $InactDays          = $using:u_InactivityThresholdDays
    $SecExpDays         = $using:u_SecretExpiryWarningDays
    $SICacheDays        = $using:u_SignInCacheWindowDays
    $TeamsThreshold     = $using:u_TeamsAlertScoreThreshold
    $DoRemediate        = $using:u_DoRemediate
    $RemScoreThreshold  = $using:u_RemediationScoreThreshold
    $QHours             = $using:u_QuarantineHours
    $MaxRetry           = $using:u_MaxRetryAttempts
    $RunDt              = $using:u_RunDate
    $GraphOpAccount     = $using:u_GraphContextAccount
    $LogPath            = $using:u_ExecutionLogPath
    $IsWhatIfMode       = $using:u_IsWhatIf
    $NeedsFlush         = $using:u_NeedsMemoryFlush
    $FlushDir           = $using:u_FlushTempDir

    # Collections thread-safe (ConcurrentBag)
    $ReportBag  = $using:ReportBag
    $DriftBag   = $using:DriftAlertsBag
    $QLogBag    = $using:QuarantineLogBag
    $RLogBag    = $using:RemediationLogBag
    $StateBag   = $using:NewStateBag

    # ===================================================================
    # FONCTIONS INTERNES AU RUNSPACE (définies localement)
    # ===================================================================

    # --- Log parallèle thread-safe (fichier + console) avec Mutex UNIQUE par runspace ---
    $LogMutex = [System.Threading.Mutex]::new($false, "Global\ShadowIT_LogMutex")

    function Write-ParallelLog {
        param([string]$Level, [string]$Message)
        $ts    = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $color = switch ($Level) {
            "INFO"   { "Cyan" }  "OK"     { "Green" }  "WARN"   { "Yellow" }
            "ERROR"  { "Red" }   "ACTION" { "Magenta" } "WHATIF" { "DarkYellow" }
            default  { "Gray" }
        }
        $logAcquired = $false
        try {
            if ($LogMutex -and $LogMutex.SafeWaitHandle -and -not $LogMutex.SafeWaitHandle.IsClosed) {
                $logAcquired = $LogMutex.WaitOne(2000)
                # Si $logAcquired = $false (timeout) : output best-effort sans protection — interleaving possible
            }
            Write-Host "$($ts.Substring(11)) [$Level] $Message" -ForegroundColor $color
            Add-Content -Path $LogPath -Value "$ts | $($Level.PadRight(7)) | $Message" -Encoding UTF8 -ErrorAction SilentlyContinue
        }
        catch { }
        finally {
            try {
                if ($logAcquired -and $LogMutex -and $LogMutex.SafeWaitHandle -and -not $LogMutex.SafeWaitHandle.IsClosed) {
                    $LogMutex.ReleaseMutex()
                }
            }
            catch {}
        }
    }

    # --- Retry local au runspace (backoff exponentiel) ---
    function Invoke-GraphRetryLocal {
        param([scriptblock]$ScriptBlock, [int]$MaxAttempts = 3, [string]$Operation = "Graph")
        $attempt = 0; $baseDelay = 2
        while ($attempt -lt $MaxAttempts) {
            $attempt++
            try { return (& $ScriptBlock) }
            catch {
                $errMsg     = $_.Exception.Message
                $statusCode = $null
                try { $statusCode = [int]$_.Exception.Response.StatusCode } catch {}

                if ($statusCode -in @(400, 401, 403, 404)) {
                    Write-ParallelLog "ERROR" "[$($SP.DisplayName)][$Operation] Erreur permanente ($statusCode) — abandon."
                    throw $_
                }
                if ($attempt -ge $MaxAttempts) {
                    Write-ParallelLog "ERROR" "[$($SP.DisplayName)][$Operation] ÉCHEC après $MaxAttempts tentatives — $errMsg"
                    throw $_
                }
                $retryAfter = $null
                try { $retryAfter = [int]$_.Exception.Response.Headers.GetValues("Retry-After")[0] } catch {}
                $delay = if ($retryAfter -and $retryAfter -gt 0) { $retryAfter } else { [Math]::Pow(2, $attempt) * $baseDelay }
                Write-ParallelLog "WARN" "[$($SP.DisplayName)][$Operation] Retry $attempt/$MaxAttempts — HTTP:$statusCode — attente ${delay}s"
                Start-Sleep -Seconds $delay
            }
        }
    }

    # --- Scoring Tiered local ---
    function Invoke-RiskScoringLocal {
        param([string[]]$Perms, [bool]$IsTp, [bool]$IsIn, [bool]$HasSec, [string[]]$T1P, [string[]]$T2P)
        $score = 0; $t1p = @(); $t2p = @(); $rp = @()
        foreach ($perm in $Perms) {
            $inT1 = $false
            foreach ($pattern in $T1P) { if ($perm -like $pattern) { $inT1 = $true; break } }
            if ($inT1) { $t1p += $perm; continue }

            $inT2 = $false
            foreach ($pattern in $T2P) { if ($perm -like $pattern) { $inT2 = $true; break } }
            if ($inT2) { $t2p += $perm; continue }

            if ($perm -like "*Read*") { $rp += $perm }
        }

        # Tier 1 : +50 pts première, +10 suivantes, plafond 70
        $t1Score = 0
        for ($i = 0; $i -lt $t1p.Count; $i++) { $t1Score += if ($i -eq 0) { 50 } else { 10 } }
        $score += [Math]::Min($t1Score, 70)

        # Tier 2 : +30 pts première, +10 suivantes, plafond 45
        $t2Score = 0
        for ($i = 0; $i -lt $t2p.Count; $i++) { $t2Score += if ($i -eq 0) { 30 } else { 10 } }
        $score += [Math]::Min($t2Score, 45)

        # Read non critiques : +2 pts par permission
        $score += ($rp.Count * 2)

        # Majorations contextuelles
        if ($IsTp)  { $score += 20 }
        if ($IsIn)  { $score += 15 }
        if ($HasSec) { $score += 10 }

        return @{
            Score      = [Math]::Min($score, 100)
            HasTier1   = ($t1p.Count -gt 0)
            HasTier2   = ($t2p.Count -gt 0)
            Tier1Perms = $t1p
            Tier2Perms = $t2p
        }
    }

    # ===================================================================
    # CHARGEMENT DES MODULES GRAPH (OBLIGATOIRE DANS LE RUNSPACE)
    # ===================================================================
    try {
        Import-Module Microsoft.Graph.Applications -ErrorAction Stop -DisableNameChecking
        Import-Module Microsoft.Graph.Authentication -ErrorAction Stop -DisableNameChecking
        Import-Module Microsoft.Graph.Reports -ErrorAction SilentlyContinue -DisableNameChecking
        Import-Module Microsoft.Graph.Users -ErrorAction SilentlyContinue -DisableNameChecking
    }
    catch {
        Write-ParallelLog "ERROR" "[$($SP.DisplayName)] Impossible de charger les modules Graph : $($_.Exception.Message)"
        $LogMutex.Dispose()
        return
    }

    # ===================================================================
    # TRY GLOBAL
    # ===================================================================
    try {

        # -----------------------------------------------------------------
        # ÉTAPE 2 : EARLY EXIT (Apps Microsoft désactivées)
        # -----------------------------------------------------------------
        $IsThirdParty = ($SP.AppOwnerOrganizationId -and
                         $SP.AppOwnerOrganizationId -ne "" -and
                         $SP.AppOwnerOrganizationId -ne $MicTenantId)

        if (-not $IsThirdParty -and $SP.AccountEnabled -eq $false) {
            Write-ParallelLog "INFO" "[$($SP.DisplayName)] Ignorée (MS désactivée)"
            return
        }

        # Soft-exit gracieux : le runspace courant est abandonné, les runspaces en cours finissent normalement
        # $ShouldStop[0] = $true signale aux runspaces suivants d'abandonner sans traitement
        $elapsedMin = ((Get-Date) - $RunDt).TotalMinutes
        if ($elapsedMin -ge $using:u_MaxExecutionMinutes) {
            $stopArr        = $using:u_ShouldStop
            $stopArr[0]     = $true
            Write-ParallelLog "WARN" "[$($SP.DisplayName)] Soft-exit timeout ($([Math]::Round($elapsedMin))min >= $($using:u_MaxExecutionMinutes)min) — rapport dégradé."
            return
        }
        # Vérification du signal d'arrêt posé par un runspace précédent
        if ($using:u_ShouldStop[0]) { return }

        $IsExpectedDrift = $ExpectedDriftIds -contains $SP.AppId
        $IsWhitelisted   = $WhitelistIds -contains $SP.AppId

        # -----------------------------------------------------------------
        # ÉTAPE 3 : COLLECTE LOCALE
        # -----------------------------------------------------------------
        # OAuth2 avec double lookup
        $DelegatedScopes = @()
        $HasUserConsent  = $false
        $GrantsForSP = $GrantsIdx[$SP.Id]
        if (-not $GrantsForSP) { $GrantsForSP = $GrantsIdx[$SP.AppId] }
        if ($GrantsForSP) {
            foreach ($grant in $GrantsForSP) {
                $DelegatedScopes += ($grant.Scope -split "\s+" | Where-Object { $_ })
                if ($grant.ConsentType -ne "AllPrincipals") { $HasUserConsent = $true }
            }
        }
        $DelegatedScopes       = $DelegatedScopes | Sort-Object -Unique
        $ConsentTypeNormalized = if ($HasUserConsent) { "UserConsent" } else { "AdminConsent" }

        # Rôles applicatifs
        $AppPermissions = @()
        try {
            $Assignments = Invoke-GraphRetryLocal -MaxAttempts $MaxRetry -Operation "AppRoleAssignments" -ScriptBlock {
                Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $SP.Id -All -ErrorAction Stop
            }
            foreach ($assign in $Assignments) {
                $ResourceSP = $SPIndex[$assign.ResourceId]
                if ($ResourceSP) {
                    $Role = $ResourceSP.AppRoles | Where-Object { $_.Id -eq $assign.AppRoleId }
                    if ($Role -and $Role.Value) { $AppPermissions += $Role.Value }
                }
            }
            $AppPermissions = $AppPermissions | Sort-Object -Unique
        }
        catch {
            Write-ParallelLog "WARN" "[$($SP.DisplayName)] AppRoles inaccessibles : $($_.Exception.Message)"
        }

        # Propriétaires (avec gestion Group/SP)
        $OwnerNames      = @()
        $OwnerNormalized = ""
        try {
            $Owners = Invoke-GraphRetryLocal -MaxAttempts $MaxRetry -Operation "Owners" -ScriptBlock {
                Get-MgServicePrincipalOwner -ServicePrincipalId $SP.Id -All -ErrorAction Stop
            }
            foreach ($owner in $Owners) {
                $odataType = $owner.AdditionalProperties["@odata.type"]
                if ($odataType -and $odataType -like "*group*") {
                    $OwnerNames += "[Groupe] $($owner.Id)"
                }
                elseif ($owner.AdditionalProperties["displayName"]) {
                    $OwnerNames += $owner.AdditionalProperties["displayName"]
                }
                elseif ($owner.AdditionalProperties["userPrincipalName"]) {
                    $OwnerNames += $owner.AdditionalProperties["userPrincipalName"]
                }
                elseif ($owner.AdditionalProperties["appId"]) {
                    $OwnerNames += "[App] $($owner.AdditionalProperties['appId'])"
                }
                else {
                    $OwnerNames += $owner.Id
                }
            }
            $OwnerNormalized = ($OwnerNames | Sort-Object) -join ";"
        }
        catch {
            Write-ParallelLog "WARN" "[$($SP.DisplayName)] Owners inaccessibles : $($_.Exception.Message)"
        }

        # Secrets & Certificats
        $HasExpiringSecret  = $false    # Secret expirant dans < $SecExpDays jours (scoring)
        $HasExpiredSecret   = $false    # Secret déjà expiré (hygiene distincte du scoring)
        $CredentialsSummary = @()

        foreach ($cred in $SP.PasswordCredentials) {
            $expiryStr = "N/A"
            if ($cred.EndDateTime) {
                $daysLeft  = ($cred.EndDateTime - $RunDt).Days
                $expiryStr = $cred.EndDateTime.ToString("dd/MM/yyyy")

                if ($daysLeft -lt 0) {
                    $HasExpiredSecret = $true
                    $expiryStr        = "EXPIRÉ ($([Math]::Abs($daysLeft))j)"
                }
                elseif ($daysLeft -ge 0 -and $daysLeft -lt $SecExpDays) {
                    $HasExpiringSecret = $true
                }
            }
            $CredentialsSummary += "Secret[$($cred.DisplayName -replace ',',';')]_Exp:$expiryStr"
        }
        foreach ($cert in $SP.KeyCredentials) {
            $exp = if ($cert.EndDateTime) { $cert.EndDateTime.ToString("dd/MM/yyyy") } else { "N/A" }
            $CredentialsSummary += "Cert[$($cert.DisplayName -replace ',',';')]_Exp:$exp"
        }

        $PenaltySecret = if ($IsExpectedDrift) { $false } else { $HasExpiringSecret }

        # Sign-in (cache O(1))
        $LastSignInDate = $SICache[$SP.AppId]
        $IsInactive     = $false
        if (-not $LastSignInDate -and $SP.CreatedDateTime -and ($RunDt - $SP.CreatedDateTime).Days -gt $InactDays) {
            $IsInactive = $true
        }

        # Verified Publisher (sans opérateur `?.`)
        $IsVerifiedPublisher = $false
        if ($SP.VerifiedPublisher) {
            $IsVerifiedPublisher = ($SP.VerifiedPublisher.VerifiedPublisherId -and $SP.VerifiedPublisher.VerifiedPublisherId -ne "")
        }

        # -----------------------------------------------------------------
        # ÉTAPE 4 : SCORING & EXPECTED DRIFT
        # -----------------------------------------------------------------
        $AllPerms    = ($DelegatedScopes + $AppPermissions) | Sort-Object -Unique
        $ScoreResult = Invoke-RiskScoringLocal -Perms $AllPerms `
                            -IsTp $IsThirdParty -IsIn $IsInactive -HasSec $PenaltySecret `
                            -T1P $T1Patterns -T2P $T2Patterns
        $RawScore   = $ScoreResult.Score
        $HasTier1   = $ScoreResult.HasTier1
        $HasTier2   = $ScoreResult.HasTier2
        $Tier1Perms = $ScoreResult.Tier1Perms
        $Tier2Perms = $ScoreResult.Tier2Perms

        $FinalScore = if ($IsWhitelisted) { 0 } else { $RawScore }

        $RiskLabel = if ($IsWhitelisted) { "RISQUE ACCEPTÉ" }
                     elseif ($FinalScore -ge 70) { "CRITIQUE" }
                     elseif ($FinalScore -ge 40) { "ÉLEVÉ" }
                     elseif ($FinalScore -ge 20) { "MOYEN" }
                     else { "FAIBLE" }

        # -----------------------------------------------------------------
        # TAGS ACTUELS (lecture initiale)
        # -----------------------------------------------------------------
        $CurrentTags      = if ($SP.Tags) { @($SP.Tags) } else { @() }
        $QuarantineTag    = $CurrentTags | Where-Object { $_ -like "$QPrefix*" } | Select-Object -First 1
        $IsAlreadyDisabled= $CurrentTags -contains $QDisabled
        $IsInQuarantine   = $QuarantineTag -ne $null
        $QuarantineDate   = $null
        $QuarantineExpired= $false

        if ($IsInQuarantine -and $QuarantineTag) {
            try {
                $QuarantineDate    = [DateTime]::ParseExact(($QuarantineTag -replace $QPrefix, ""), "yyyyMMdd", $null)
                $QuarantineExpired = ($RunDt - $QuarantineDate).TotalHours -gt $QHours
            }
            catch {
                Write-ParallelLog "WARN" "[$($SP.DisplayName)] Impossible de parser la date du tag quarantaine '$QuarantineTag'."
            }
        }

        # -----------------------------------------------------------------
        # ÉTAPE 5 : SMART ALERTS & DRIFT DETECTION
        # -----------------------------------------------------------------
        $Flags = [System.Collections.Generic.List[string]]::new()
        if ($IsWhitelisted)                                   { $Flags.Add("✅ WHITELISTÉ") }
        if ($HasUserConsent)                                  { $Flags.Add("🚨 USER CONSENT") }
        if ($IsThirdParty -and -not $IsVerifiedPublisher)     { $Flags.Add("⚠️ UNVERIFIED PUBLISHER") }
        if ($IsInactive)                                      { $Flags.Add("🕒 INACTIF") }
        if ($IsInQuarantine -and -not $IsAlreadyDisabled)     { $Flags.Add("⏳ EN QUARANTAINE ($QuarantineTag)") }
        if ($IsAlreadyDisabled)                               { $Flags.Add("🔒 DÉSACTIVÉ PAR AUDIT") }
        # FIX-005 : deux flags distincts selon l'état réel du secret
        if ($HasExpiringSecret -and -not $IsExpectedDrift)    { $Flags.Add("🔑 SECRET EXP.") }
        if ($HasExpiredSecret)                                { $Flags.Add("💀 SECRET EXPIRÉ") }
        if ($IsExpectedDrift)                                 { $Flags.Add("🔄 ROTATION ATTENDUE") }

        # Smart Alerts
        if ($HasTier1 -and $OwnerNames.Count -eq 0 -and -not $IsWhitelisted) {
            $Flags.Add("🚨 ORPHANED CRITICAL")
        }
        if ($HasTier1 -and $HasUserConsent -and -not $IsWhitelisted) {
            $Flags.Add("☢️ TOXIC CONSENT")
        }
        if ($IsInactive -and ($HasTier1 -or $HasTier2) -and -not $IsWhitelisted) {
            $Flags.Add("👻 DORMANT PRIVILEGED APP")
        }
        if ($IsThirdParty -and -not $IsVerifiedPublisher -and $HasTier1 -and -not $IsWhitelisted) {
            $Flags.Add("⚠️ UNTRUSTED HIGH PRIVILEGE")
        }

        # Drift Detection
        $DriftStatus  = $null
        $DriftDetails = [System.Collections.Generic.List[string]]::new()

        if ($PrevStateIdx.Count -gt 0) {
            if (-not $PrevStateIdx.ContainsKey($SP.AppId)) {
                $DriftStatus = "NOUVELLE APP"
                $Flags.Add("🆕 NOUVELLE APP")
                $DriftDetails.Add("Application jamais vue lors de la dernière exécution.")
            }
            else {
                $Prev = $PrevStateIdx[$SP.AppId]

                # Comparaison 1 — Permissions
                $PrevPerms = if ($Prev.AllPermissions) { $Prev.AllPermissions -split ";" | Where-Object { $_ } } else { @() }
                $NewPerms = $AllPerms | Where-Object { $PrevPerms -notcontains $_ }
                if ($NewPerms.Count -gt 0) {
                    if (-not $DriftStatus) { $DriftStatus = "ESCALADE PERMS" }
                    $Flags.Add("📈 ESCALADE PERMS (+$($NewPerms.Count))")
                    $DriftDetails.Add("Nouvelles permissions : $($NewPerms -join ', ')")
                }

                # Comparaison 2 — Owner (supprimé si ExpectedDrift)
                $PrevOwner = if ($Prev.OwnerNormalized) { $Prev.OwnerNormalized } else { "" }
                if ($PrevOwner -ne $OwnerNormalized) {
                    if ($IsExpectedDrift) {
                        $DriftDetails.Add("Changement owner ignoré (rotation attendue).")
                    }
                    else {
                        if (-not $DriftStatus) { $DriftStatus = "CHANGEMENT OWNER" }
                        $Flags.Add("🔄 CHANGEMENT OWNER")
                        $DriftDetails.Add("Owner : '$PrevOwner' → '$OwnerNormalized'")
                    }
                }

                # Comparaison 3 — ConsentType
                $PrevConsent = if ($Prev.ConsentType) { $Prev.ConsentType } else { "AdminConsent" }
                if ($PrevConsent -ne $ConsentTypeNormalized) {
                    if (-not $DriftStatus) { $DriftStatus = "CHANGEMENT CONSENT" }
                    $Flags.Add("🚨 CHANGEMENT CONSENT")
                    $DriftDetails.Add("Consent : '$PrevConsent' → '$ConsentTypeNormalized'")
                }

                # Comparaison 4 — AccountEnabled (réactivation)
                $PrevEnabled = if ($null -ne $Prev.AccountEnabled) { [bool]$Prev.AccountEnabled } else { $true }
                if ($PrevEnabled -eq $false -and $SP.AccountEnabled -eq $true) {
                    if (-not $DriftStatus) { $DriftStatus = "STATUT MODIFIÉ" }
                    $Flags.Add("⚠️ STATUT MODIFIÉ")
                    $DriftDetails.Add("Compte réactivé (était désactivé au dernier audit).")
                }
            }

            if ($DriftStatus -and $FinalScore -ge $TeamsThreshold) {
                $DriftBag.Add([PSCustomObject]@{
                    AppName      = $SP.DisplayName
                    AppId        = $SP.AppId
                    DriftStatus  = $DriftStatus
                    DriftDetails = $DriftDetails -join " | "
                    Score        = $FinalScore
                    RiskLabel    = $RiskLabel
                    Flags        = ($Flags -join ", ")
                })
            }
        }

        # -----------------------------------------------------------------
        # SAUVEGARDE ÉTAT (pour prochaine exécution)
        # -----------------------------------------------------------------
        $StateBag.Add([PSCustomObject]@{
            AppId           = $SP.AppId
            DisplayName     = $SP.DisplayName
            AllPermissions  = ($AllPerms -join ";")
            OwnerNormalized = $OwnerNormalized
            ConsentType     = $ConsentTypeNormalized
            AccountEnabled  = $SP.AccountEnabled
            ScoreRisque     = $FinalScore
            LastSeen        = $RunDt.ToString("o")
        })

        # -----------------------------------------------------------------
        # ÉTAPE 6 : REMÉDIATION (avec mutex et vérification AccountEnabled)
        # -----------------------------------------------------------------
        $StatutQuarantaine = if ($IsAlreadyDisabled) {
            "DÉSACTIVÉ"
        }
        elseif ($IsInQuarantine) {
            "QUARANTAINE ($QuarantineTag)"
        }
        else { "" }

        # Note : Les mutex ci-dessous protègent UNIQUEMENT la concurrence locale.
        # Pour une exécution CI/CD multi-agents, sérialiser au niveau du pipeline.
        if ($DoRemediate -and $FinalScore -ge $RemScoreThreshold -and -not $IsWhitelisted) {

            # Refresh Tags + AccountEnabled avant toute action
            $FreshSP = $null
            try {
                $FreshSP = Invoke-GraphRetryLocal -MaxAttempts $MaxRetry -Operation "RefreshTags" -ScriptBlock {
                    Get-MgServicePrincipal -ServicePrincipalId $SP.Id -Property Tags, AccountEnabled -ErrorAction Stop
                }
            }
            catch {
                Write-ParallelLog "ERROR" "[$($SP.DisplayName)] Refresh Tags/AccountEnabled échoué : $($_.Exception.Message) — abandon de la remédiation."
            }

            if ($FreshSP) {

                # Vérification intervention humaine (compte réactivé depuis l'initialisation)
                $InitialAccountEnabled = $SP.AccountEnabled
                if ($InitialAccountEnabled -eq $false -and $FreshSP.AccountEnabled -eq $true) {
                    Write-ParallelLog "WARN" "[$($SP.DisplayName)] Intervention humaine détectée (compte réactivé). Abandon de la remédiation."
                }
                else {
                    # Si Tags est null après refresh (tags vidés externement), conserver les tags initiaux
                    if ($null -eq $FreshSP.Tags) {
                        Write-ParallelLog "WARN" "[$($SP.DisplayName)] FreshSP.Tags null après refresh (tags vidés ?) — conservation de l'état initial."
                        $CurrentTags = if ($SP.Tags) { @($SP.Tags) } else { @() }
                    }
                    else {
                        $CurrentTags = @($FreshSP.Tags)
                    }
                    $QuarantineTag     = $CurrentTags | Where-Object { $_ -like "$QPrefix*" } | Select-Object -First 1
                    $IsAlreadyDisabled = $CurrentTags -contains $QDisabled
                    $IsInQuarantine    = $QuarantineTag -ne $null
                    $QuarantineDate    = $null
                    $QuarantineExpired = $false
                    if ($IsInQuarantine -and $QuarantineTag) {
                        try {
                            $QuarantineDate    = [DateTime]::ParseExact(($QuarantineTag -replace $QPrefix, ""), "yyyyMMdd", $null)
                            $QuarantineExpired = ($RunDt - $QuarantineDate).TotalHours -gt $QHours
                        }
                        catch {}
                    }

                    # ⚠️ ARCHITECTURE NOTE : Les mutex de ce script protègent la concurrence LOCALE (15 threads). Pour une exécution distribuée CI/CD, sérialisez le pipeline via l'orchestrateur (ex: Concurrency GitHub Actions).
                    $RemediationMutex = [System.Threading.Mutex]::new($false, "Global\ShadowIT_RemediationMutex")
                    $acquired = $false
                    try {
                        $acquired = $RemediationMutex.WaitOne(15000)
                        if (-not $acquired) {
                            Write-ParallelLog "WARN" "[$($SP.DisplayName)] Mutex de remédiation timeout. Abandon pour ce SP."
                        }
                        else {
                            # --- Mise en quarantaine ---
                            if (-not $IsInQuarantine -and -not $IsAlreadyDisabled) {
                                $NewQTag    = "$QPrefix$($RunDt.ToString('yyyyMMdd'))"
                                $UpdatedTags = @($CurrentTags) + $NewQTag

                                if ($IsWhatIfMode) {
                                    Write-ParallelLog "WHATIF" "[WHATIF] Simulerait : Ajout tag '$NewQTag' sur '$($SP.DisplayName)' (Score: $FinalScore)"
                                    $QLogBag.Add([PSCustomObject]@{ Timestamp = $RunDt.ToString("o"); AppName = $SP.DisplayName; AppId = $SP.AppId; Score = $FinalScore; Action = "QUARANTINE_TAGGED"; Tag = $NewQTag; Status = "SIMULATED (WHATIF)"; Operator = $GraphOpAccount })
                                    $Flags.Add("⏳ MISE EN QUARANTAINE [SIMULÉ]")
                                    $StatutQuarantaine = "QUARANTAINE ($NewQTag) [SIMULÉ]"
                                }
                                else {
                                    try {
                                        Write-ParallelLog "ACTION" "QUARANTAINE ÉTAPE 1 : '$($SP.DisplayName)' → Tag '$NewQTag'"
                                        Update-MgServicePrincipal -ServicePrincipalId $SP.Id -Tags $UpdatedTags -ErrorAction Stop
                                        Write-ParallelLog "OK" "Tag quarantaine appliqué sur '$($SP.DisplayName)'."
                                        $Flags.Add("⏳ MISE EN QUARANTAINE")
                                        $StatutQuarantaine = "QUARANTAINE ($NewQTag)"
                                        $QLogBag.Add([PSCustomObject]@{ Timestamp = $RunDt.ToString("o"); AppName = $SP.DisplayName; AppId = $SP.AppId; Score = $FinalScore; Action = "QUARANTINE_TAGGED"; Tag = $NewQTag; Status = "SUCCESS"; Operator = $GraphOpAccount })
                                    }
                                    catch {
                                        Write-ParallelLog "ERROR" "ÉCHEC tag quarantaine '$($SP.DisplayName)' : $($_.Exception.Message)"
                                        $QLogBag.Add([PSCustomObject]@{ Timestamp = $RunDt.ToString("o"); AppName = $SP.DisplayName; AppId = $SP.AppId; Score = $FinalScore; Action = "QUARANTINE_TAGGED"; Tag = $NewQTag; Status = "FAILED: $($_.Exception.Message)"; Operator = $GraphOpAccount })
                                    }
                                }
                            }

                            # --- Désactivation définitive ---
                            elseif ($IsInQuarantine -and $QuarantineExpired -and -not $IsAlreadyDisabled) {
                                $UpdatedTags = @($CurrentTags | Where-Object { $_ -ne $QuarantineTag }) + $QDisabled

                                if ($IsWhatIfMode) {
                                    Write-ParallelLog "WHATIF" "[WHATIF] Simulerait : Désactivation de '$($SP.DisplayName)' (quarantaine expirée depuis $([Math]::Round(($RunDt - $QuarantineDate).TotalHours))h)"
                                    $RLogBag.Add([PSCustomObject]@{ Timestamp = $RunDt.ToString("o"); AppName = $SP.DisplayName; AppId = $SP.AppId; Score = $FinalScore; Action = "ACCOUNT_DISABLED"; QuarantineTag = $QuarantineTag; Status = "SIMULATED (WHATIF)"; Operator = $GraphOpAccount })
                                    $Flags.Add("🔒 DÉSACTIVÉ PAR AUDIT [SIMULÉ]")
                                    $StatutQuarantaine = "DÉSACTIVÉ [SIMULÉ]"
                                }
                                else {
                                    try {
                                        Write-ParallelLog "ACTION" "DÉSACTIVATION ÉTAPE 2 : '$($SP.DisplayName)' (quarantaine depuis $([Math]::Round(($RunDt - $QuarantineDate).TotalHours))h)"
                                        Update-MgServicePrincipal -ServicePrincipalId $SP.Id `
                                            -AccountEnabled:$false -Tags $UpdatedTags -ErrorAction Stop
                                        Write-ParallelLog "OK" "Service Principal '$($SP.DisplayName)' désactivé."
                                        $Flags.Add("🔒 DÉSACTIVÉ PAR AUDIT")
                                        $StatutQuarantaine = "DÉSACTIVÉ"
                                        $RLogBag.Add([PSCustomObject]@{ Timestamp = $RunDt.ToString("o"); AppName = $SP.DisplayName; AppId = $SP.AppId; Score = $FinalScore; Action = "ACCOUNT_DISABLED"; QuarantineTag = $QuarantineTag; Status = "SUCCESS"; Operator = $GraphOpAccount })
                                    }
                                    catch {
                                        Write-ParallelLog "ERROR" "ÉCHEC désactivation '$($SP.DisplayName)' : $($_.Exception.Message)"
                                        $RLogBag.Add([PSCustomObject]@{ Timestamp = $RunDt.ToString("o"); AppName = $SP.DisplayName; AppId = $SP.AppId; Score = $FinalScore; Action = "ACCOUNT_DISABLED"; QuarantineTag = $QuarantineTag; Status = "FAILED: $($_.Exception.Message)"; Operator = $GraphOpAccount })
                                    }
                                }
                            }
                        }
                    }
                    catch {
                        Write-ParallelLog "ERROR" "[$($SP.DisplayName)] Exception lors de la remédiation : $($_.Exception.Message)"
                    }
                    finally {
                        if ($RemediationMutex) {
                            if ($acquired) { try { $RemediationMutex.ReleaseMutex() } catch {} }
                            $RemediationMutex.Dispose()
                        }
                    }
                }
            }
        }

        # -----------------------------------------------------------------
        # ÉTAPE 7 : DEEP COPY & AJOUT AU REPORTBAG
        # -----------------------------------------------------------------
        # Sans ce cast, _Flags après sérialisation/désérialisation JSON (flush) devient PSObject[]
        # cassant les switch -Wildcard dans la génération HTML
        $Flags = [string[]]($Flags | Select-Object -Unique)

        # Déterminer le nom de l'éditeur sans utiliser d'opérateur `?.`
        $NomEditeur = "Non vérifié"
        if ($SP.VerifiedPublisher -and $SP.VerifiedPublisher.DisplayName) {
            $NomEditeur = $SP.VerifiedPublisher.DisplayName
        }

        $ReportBag.Add([PSCustomObject]@{
            NomApplication          = $SP.DisplayName
            AppId                   = $SP.AppId
            AppOwnerTenantId        = $SP.AppOwnerOrganizationId
            TypeSP                  = $SP.ServicePrincipalType
            CompteActif             = $SP.AccountEnabled
            DateCreation            = if ($SP.CreatedDateTime) { $SP.CreatedDateTime.ToString("dd/MM/yyyy HH:mm") } else { "N/A" }
            EstTiers                = $IsThirdParty
            EditeurVerifie          = $IsVerifiedPublisher
            NomEditeur              = $NomEditeur
            PermissionsDéléguées    = ($DelegatedScopes -join "; ")
            PermissionsApplicatives = ($AppPermissions -join "; ")
            PermissionsTier1        = ($Tier1Perms -join "; ")
            PermissionsTier2        = ($Tier2Perms -join "; ")
            NbPermsTier1            = $Tier1Perms.Count
            NbPermsTier2            = $Tier2Perms.Count
            TypeConsentement        = if ($HasUserConsent) { "User Consent" } else { "Admin Consent" }
            DernierSignIn           = if ($LastSignInDate) { $LastSignInDate.ToString("dd/MM/yyyy HH:mm") } else { "Hors fenêtre $SICacheDays j" }
            Inactif                 = $IsInactive
            Credentials             = ($CredentialsSummary -join " | ")
            SecretExpirant          = $HasExpiringSecret                           # fait observé brut
            SecretExpire            = $HasExpiredSecret                            # secret déjà périmé
            SecretPenaliteSupprimee = ($IsExpectedDrift -and $HasExpiringSecret)   # décision scoring masquée
            RotationAttendue        = $IsExpectedDrift
            Proprietaires           = ($OwnerNames -join "; ")
            StatutQuarantaine       = $StatutQuarantaine
            ScoreRisque             = $FinalScore
            HasTier1                = $HasTier1
            HasTier2                = $HasTier2
            NiveauRisque            = $RiskLabel
            Whiteliste              = $IsWhitelisted
            DriftStatus             = if ($DriftStatus) { $DriftStatus } else { "" }
            DriftDetails            = ($DriftDetails -join " | ")
            Flags                   = ($Flags -join " | ")
            _Tier1Perms = if ($Tier1Perms -and $Tier1Perms.Count -gt 0) { [string[]]$Tier1Perms.Clone() } else { [string[]]@() }
            _Tier2Perms = if ($Tier2Perms -and $Tier2Perms.Count -gt 0) { [string[]]$Tier2Perms.Clone() } else { [string[]]@() }
            _Flags      = if ($Flags -and $Flags.Count -gt 0) { [string[]]$Flags.Clone() } else { [string[]]@() }
        })


        # ── ÉTAPE 8 : FLUSH MÉMOIRE (Double-Checked Locking) ──────────────────────────
        if ($NeedsFlush) {
            # ($using:u_SharedCounter)[0] est une rvalue → la référence pointe sur une copie
            # $sharedCtr[0] avec $sharedCtr variable locale → référence sur l'élément heap réel
            $sharedCtr = $using:u_SharedCounter
            $sharedNxt = $using:u_SharedNextFlush

            $count = [System.Threading.Interlocked]::Increment([ref]$sharedCtr[0])

            if ($count -ge $sharedNxt[0]) {
                $FlushMutex    = $null
                $flushAcquired = $false
                try {
                    $FlushMutex    = [System.Threading.Mutex]::new($false, "Global\ShadowIT_FlushMutex")
                    $flushAcquired = $FlushMutex.WaitOne(5000)

                    if (-not $flushAcquired) {
                        Write-ParallelLog "WARN" "[FLUSH] Mutex timeout — flush ignoré pour ce cycle."
                    }
                    else {
                        # Redondant vis-à-vis de l'acquire fence implicite du mutex .NET (ECMA-335 I.12.6.5)
                        # Maintenu comme defensive coding — l'indirection PS7 runspace ne garantit pas
                        # que l'accès à $sharedCtr[0] traverse la barrière implicite du runtime CLR
                        [System.Threading.Thread]::MemoryBarrier()

                        # Double vérification avec variables locales (pas d'expression inline $using:)
                        if ($sharedCtr[0] -ge $sharedNxt[0]) {
                            $temp = [System.Collections.Generic.List[PSCustomObject]]::new()
                            $item = $null
                            $localBag = $using:ReportBag
                            while ($localBag.TryTake([ref]$item)) {
                                if ($null -ne $item) { $temp.Add($item) }
                            }
                            if ($temp.Count -gt 0) {
                                # Nanosecondes dans le nom pour éviter les collisions entre runspaces simultanés
                                $flushFile = Join-Path $FlushDir "flush_$(Get-Date -Format 'yyyyMMddHHmmssfffffff').json"
                                $temp | ConvertTo-Json -Depth 5 -Compress | Out-File $flushFile -Encoding UTF8 -Force
                                Write-ParallelLog "INFO" "[FLUSH] $($temp.Count) objets → $(Split-Path $flushFile -Leaf)"
                            }
                            [System.Threading.Interlocked]::Add([ref]$sharedNxt[0], [long]$using:u_FlushThreshold) | Out-Null
                        }
                    }
                }
                catch {
                    Write-ParallelLog "ERROR" "[FLUSH] Exception : $($_.Exception.Message)"
                }
                finally {
                    if ($FlushMutex) {
                        try { if ($flushAcquired) { $FlushMutex.ReleaseMutex() } } catch {}
                        $FlushMutex.Dispose()
                    }
                }
            }
        }

    }
    catch {
        Write-ParallelLog "ERROR" "[$($SP.DisplayName)] Exception non gérée : $($_.Exception.Message)"
    }
    finally {
        # Libération du mutex de log à la toute fin du runspace
        if ($LogMutex) { $LogMutex.Dispose() }
    }

} -ThrottleLimit $ThrottleLimit

if ($ShouldStop[0]) {
    Write-LogMain "AVERTISSEMENT : Exécution interrompue — limite de $MaxExecutionMinutes min atteinte. Rapport dégradé (SPs partiels)." -Level WARN
}

# ===================================================================
# FUSION DES FLUSH TEMPORAIRES AVEC LE REPORTBAG RESTANT
# ===================================================================
if ($NeedsMemoryFlush) {
    Write-LogMain "Fusion des fichiers de flush mémoire..." -Level INFO
    $TempItems = [System.Collections.Generic.List[PSCustomObject]]::new()
    Get-ChildItem -Path $FlushTempDir -Filter "*.json" | ForEach-Object {
        try {
            $data = Get-Content $_.FullName -Raw | ConvertFrom-Json
            if ($data) { $TempItems.AddRange(@($data)) }
            Remove-Item $_.FullName -Force
        }
        catch {
            Write-LogMain "Erreur fusion flush : $($_.FullName) - $($_.Exception.Message)" -Level WARN
        }
    }
    # Ajout des éléments fusionnés au report bag
    foreach ($item in $TempItems) { $ReportBag.Add($item) }
    Remove-Item $FlushTempDir -Force -ErrorAction SilentlyContinue
}

# ===================================================================
# CONVERSION DES ConcurrentBag EN TABLEAUX TRIÉS
# ===================================================================
$Report         = $ReportBag.ToArray() | Sort-Object ScoreRisque -Descending
$DriftAlerts    = $DriftAlertsBag.ToArray()
$QuarantineLog  = $QuarantineLogBag.ToArray()
$RemediationLog = $RemediationLogBag.ToArray()
$NewStateList   = $NewStateBag.ToArray()

# Déduplication par AppId : élimine les doublons créés par un double-flush éventuel
# Conserve l'entrée avec le score le plus élevé par AppId
$Report = @(
    $Report |
        Sort-Object ScoreRisque -Descending |
        Group-Object AppId |
        ForEach-Object { $_.Group[0] }
) | Sort-Object ScoreRisque -Descending

$AnalysisDuration = [Math]::Round(((Get-Date) - $AnalysisStart).TotalSeconds)
Write-LogMain "Analyse parallèle terminée en ${AnalysisDuration}s — $($Report.Count) app(s) traitée(s)." -Level PERF
# ================================================================================================================================
# ÉTAPE 6 : SAUVEGARDE ÉTAT DRIFT & LOGS
# ================================================================================================================================

#region ═════════════════════════ ÉTAPE 6 : SAUVEGARDE ÉTAT DRIFT & LOGS ═════════════

Write-LogMain "SAUVEGARDE DE L'ÉTAT DRIFT V5.2" -Level SECTION
try {
    $NewStateList | ConvertTo-Json -Depth 5 | Out-File $StatePath -Encoding UTF8 -Force
    Write-LogMain "État sauvegardé : $StatePath ($($NewStateList.Count) entrées)." -Level OK
}
catch {
    Write-LogMain "Erreur état : $($_.Exception.Message)" -Level WARN
}

if ($QuarantineLog.Count -gt 0) {
    $QPath = Join-Path $OutputDir "ShadowIT_Quarantine_$RunTimestamp.json"
    try {
        $QuarantineLog | ConvertTo-Json -Depth 5 | Out-File $QPath -Encoding UTF8 -Force
        Write-LogMain "Log quarantaine : $QPath ($($QuarantineLog.Count) action(s))." -Level OK
    }
    catch {
        Write-LogMain "Erreur export log quarantaine : $($_.Exception.Message)" -Level WARN
    }
}

if ($RemediationLog.Count -gt 0) {
    $RPath = Join-Path $OutputDir "ShadowIT_Remediation_$RunTimestamp.json"
    try {
        $RemediationLog | ConvertTo-Json -Depth 5 | Out-File $RPath -Encoding UTF8 -Force
        Write-LogMain "Log remédiation : $RPath ($($RemediationLog.Count) action(s))." -Level OK
    }
    catch {
        Write-LogMain "Erreur export log remédiation : $($_.Exception.Message)" -Level WARN
    }
}

#endregion

# ================================================================================================================================
# ÉTAPE 7 : ALERTES TEAMS
# ================================================================================================================================

#region ═════════════════════════ ÉTAPE 7 : ALERTES TEAMS ═════════════════════════════

Write-LogMain "ALERTES TEAMS" -Level SECTION

if ($TeamsWebhookUrl -and $DriftAlerts.Count -gt 0) {
    Write-LogMain "$($DriftAlerts.Count) alerte(s) à envoyer..." -Level INFO

    foreach ($alert in $DriftAlerts) {
        $riskColor = switch ($alert.RiskLabel) {
            "CRITIQUE" { "attention" }
            "ÉLEVÉ"    { "warning" }
            default    { "accent" }
        }
        $driftIcon = switch -Wildcard ($alert.DriftStatus) {
            "NOUVELLE APP"       { "🆕" }
            "ESCALADE PERMS"     { "📈" }
            "CHANGEMENT OWNER"   { "🔄" }
            "CHANGEMENT CONSENT" { "🚨" }
            "STATUT MODIFIÉ"     { "⚠️" }
            default              { "🔍" }
        }

        $AdaptiveCard = @{
            type        = "message"
            attachments = @(@{
                    contentType = "application/vnd.microsoft.card.adaptive"
                    contentUrl  = $null
                    content     = @{
                        "`$schema" = "http://adaptivecards.io/schemas/adaptive-card.json"
                        type       = "AdaptiveCard"
                        version    = "1.4"
                        body       = @(
                            @{
                                type   = "TextBlock"
                                text   = "$driftIcon Shadow IT V5.2 — $($alert.DriftStatus)"
                                weight = "Bolder"
                                size   = "Large"
                                color  = $riskColor
                            },
                            @{
                                type  = "FactSet"
                                facts = @(
                                    @{ title = "Application" ; value = $alert.AppName }
                                    @{ title = "AppId"       ; value = $alert.AppId }
                                    @{ title = "Score"       ; value = "$($alert.Score)/100 — $($alert.RiskLabel)" }
                                    @{ title = "Flags"       ; value = $alert.Flags }
                                    @{ title = "Détails"     ; value = $alert.DriftDetails }
                                    @{ title = "Tenant"      ; value = $GraphContext.TenantId }
                                )
                            },
                            @{
                                type     = "TextBlock"
                                text     = "$(Get-Date -Format 'dd/MM/yyyy HH:mm') · Shadow IT Detector V5.2"
                                size     = "Small"
                                isSubtle = $true
                            }
                        )
                    }
                })
        }

        try {
            Invoke-RestMethod -Uri $TeamsWebhookUrl -Method Post `
                -Body ($AdaptiveCard | ConvertTo-Json -Depth 20 -Compress) `
                -ContentType "application/json" -ErrorAction Stop | Out-Null
            Write-LogMain "Alerte Teams : [$($alert.DriftStatus)] $($alert.AppName) (Score: $($alert.Score))" -Level OK
        }
        catch {
            Write-LogMain "Échec Teams '$($alert.AppName)' : $($_.Exception.Message)" -Level WARN
        }
    }
}
elseif (-not $TeamsWebhookUrl) {
    Write-LogMain "TEAMS_WEBHOOK_URL non définie — alertes désactivées." -Level WARN
}
else {
    Write-LogMain "Aucun drift éligible (score < $TeamsAlertScoreThreshold)." -Level OK
}

#endregion

# ================================================================================================================================
# ÉTAPE 8 : STATISTIQUES
# ================================================================================================================================

#region ═════════════════════════ ÉTAPE 8 : STATISTIQUES ══════════════════════════════

$Stats = [ordered]@{
    Total             = $Report.Count
    Critique          = ($Report | Where-Object { $_.NiveauRisque -eq "CRITIQUE"        }).Count
    Eleve             = ($Report | Where-Object { $_.NiveauRisque -eq "ÉLEVÉ"           }).Count
    Moyen             = ($Report | Where-Object { $_.NiveauRisque -eq "MOYEN"           }).Count
    Faible            = ($Report | Where-Object { $_.NiveauRisque -eq "FAIBLE"          }).Count
    RisqueAccepte     = ($Report | Where-Object { $_.NiveauRisque -eq "RISQUE ACCEPTÉ"  }).Count
    Tiers             = ($Report | Where-Object { $_.EstTiers                           }).Count
    Inactifs          = ($Report | Where-Object { $_.Inactif                            }).Count
    UserConsent       = ($Report | Where-Object { $_.TypeConsentement -eq "User Consent" }).Count
    NonVerifies       = ($Report | Where-Object { $_.EstTiers -and -not $_.EditeurVerifie }).Count
    AvecTier1         = ($Report | Where-Object { $_.HasTier1                           }).Count
    AvecTier2         = ($Report | Where-Object { $_.HasTier2                           }).Count
    EnQuarantaine     = ($Report | Where-Object { $_.StatutQuarantaine -like "*QUARANTAINE*" }).Count
    Desactives        = ($Report | Where-Object { $_.StatutQuarantaine -eq "DÉSACTIVÉ"  }).Count
    OrphanedCritical  = ($Report | Where-Object { $_.Flags -like "*ORPHANED CRITICAL*"  }).Count
    ToxicConsent      = ($Report | Where-Object { $_.Flags -like "*TOXIC CONSENT*"      }).Count
    DormantPriv       = ($Report | Where-Object { $_.Flags -like "*DORMANT PRIVILEGED*" }).Count
    UntrustedHigh     = ($Report | Where-Object { $_.Flags -like "*UNTRUSTED HIGH*"     }).Count
    RotationAttendue  = ($Report | Where-Object { $_.RotationAttendue                   }).Count
    NouvApps          = ($DriftAlerts | Where-Object { $_.DriftStatus -eq "NOUVELLE APP"        }).Count
    EscaladePerms     = ($DriftAlerts | Where-Object { $_.DriftStatus -eq "ESCALADE PERMS"      }).Count
    ChgtOwner         = ($DriftAlerts | Where-Object { $_.DriftStatus -eq "CHANGEMENT OWNER"    }).Count
    ChgtConsent       = ($DriftAlerts | Where-Object { $_.DriftStatus -eq "CHANGEMENT CONSENT"  }).Count
    ChgtStatut        = ($DriftAlerts | Where-Object { $_.DriftStatus -eq "STATUT MODIFIÉ"      }).Count
    Remediations      = $RemediationLog.Count
    Quarantaines      = $QuarantineLog.Count
}

#endregion

# ================================================================================================================================
# ÉTAPE 9 : AFFICHAGE CONSOLE
# ================================================================================================================================

#region ═════════════════════════ ÉTAPE 9 : AFFICHAGE CONSOLE ═════════════════════════

Write-LogMain "RÉSUMÉ DE L'AUDIT V5.2" -Level SECTION
Write-Host ""
Write-Host "  ┌──────────────────────────────────────────────────────────────────────────┐" -ForegroundColor DarkCyan
Write-Host "  │               SHADOW IT DETECTOR V5.2 — RÉSULTATS COMPLETS               │" -ForegroundColor Cyan
Write-Host "  ├──────────────────────────────────────────────────────────────────────────┤" -ForegroundColor DarkCyan
Write-Host ("  │  Applications analysées       : {0,-41}│" -f $Stats.Total)           -ForegroundColor White
Write-Host ("  │  ● CRITIQUE  (score ≥ 70)     : {0,-41}│" -f $Stats.Critique)        -ForegroundColor Red
Write-Host ("  │  ● ÉLEVÉ     (score 40–69)    : {0,-41}│" -f $Stats.Eleve)           -ForegroundColor DarkYellow
Write-Host ("  │  ● MOYEN     (score 20–39)    : {0,-41}│" -f $Stats.Moyen)           -ForegroundColor Yellow
Write-Host ("  │  ● FAIBLE    (score < 20)     : {0,-41}│" -f $Stats.Faible)          -ForegroundColor Green
Write-Host ("  │  ✅ Risque Accepté (whitelist) : {0,-41}│" -f $Stats.RisqueAccepte)   -ForegroundColor DarkGreen
Write-Host "  ├──────────────────────────────────────────────────────────────────────────┤" -ForegroundColor DarkCyan
Write-Host ("  │  Apps tierces                 : {0,-41}│" -f $Stats.Tiers)           -ForegroundColor Cyan
Write-Host ("  │  User Consent                 : {0,-41}│" -f $Stats.UserConsent)     -ForegroundColor Red
Write-Host ("  │  Éditeurs non vérifiés        : {0,-41}│" -f $Stats.NonVerifies)     -ForegroundColor DarkYellow
Write-Host ("  │  Inactifs > $InactivityThresholdDays j                : {0,-41}│" -f $Stats.Inactifs)      -ForegroundColor Magenta
Write-Host ("  │  Apps avec Tier 1 (critique)  : {0,-41}│" -f $Stats.AvecTier1)       -ForegroundColor Red
Write-Host ("  │  Rotation attendue (ExpDrift) : {0,-41}│" -f $Stats.RotationAttendue)-ForegroundColor DarkCyan
Write-Host "  ├──────────────────────────────────────────────────────────────────────────┤" -ForegroundColor DarkCyan
Write-Host ("  │  🚨 Orphaned Critical         : {0,-41}│" -f $Stats.OrphanedCritical) -ForegroundColor Red
Write-Host ("  │  ☢️  Toxic Consent             : {0,-41}│" -f $Stats.ToxicConsent)     -ForegroundColor Magenta
Write-Host ("  │  👻 Dormant Privileged        : {0,-41}│" -f $Stats.DormantPriv)      -ForegroundColor DarkYellow
Write-Host "  ├──────────────────────────────────────────────────────────────────────────┤" -ForegroundColor DarkCyan
Write-Host ("  │  ⏳ En quarantaine            : {0,-41}│" -f $Stats.EnQuarantaine)    -ForegroundColor DarkYellow
Write-Host ("  │  🔒 Désactivés par audit      : {0,-41}│" -f $Stats.Desactives)       -ForegroundColor Red
Write-Host ("  │  ⚡ Quarantaines appliquées    : {0,-41}│" -f $Stats.Quarantaines)     -ForegroundColor Magenta
Write-Host ("  │  ⚡ Remédiation définitive     : {0,-41}│" -f $Stats.Remediations)     -ForegroundColor Magenta
Write-Host "  ├──────────────────────────────────────────────────────────────────────────┤" -ForegroundColor DarkCyan
Write-Host ("  │  🆕 Nouvelles apps (drift)    : {0,-41}│" -f $Stats.NouvApps)         -ForegroundColor Cyan
Write-Host ("  │  📈 Escalades perms (drift)   : {0,-41}│" -f $Stats.EscaladePerms)    -ForegroundColor DarkYellow
Write-Host ("  │  🔄 Changements owner (drift) : {0,-41}│" -f $Stats.ChgtOwner)        -ForegroundColor Cyan
Write-Host ("  │  🚨 Changements consent (drift): {0,-41}│" -f $Stats.ChgtConsent)      -ForegroundColor Red
Write-Host ("  │  ⚠️  Statuts modifiés (drift)  : {0,-41}│" -f $Stats.ChgtStatut)       -ForegroundColor Yellow
Write-Host "  └──────────────────────────────────────────────────────────────────────────┘" -ForegroundColor DarkCyan
Write-Host ""

Write-Host "  TOP 10 — APPLICATIONS LES PLUS RISQUÉES :" -ForegroundColor DarkYellow
$Report | Sort-Object ScoreRisque -Descending | Select-Object -First 10 | ForEach-Object {
    $col = switch ($_.NiveauRisque) {
        "CRITIQUE" { "Red" }
        "ÉLEVÉ" { "DarkYellow" }
        "MOYEN" { "Yellow" }
        "RISQUE ACCEPTÉ" { "DarkGreen" }
        default { "Gray" }
    }
    Write-Host ("  [{0,3}/100] [{1,-14}] {2,-42} Tier1:{3} Tier2:{4}" -f $_.ScoreRisque, $_.NiveauRisque, $_.NomApplication, $_.NbPermsTier1, $_.NbPermsTier2) -ForegroundColor $col
}
Write-Host ""

#endregion

# ================================================================================================================================
# ÉTAPE 10 : EXPORT CSV
# ================================================================================================================================

#region ═════════════════════════ ÉTAPE 10 : EXPORT CSV ═══════════════════════════════

Write-LogMain "EXPORT CSV" -Level SECTION
try {
    $Report | Select-Object -ExcludeProperty _Flags, _Tier1Perms, _Tier2Perms |
    Sort-Object ScoreRisque -Descending |
    Export-Csv $CsvReportPath -NoTypeInformation -Encoding UTF8 -Delimiter ";"
    Write-LogMain "CSV : $CsvReportPath" -Level OK
}
catch {
    Write-LogMain "Erreur CSV : $($_.Exception.Message)" -Level WARN
}

#endregion

# ================================================================================================================================
# ÉTAPE 11 : EXPORT SIEM JSON
# ================================================================================================================================

#region ═════════════════════════ ÉTAPE 11 : EXPORT SIEM JSON ═════════════════════════

Write-LogMain "EXPORT SIEM JSON" -Level SECTION
try {
    $SiemData = $Report | Where-Object { $_.ScoreRisque -gt 0 } |
    Sort-Object ScoreRisque -Descending | ForEach-Object {
        [PSCustomObject]@{
            timestamp                 = $RunDate.ToString("o")
            event_type                = "shadow_it_oauth_audit_v5_2"
            source                    = "ShadowIT-Detector-V5.2"
            tenant_id                 = if ($GraphContext.TenantId) { $GraphContext.TenantId } else { "" }
            app_name                  = if ($_.NomApplication) { $_.NomApplication } else { "" }
            app_id                    = if ($_.AppId) { $_.AppId } else { "" }
            is_third_party            = if ($null -ne $_.EstTiers) { $_.EstTiers } else { $false }
            publisher_verified        = if ($null -ne $_.EditeurVerifie) { $_.EditeurVerifie } else { $false }
            account_enabled           = if ($null -ne $_.CompteActif) { $_.CompteActif } else { $false }
            consent_type              = if ($_.TypeConsentement) { $_.TypeConsentement } else { "" }
            permissions_tier1         = if ($_.PermissionsTier1) { $_.PermissionsTier1 } else { "" }
            permissions_tier2         = if ($_.PermissionsTier2) { $_.PermissionsTier2 } else { "" }
            tier1_count               = if ($null -ne $_.NbPermsTier1) { $_.NbPermsTier1 } else { 0 }
            tier2_count               = if ($null -ne $_.NbPermsTier2) { $_.NbPermsTier2 } else { 0 }
            last_sign_in              = if ($_.DernierSignIn) { $_.DernierSignIn } else { "" }
            is_inactive               = if ($null -ne $_.Inactif) { $_.Inactif } else { $false }
            # FIX-008 : SIEM reçoit fait observé (has_expiring_secret) + état réel + décision scoring séparés
            has_expiring_secret       = if ($null -ne $_.SecretExpirant) { $_.SecretExpirant } else { $false }
            has_expired_secret        = if ($null -ne $_.SecretExpire) { $_.SecretExpire } else { $false }
            secret_penalty_suppressed = if ($null -ne $_.SecretPenaliteSupprimee) { $_.SecretPenaliteSupprimee } else { $false }
            is_expected_drift         = if ($null -ne $_.RotationAttendue) { $_.RotationAttendue } else { $false }
            quarantine_status         = if ($_.StatutQuarantaine) { $_.StatutQuarantaine } else { "" }
            risk_score                = if ($null -ne $_.ScoreRisque) { $_.ScoreRisque } else { 0 }
            risk_level                = if ($_.NiveauRisque) { $_.NiveauRisque } else { "" }
            whitelisted               = if ($null -ne $_.Whiteliste) { $_.Whiteliste } else { $false }
            drift_status              = if ($_.DriftStatus) { $_.DriftStatus } else { "" }
            drift_details             = if ($_.DriftDetails) { $_.DriftDetails } else { "" }
            flags                     = if ($_.Flags) { $_.Flags } else { "" }
            scoring_model             = "tiered_v5_2"
            severity                  = if ($_.NiveauRisque -eq "CRITIQUE") { 4 } elseif ($_.NiveauRisque -eq "ÉLEVÉ") { 3 } elseif ($_.NiveauRisque -eq "MOYEN") { 2 } else { 1 }
        }
    }
    $SiemData | ConvertTo-Json -Depth 10 | Out-File $SiemReportPath -Encoding UTF8
    Write-LogMain "SIEM JSON : $SiemReportPath ($($SiemData.Count) événements)." -Level OK
}
catch {
    Write-LogMain "Erreur SIEM JSON : $($_.Exception.Message)" -Level WARN
}

#endregion

# ================================================================================================================================
# ÉTAPE 12 : GÉNÉRATION DU RAPPORT HTML INTERACTIF (ENTERPRISE SOC DASHBOARD)
# ================================================================================================================================

#region HTML_INTERACTIF

Write-LogMain "GÉNÉRATION DU RAPPORT HTML INTERACTIF (SOC DASHBOARD)" -Level SECTION

# Mapping des classes CSS pour les flags (défini une seule fois hors de la boucle)
$FlagCssMap = @{
    "*WHITELISTÉ*"         = "flag-ok"
    "*TOXIC*"              = "flag-toxic"
    "*ORPHANED CRITICAL*"  = "flag-critical"
    "*QUARANTAINE*"        = "flag-quarantine"
    "*DÉSACTIVÉ*"          = "flag-disabled"
    "*ROTATION ATTENDUE*"  = "flag-rotation"
    "*UNTRUSTED*"          = "flag-untrusted"
    "*DORMANT*"            = "flag-dormant"
    "*ESCALADE PERMS*"     = "flag-escalade"
    "*CHANGEMENT OWNER*"   = "flag-owner"
    "*CHANGEMENT CONSENT*" = "flag-consent"
    "*NOUVELLE APP*"       = "flag-new"
    "*USER CONSENT*"       = "flag-userconsent"
    "*SECRET EXPIRÉ*"      = "flag-expired"
    "*SECRET EXP.*"        = "flag-expiring"
}

# StringBuilder : évite l'allocation O(n²) de += sur string pour grands tenants
$sb = [System.Text.StringBuilder]::new(10 * 1024 * 1024)

foreach ($app in $Report) {
    $rc  = Get-RiskColor    $app.NiveauRisque
    $rtc = Get-RiskTextColor $app.NiveauRisque

    $t1Html = if ($app._Tier1Perms -and $app._Tier1Perms.Count -gt 0) {
        ($app._Tier1Perms | ForEach-Object { "<span class='perm-badge t1'>$([System.Net.WebUtility]::HtmlEncode($_))</span>" }) -join " "
    } else { "" }

    $t2Html = if ($app._Tier2Perms -and $app._Tier2Perms.Count -gt 0) {
        ($app._Tier2Perms | ForEach-Object { "<span class='perm-badge t2'>$([System.Net.WebUtility]::HtmlEncode($_))</span>" }) -join " "
    } else { "" }

    $permsHtml = ("$t1Html $t2Html".Trim())
    if (-not $permsHtml) { $permsHtml = "<span class='muted'>—</span>" }

    $sbFlags = [System.Text.StringBuilder]::new(512)
    foreach ($flag in $app._Flags) {
        if (-not $flag) { continue }
        $cssClass = "flag-default"
        foreach ($pattern in $FlagCssMap.Keys) {
            if ($flag -like $pattern) { $cssClass = $FlagCssMap[$pattern]; break }
        }
        [void]$sbFlags.Append("<span class='badge $cssClass'>$([System.Net.WebUtility]::HtmlEncode($flag))</span> ")
    }

    [void]$sb.Append("<tr data-risk='$($app.NiveauRisque)' data-score='$($app.ScoreRisque)'>")
    [void]$sb.Append("<td><div class='app-name'>$([System.Net.WebUtility]::HtmlEncode($app.NomApplication))</div>")
    [void]$sb.Append("<div class='app-id'>$([System.Net.WebUtility]::HtmlEncode($app.AppId))</div></td>")
    [void]$sb.Append("<td class='center'><span class='risk-badge' style='background:$rc;color:$rtc'>$($app.NiveauRisque)</span></td>")
    [void]$sb.Append("<td class='center'><div class='score-ring' style='--sc:$rc'>$($app.ScoreRisque)</div></td>")
    [void]$sb.Append("<td class='perms-cell'>$permsHtml</td>")
    [void]$sb.Append("<td>$($sbFlags.ToString())</td>")
    [void]$sb.Append("<td class='center small'>$([System.Net.WebUtility]::HtmlEncode($app.DernierSignIn))</td>")
    [void]$sb.Append("</tr>`n")
}

$TableRows = $sb.ToString()

# Génération du document HTML complet avec toutes les variables PowerShell interpolées
$HtmlDocument = @"
<!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8"><title>Shadow IT Detector V5.2</title>
<style>
:root{--bg:#04070d;--surface:#090f1c;--surface2:#101829;--border:#121e33;--border2:#1c2d48;--text:#bfcfe8;--muted:#4a5a7a;--accent:#00a8c8;--accent2:#0077b6;--font-sans:'Segoe UI',sans-serif;--font-mono:'Cascadia Code',monospace;--r:8px;}
body{background:var(--bg);color:var(--text);font-family:var(--font-sans);font-size:13px;margin:0;}
body::before{content:'';position:fixed;inset:0;z-index:-1;background:repeating-linear-gradient(0deg,transparent,transparent 3px,rgba(0,168,200,.015) 3px,rgba(0,168,200,.015) 4px);}
header{background:linear-gradient(135deg,#060c18 0%,#081224 50%,#04070d 100%);border-bottom:1px solid var(--border);padding:2rem 3rem;}
.eyebrow{font-family:var(--font-mono);font-size:.65rem;color:var(--accent);letter-spacing:.2em;text-transform:uppercase;margin-bottom:.5rem;}
h1{font-size:1.8rem;margin:0;color:#fff;} h1 em{color:var(--accent);font-style:normal;}
.stats-section{padding:1.5rem 3rem;} .stats-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:.7rem;}
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);padding:1rem;position:relative;transition:transform .15s;}
.stat-card:hover{transform:translateY(-2px);border-color:var(--border2);}
.stat-card::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:var(--c,var(--accent));}
.stat-label{font-family:var(--font-mono);font-size:.6rem;color:var(--muted);text-transform:uppercase;}
.stat-value{font-size:1.6rem;font-weight:700;color:var(--c,var(--accent));margin-top:.3rem;}
.filter-bar{padding:.8rem 3rem;background:var(--surface);border-top:1px solid var(--border);border-bottom:1px solid var(--border);display:flex;gap:.5rem;align-items:center;}
.filter-btn{background:transparent;border:1px solid var(--border2);color:var(--muted);padding:.3rem .8rem;border-radius:20px;cursor:pointer;font-family:var(--font-mono);font-size:.65rem;}
.filter-btn.active{background:var(--accent2);color:#fff;border-color:var(--accent2);}
.search-box{margin-left:auto;background:var(--surface2);border:1px solid var(--border2);color:var(--text);padding:.3rem .8rem;border-radius:20px;outline:none;font-family:var(--font-mono);}
.table-section{padding:1.5rem 3rem;} table{width:100%;border-collapse:collapse;background:var(--surface);border-radius:var(--r);overflow:hidden;}
th,td{padding:.7rem 1rem;border-bottom:1px solid var(--border);text-align:left;} th{background:#050912;font-family:var(--font-mono);font-size:.6rem;color:var(--muted);text-transform:uppercase;}
th{cursor:pointer;user-select:none;}
th.sorted-asc::after{content:" ↑";color:var(--accent);}
th.sorted-desc::after{content:" ↓";color:var(--accent);}
.no-results{text-align:center;padding:2rem;color:var(--muted);font-family:var(--font-mono);display:none;}
.app-name{font-weight:bold;color:#fff;} .app-id{font-family:var(--font-mono);font-size:.6rem;color:var(--muted);}
.badge{padding:.15rem .4rem;border-radius:3px;font-size:.6rem;font-weight:bold;margin-right:.2rem;display:inline-block;}
code{background:#0a101d;padding:.15rem .3rem;border-radius:3px;border:1px solid #142033;font-family:var(--font-mono);font-size:.6rem;display:inline-block;margin:1px;}
.score-ring{display:inline-flex;align-items:center;justify-content:center;width:32px;height:32px;border-radius:50%;border:2px solid var(--sc);font-weight:bold;color:var(--sc);background:rgba(0,0,0,.3);}
.risk-badge{padding:.2rem .6rem;border-radius:20px;font-weight:bold;font-size:.65rem;}
.flag-ok{background:#059669;color:#fff;}
.flag-toxic{background:#3b0764;color:#e9d5ff;border:1px solid #9333ea;font-weight:800;}
.flag-critical{background:#7f1d1d;color:#fca5a5;border:1px solid #dc2626;font-weight:800;}
.flag-quarantine{background:#854d0e;color:#fef08a;}
.flag-disabled{background:#1e293b;color:#94a3b8;border:1px solid #475569;}
.flag-rotation{background:#0c4a6e;color:#7dd3fc;}
.flag-untrusted{background:#431407;color:#fdba74;border:1px solid #ea580c;font-weight:800;}
.flag-dormant{background:#0c1a0c;color:#86efac;border:1px solid #16a34a;font-weight:800;}
.flag-escalade{background:#C2410C;color:#fff;}
.flag-owner{background:#0369A1;color:#fff;}
.flag-consent{background:#991B1B;color:#fff;}
.flag-new{background:#0891B2;color:#fff;}
.flag-userconsent{background:#DC2626;color:#fff;}
.flag-expired{background:#450a0a;color:#fca5a5;border:1px solid #7f1d1d;}
.flag-expiring{background:#7C3AED;color:#fff;}
.flag-default{background:#1e293b;color:#94a3b8;}
</style></head><body>
<header><div class="eyebrow">SOC Toolkit / Enterprise OAuth Audit</div><h1>Shadow IT <em>Detector</em> V5.2</h1></header>
<section class="stats-section"><div class="stats-grid">
    <div class="stat-card" style="--c:#8b9dc3"><div class="stat-label">Total Analysé</div><div class="stat-value">$($Stats.Total)</div></div>
    <div class="stat-card" style="--c:#FF3B30"><div class="stat-label">Risque Critique</div><div class="stat-value">$($Stats.Critique)</div></div>
    <div class="stat-card" style="--c:#FF9500"><div class="stat-label">Risque Élevé</div><div class="stat-value">$($Stats.Eleve)</div></div>
    <div class="stat-card" style="--c:#059669"><div class="stat-label">Whitelist (Accepté)</div><div class="stat-value">$($Stats.RisqueAccepte)</div></div>
    <div class="stat-card" style="--c:#9F1239"><div class="stat-label">Orphaned Critical</div><div class="stat-value">$($Stats.OrphanedCritical)</div></div>
    <div class="stat-card" style="--c:#581c87"><div class="stat-label">Toxic Consent</div><div class="stat-value">$($Stats.ToxicConsent)</div></div>
    <div class="stat-card" style="--c:#854d0e"><div class="stat-label">En Quarantaine</div><div class="stat-value">$($Stats.EnQuarantaine)</div></div>
    <div class="stat-card" style="--c:#475569"><div class="stat-label">Désactivés (Audit)</div><div class="stat-value">$($Stats.Desactives)</div></div>
</div></section>
<div class="filter-bar">
    <button class="filter-btn active" onclick="filterRisk('ALL',this)">Tous</button>
    <button class="filter-btn" onclick="filterRisk('CRITIQUE',this)">🔴 Critique</button>
    <button class="filter-btn" onclick="filterRisk('ÉLEVÉ',this)">🟠 Élevé</button>
    <button class="filter-btn" onclick="filterRisk('RISQUE ACCEPTÉ',this)">✅ Accepté</button>
    <input type="text" class="search-box" placeholder="Rechercher par nom ou AppId..." oninput="debounceSearch(this.value)">
</div>
<section class="table-section"><table>
    <thead><tr>
        <th onclick="sortTable(0)">Application</th>
        <th onclick="sortTable(1)">Niveau</th>
        <th onclick="sortTable(2)">Score</th>
        <th onclick="sortTable(3)">Permissions T1 🔴 / T2 🔵</th>
        <th onclick="sortTable(4)">Flags &amp; Smart Alerts</th>
        <th onclick="sortTable(5)">Dernier SignIn</th>
    </tr></thead>
    <tbody id="tableBody">$TableRows</tbody>
</table>
<div class="no-results" id="noResults">Aucun résultat — ajustez les filtres ou la recherche.</div>
</section>
<script>
// ── Filtre par niveau de risque ──────────────────────────────────────────────
function filterRisk(l, b) {
    document.querySelectorAll('.filter-btn').forEach(x => x.classList.remove('active'));
    b.classList.add('active');
    const rows = document.querySelectorAll('#tableBody tr');
    let v = 0;
    rows.forEach(r => {
        const s = l === 'ALL' || r.dataset.risk === l;
        r.style.display = s ? '' : 'none';
        if (s) v++;
    });
    const nr = document.getElementById('noResults');
    if (nr) nr.style.display = v === 0 ? 'block' : 'none';
}

// ── Recherche avec debounce 300ms (évite le freeze DOM sur grands rapports) ──
let _searchTimeout;
function debounceSearch(val) {
    clearTimeout(_searchTimeout);
    _searchTimeout = setTimeout(() => searchTable(val), 300);
}
function searchTable(q) {
    q = q.toLowerCase();
    const rows = document.querySelectorAll('#tableBody tr');
    let v = 0;
    rows.forEach(r => {
        const s = r.textContent.toLowerCase().includes(q);
        r.style.display = s ? '' : 'none';
        if (s) v++;
    });
    const nr = document.getElementById('noResults');
    if (nr) nr.style.display = v === 0 ? 'block' : 'none';
}

// ── Tri de colonnes (toggle asc/desc) ────────────────────────────────────────
let _ss = { col: 2, asc: false };
function sortTable(ci) {
    const tbody = document.getElementById('tableBody');
    if (!tbody) return;
    const rows  = Array.from(tbody.querySelectorAll('tr'));
    const heads = document.querySelectorAll('thead th');
    const asc   = _ss.col === ci ? !_ss.asc : false;
    _ss = { col: ci, asc };
    heads.forEach((h, i) => {
        h.classList.remove('sorted-asc', 'sorted-desc');
        if (i === ci) h.classList.add(asc ? 'sorted-asc' : 'sorted-desc');
    });
    rows.sort((a, b) => {
        const ta = a.cells[ci]?.textContent.trim() || '';
        const tb = b.cells[ci]?.textContent.trim() || '';
        const na = parseFloat(ta), nb = parseFloat(tb);
        const c  = (!isNaN(na) && !isNaN(nb)) ? na - nb : ta.localeCompare(tb, 'fr');
        return asc ? c : -c;
    });
    rows.forEach(r => tbody.appendChild(r));
}
</script>
</body></html>
"@

    # Export du fichier HTML sur le disque
    try {
        $HtmlDocument | Out-File $HtmlReportPath -Encoding UTF8 -Force
        Write-LogMain "HTML interactif exporté : $HtmlReportPath" -Level OK
    }
    catch {
        Write-LogMain "Erreur lors de la génération du rapport HTML : $($_.Exception.Message)" -Level WARN
    }

#endregion

# ================================================================================================================================
# ÉTAPE 13 : DÉCONNEXION
# ================================================================================================================================

#region ═════════════════════════ ÉTAPE 13 : DÉCONNEXION ══════════════════════════════

Write-LogMain "DÉCONNEXION" -Level SECTION
try { Disconnect-MgGraph | Out-Null } catch {}
Write-LogMain "Déconnecté de Microsoft Graph." -Level OK

#endregion
