<#
.SYNOPSIS
    One-click Azure infrastructure provisioning for pci-auditor.

.DESCRIPTION
    1. Logs in to Azure CLI (prompts if needed).
    2. Creates (or reuses) a resource group.
    3. Deploys infra/main.bicep:
         - Azure OpenAI account with gpt-4o + text-embedding-3-small deployments
         - Azure AI Search service (optional, for vector rule retrieval)
    4. Writes all required values to <repo>/pci-auditor/.env automatically.

    After the script completes, run:
        cd pci-auditor
        pip install -e .
        pci-auditor scan codebase --path ../sample-vulnerable-app

.PARAMETER ResourceGroup
    Name of the Azure resource group to create or reuse.

.PARAMETER Location
    Azure region. Must support Azure OpenAI GPT-4o.
    Recommended: eastus | eastus2 | swedencentral | australiaeast

.PARAMETER Prefix
    3–8 lowercase alphanumeric characters prepended to every resource name.
    Defaults to "pciaudit".

.PARAMETER SubscriptionId
    Optional. Azure subscription ID. Defaults to the active CLI subscription.

.PARAMETER IncludeSearch
    Switch. When set, deploys an Azure AI Search service for vector rule
    retrieval. Omit to use the built-in local cosine-similarity index instead.

.PARAMETER SearchSku
    Azure AI Search pricing tier: free | basic | standard
    NOTE: "free" does NOT support vector search. Use "basic" or higher for
    production, or omit -IncludeSearch entirely to skip AI Search.
    Defaults to "basic".

.PARAMETER Gpt4oCapacityK
    GPT-4o deployment capacity in thousands of TPM. Default: 10 (= 10 000 TPM).
    Increase if you hit throttling on large codebases.

.PARAMETER EmbeddingCapacityK
    text-embedding-3-small deployment capacity in thousands of TPM. Default: 10.

.EXAMPLE
    # Minimal — no AI Search, eastus, default prefix
    .\infra\deploy.ps1 -ResourceGroup rg-pci-auditor -Location eastus

.EXAMPLE
    # Full — includes AI Search, custom prefix, Sweden Central
    .\infra\deploy.ps1 -ResourceGroup rg-pci-auditor -Location swedencentral `
        -Prefix myproj -IncludeSearch -SearchSku basic

.EXAMPLE
    # Explicit subscription
    .\infra\deploy.ps1 -ResourceGroup rg-pci-auditor -Location eastus `
        -SubscriptionId 00000000-0000-0000-0000-000000000000
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true,  HelpMessage = 'Azure resource group name')]
    [string] $ResourceGroup,

    [Parameter(Mandatory = $true,  HelpMessage = 'Azure region (e.g. eastus, swedencentral)')]
    [string] $Location,

    [Parameter(Mandatory = $false)]
    [ValidatePattern('^[a-z0-9]{3,8}$')]
    [string] $Prefix = 'pciaudit',

    [Parameter(Mandatory = $false)]
    [string] $SubscriptionId = '',

    [Parameter(Mandatory = $false)]
    [switch] $IncludeSearch,

    [Parameter(Mandatory = $false)]
    [ValidateSet('free', 'basic', 'standard')]
    [string] $SearchSku = 'basic',

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 400)]
    [int] $Gpt4oCapacityK = 10,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 350)]
    [int] $EmbeddingCapacityK = 10
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Helpers ───────────────────────────────────────────────────────────────────
function Write-Step  { param([string]$Msg) Write-Host "`n==> $Msg" -ForegroundColor Cyan }
function Write-OK    { param([string]$Msg) Write-Host "    [OK]  $Msg" -ForegroundColor Green }
function Write-Warn  { param([string]$Msg) Write-Host "    [!!]  $Msg" -ForegroundColor Yellow }
function Write-Banner {
    param([string]$Msg)
    $line = '=' * 65
    Write-Host "`n$line"       -ForegroundColor White
    Write-Host "  $Msg"        -ForegroundColor Green
    Write-Host "$line`n"       -ForegroundColor White
}

# ── Locate files ──────────────────────────────────────────────────────────────
$InfraDir   = $PSScriptRoot                                    # …/pci-auditor/infra
$BicepFile  = Join-Path $InfraDir 'main.bicep'
$EnvFile    = [System.IO.Path]::GetFullPath((Join-Path $InfraDir '..' '.env'))

if (-not (Test-Path $BicepFile)) {
    throw "Bicep template not found at: $BicepFile"
}

# ── 1. Azure CLI check ────────────────────────────────────────────────────────
Write-Step 'Checking Azure CLI...'
if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    throw 'Azure CLI (az) not found. Install from https://aka.ms/installazurecli and re-run.'
}

$account = az account show 2>$null | ConvertFrom-Json
if (-not $account) {
    Write-Warn 'Not logged in. Opening browser for az login...'
    az login | Out-Null
    $account = az account show | ConvertFrom-Json
}
Write-OK "Signed in as : $($account.user.name)"
Write-OK "Subscription : $($account.name)  ($($account.id))"

if ($SubscriptionId) {
    Write-Step "Switching to subscription $SubscriptionId..."
    az account set --subscription $SubscriptionId
    $account = az account show | ConvertFrom-Json
    Write-OK "Active subscription : $($account.name)"
}

# ── 2. Resource group ─────────────────────────────────────────────────────────
Write-Step "Ensuring resource group '$ResourceGroup' in '$Location'..."
$rgExists = az group exists --name $ResourceGroup | ConvertFrom-Json
if ($rgExists) {
    Write-OK 'Resource group already exists — reusing.'
} else {
    az group create --name $ResourceGroup --location $Location --output none
    Write-OK 'Resource group created.'
}

# ── 3. Deploy Bicep ───────────────────────────────────────────────────────────
$deploymentName = "pci-auditor-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
$deploySearch   = if ($IncludeSearch) { 'true' } else { 'false' }

Write-Step "Deploying Bicep template '$deploymentName'..."
Write-Host "    Resources: Azure OpenAI (gpt-4o + text-embedding-3-small)" -ForegroundColor Gray
if ($IncludeSearch) {
    Write-Host "               Azure AI Search ($SearchSku tier)" -ForegroundColor Gray
} else {
    Write-Host "               Azure AI Search: skipped (local index will be used)" -ForegroundColor Gray
}
Write-Host "    This typically takes 3–6 minutes..." -ForegroundColor Gray

$deployArgs = @(
    'deployment', 'group', 'create'
    '--resource-group',  $ResourceGroup
    '--name',            $deploymentName
    '--template-file',   $BicepFile
    '--parameters',      "prefix=$Prefix"
    '--parameters',      "location=$Location"
    '--parameters',      "deploySearch=$deploySearch"
    '--parameters',      "searchSku=$SearchSku"
    '--parameters',      "gpt4oCapacityK=$Gpt4oCapacityK"
    '--parameters',      "embeddingCapacityK=$EmbeddingCapacityK"
    '--output',          'json'
)

$result = az @deployArgs | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or $null -eq $result) {
    throw "Bicep deployment failed. Check the Azure portal for details: https://portal.azure.com"
}
Write-OK "Deployment succeeded: $deploymentName"

# ── 4. Extract outputs ────────────────────────────────────────────────────────
Write-Step 'Extracting deployment outputs...'

function Get-DeployOutput {
    param([string]$Name)
    $val = $result.properties.outputs.$Name.value
    if ($null -eq $val) { return '' }
    return [string]$val
}

$openaiEndpoint      = Get-DeployOutput 'AZURE_OPENAI_ENDPOINT'
$openaiKey           = Get-DeployOutput 'AZURE_OPENAI_API_KEY'
$openaiDeployment    = Get-DeployOutput 'AZURE_OPENAI_DEPLOYMENT'
$openaiApiVersion    = Get-DeployOutput 'AZURE_OPENAI_API_VERSION'
$embeddingDeployment = Get-DeployOutput 'AZURE_OPENAI_EMBEDDING_DEPLOYMENT'
$searchEndpoint      = Get-DeployOutput 'AZURE_SEARCH_ENDPOINT'
$searchKey           = Get-DeployOutput 'AZURE_SEARCH_API_KEY'
$searchIndexName     = Get-DeployOutput 'AZURE_SEARCH_INDEX_NAME'

Write-OK 'All values extracted.'

# ── 5. Write .env ─────────────────────────────────────────────────────────────
Write-Step "Writing .env to: $EnvFile"

# Warn if a .env already exists — back it up
if (Test-Path $EnvFile) {
    $backup = "$EnvFile.bak-$(Get-Date -Format 'yyyyMMddHHmmss')"
    Copy-Item $EnvFile $backup
    Write-Warn "Existing .env backed up to: $backup"
}

$searchBlock = if ($IncludeSearch) {
@"
# Azure AI Search  (vector rule retrieval — faster and more accurate in CI/CD)
AZURE_SEARCH_ENDPOINT=$searchEndpoint
AZURE_SEARCH_API_KEY=$searchKey
AZURE_SEARCH_INDEX_NAME=$searchIndexName
"@
} else {
@"
# Azure AI Search  (not deployed — pci-auditor will use the local cosine-similarity index)
# To add AI Search later, re-run deploy.ps1 with -IncludeSearch and update these values.
# AZURE_SEARCH_ENDPOINT=
# AZURE_SEARCH_API_KEY=
# AZURE_SEARCH_INDEX_NAME=pci-rules
"@
}

$envContent = @"
# -----------------------------------------------------------------------
# PCI Auditor — Azure Environment Variables
# Generated by infra/deploy.ps1 on $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
#
# WARNING: This file contains secrets. It is git-ignored by default.
#          Never commit it to source control.
# -----------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Azure OpenAI  (REQUIRED for AI scan mode)
# ---------------------------------------------------------------------------
AZURE_OPENAI_ENDPOINT=$openaiEndpoint
AZURE_OPENAI_API_KEY=$openaiKey
AZURE_OPENAI_DEPLOYMENT=$openaiDeployment
AZURE_OPENAI_API_VERSION=$openaiApiVersion

# ---------------------------------------------------------------------------
# Semantic Rule Retrieval / RAG
# Shares the same OpenAI resource as above — no separate endpoint needed.
# ---------------------------------------------------------------------------
AZURE_OPENAI_EMBEDDING_DEPLOYMENT=$embeddingDeployment
# AZURE_OPENAI_EMBEDDING_ENDPOINT=   # blank = reuse AZURE_OPENAI_ENDPOINT
# AZURE_OPENAI_EMBEDDING_API_KEY=    # blank = reuse AZURE_OPENAI_API_KEY
PCI_AUDITOR_TOP_K_RULES=8

# ---------------------------------------------------------------------------
$searchBlock
# ---------------------------------------------------------------------------
# Scan behaviour  (optional overrides)
# ---------------------------------------------------------------------------
# Comma-separated severities that fail the build (default: critical,high)
# PCI_AUDITOR_FAIL_ON=critical,high

# Set to 1 to disable AI analysis and run pattern-only mode
# PCI_AUDITOR_NO_AI=0
"@

Set-Content -Path $EnvFile -Value $envContent -Encoding UTF8
Write-OK ".env written."

# ── 6. (Optional) Build the rule embeddings index ────────────────────────────
if ($IncludeSearch) {
    Write-Step 'Tip: Build the Azure AI Search rule index now?'
    Write-Host '    Run the following command from the pci-auditor directory:' -ForegroundColor Gray
    Write-Host '        pci-auditor rules index-build' -ForegroundColor Yellow
    Write-Host '    This uploads rule embeddings to Azure AI Search.' -ForegroundColor Gray
}

# ── 7. Summary ────────────────────────────────────────────────────────────────
Write-Banner 'PCI Auditor — Infrastructure Ready'

Write-Host '  Resource Group  : ' -NoNewline; Write-Host $ResourceGroup       -ForegroundColor White
Write-Host '  Subscription    : ' -NoNewline; Write-Host $account.name        -ForegroundColor White
Write-Host '  Region          : ' -NoNewline; Write-Host $Location             -ForegroundColor White
Write-Host ''
Write-Host '  OpenAI Endpoint : ' -NoNewline; Write-Host $openaiEndpoint       -ForegroundColor Cyan
Write-Host '  GPT-4o Deploy   : ' -NoNewline; Write-Host $openaiDeployment     -ForegroundColor Cyan
Write-Host '  Embedding Deploy: ' -NoNewline; Write-Host $embeddingDeployment  -ForegroundColor Cyan
if ($IncludeSearch) {
    Write-Host '  Search Endpoint : ' -NoNewline; Write-Host $searchEndpoint   -ForegroundColor Cyan
    Write-Host '  Search Index    : ' -NoNewline; Write-Host $searchIndexName  -ForegroundColor Cyan
}
Write-Host ''
Write-Host '  .env written to : ' -NoNewline; Write-Host $EnvFile              -ForegroundColor Green
Write-Host ''
Write-Host '  Next steps:' -ForegroundColor Yellow
Write-Host '    cd pci-auditor'
Write-Host '    pip install -e .'
if ($IncludeSearch) {
    Write-Host '    pci-auditor rules index-build     # populate the AI Search index'
}
Write-Host '    pci-auditor scan codebase --path ../sample-vulnerable-app'
Write-Host ''
