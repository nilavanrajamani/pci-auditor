// =============================================================================
// PCI Auditor — Azure Infrastructure
// =============================================================================
// Provisions:
//   • Azure OpenAI  (gpt-4o + text-embedding-3-small deployments)
//   • Azure AI Search  (optional, for vector rule retrieval in CI/CD)
//
// Run via:  ./infra/deploy.ps1  (see that script for full usage)
// =============================================================================

@description('Azure region for all resources. Must support Azure OpenAI GPT-4o (e.g. eastus, eastus2, swedencentral, australiaeast).')
param location string = 'eastus'

@description('Short prefix applied to every resource name (3–8 lowercase alphanumeric).')
@minLength(3)
@maxLength(8)
param prefix string = 'pciaudit'

@description('GPT-4o deployment capacity in thousands of tokens per minute (TPM). Each unit = 1 000 TPM.')
@minValue(1)
@maxValue(400)
param gpt4oCapacityK int = 10

@description('text-embedding-3-small deployment capacity in thousands of TPM.')
@minValue(1)
@maxValue(350)
param embeddingCapacityK int = 10

@description('Deploy an Azure AI Search service for vector rule retrieval. Set false to use the built-in local cosine-similarity index instead.')
param deploySearch bool = true

@description('Azure AI Search pricing tier. NOTE: "free" does NOT support vector search — use "basic" or higher.')
@allowed(['free', 'basic', 'standard'])
param searchSku string = 'basic'

// ── Computed names ────────────────────────────────────────────────────────────
// uniqueString ensures globally-unique resource names within the resource group.
var suffix              = uniqueString(resourceGroup().id)
var openaiAccountName   = '${prefix}-openai-${suffix}'
var searchServiceName   = '${prefix}-search-${suffix}'
var gpt4oDeployName     = 'gpt-4o'
var embeddingDeployName = 'text-embedding-3-small'
var searchIndexName     = 'pci-rules'

// =============================================================================
// Azure OpenAI Account
// =============================================================================
resource openai 'Microsoft.CognitiveServices/accounts@2024-10-01' = {
  name: openaiAccountName
  location: location
  kind: 'OpenAI'
  sku: {
    name: 'S0'
  }
  properties: {
    customSubDomainName: openaiAccountName
    publicNetworkAccess: 'Enabled'
    // Disable local (key-based) auth to force managed-identity access in production.
    // Set to false here so the generated .env can use key-based auth for local dev.
    disableLocalAuth: false
  }
}

// -- GPT-4o deployment --------------------------------------------------------
// Deployments must be created sequentially; the embedding waits via dependsOn.
resource gpt4oDeployment 'Microsoft.CognitiveServices/accounts/deployments@2024-10-01' = {
  parent: openai
  name: gpt4oDeployName
  sku: {
    name: 'Standard'
    capacity: gpt4oCapacityK
  }
  properties: {
    model: {
      format: 'OpenAI'
      name: 'gpt-4o'
      version: '2024-11-20'
    }
    versionUpgradeOption: 'OnceCurrentVersionExpired'
  }
}

// -- text-embedding-3-small deployment ----------------------------------------
resource embeddingDeployment 'Microsoft.CognitiveServices/accounts/deployments@2024-10-01' = {
  parent: openai
  name: embeddingDeployName
  dependsOn: [gpt4oDeployment] // ARM deploys siblings in parallel — force sequential
  sku: {
    name: 'Standard'
    capacity: embeddingCapacityK
  }
  properties: {
    model: {
      format: 'OpenAI'
      name: 'text-embedding-3-small'
      version: '1'
    }
    versionUpgradeOption: 'OnceCurrentVersionExpired'
  }
}

// =============================================================================
// Azure AI Search  (optional)
// =============================================================================
resource search 'Microsoft.Search/searchServices@2023-11-01' = if (deploySearch) {
  name: searchServiceName
  location: location
  sku: {
    name: searchSku
  }
  properties: {
    replicaCount: 1
    partitionCount: 1
    publicNetworkAccess: 'enabled'
    // Semantic ranking is available on basic+; not needed for vector-only workloads.
    semanticSearch: (searchSku == 'free') ? 'disabled' : 'free'
  }
}

// =============================================================================
// Outputs  — captured by deploy.ps1 and written directly to .env
// =============================================================================

output AZURE_OPENAI_ENDPOINT string = openai.properties.endpoint

// NOTE: The API key is included here so deploy.ps1 can write it to .env for
// local development. It is stored in the ARM deployment history of the resource
// group. For production workloads, prefer managed identity and remove the key.
#disable-next-line outputs-should-not-contain-secrets
output AZURE_OPENAI_API_KEY string = openai.listKeys().key1

output AZURE_OPENAI_DEPLOYMENT string = gpt4oDeployName

output AZURE_OPENAI_API_VERSION string = '2024-02-01'

output AZURE_OPENAI_EMBEDDING_DEPLOYMENT string = embeddingDeployName

output AZURE_SEARCH_ENDPOINT string = deploySearch ? 'https://${search!.name}.search.windows.net' : ''

// Admin key — allows the index-build command to create/populate the index.
#disable-next-line outputs-should-not-contain-secrets
output AZURE_SEARCH_API_KEY string = deploySearch ? search!.listAdminKeys().primaryKey : ''

output AZURE_SEARCH_INDEX_NAME string = deploySearch ? searchIndexName : ''
