# SecretHound Taxonomy System

## Overview

SecretHound now includes a centralized technology taxonomy system that maps scanner-specific rule IDs to BloodHound node kinds. This provides consistent categorization across all secret scanners.

## How It Works

### Architecture

1. **Taxonomy Files**: JSON configuration files that define:
   - Technologies (AWS, Azure, GCP, GitHub, etc.)
   - Node kinds for each technology (`*Base` and `*Secret`)
   - Brand colors for BloodHound visualization
   - Scanner-specific rule ID mappings

2. **Automatic Node Kind Assignment**:
   - When a secret is found, its rule ID (e.g., `np.aws.2`) is looked up in the taxonomy
   - The technology is identified (e.g., `aws`)
   - Both `*Secret` and `*Base` kinds are automatically added to the node
   - Example: An AWS secret gets kinds `["AWSSecret", "AWSBase"]`

3. **Fallback Behavior**:
   - If no taxonomy mapping exists, the secret gets only the `Secret` kind
   - Legacy custom mappings (via `-c` flag) are still supported for backwards compatibility

## Taxonomy Files

### taxonomy.json (Comprehensive)
- **All 70+ technologies** get their own `*Base` and `*Secret` kinds
- Ideal for maximum categorization granularity
- Includes: AWS, Azure, GCP, GitHub, GitLab, Slack, Stripe, NPM, PyPI, etc.

### taxonomy_minimal.json (Major Technologies Only)
- **~25 major technologies** get their own kinds
- All other secrets default to just `Secret` kind
- Ideal for cleaner BloodHound graphs with less noise
- Includes: AWS, Azure, GCP, GitHub, Kubernetes, Docker, major AI platforms, etc.

## Usage

### Basic Usage (Uses taxonomy.json by default)

```bash
python secrethound.py -t noseyparker -i report.json -o output.json
```

### Use Minimal Taxonomy

```bash
python secrethound.py -t noseyparker -i report.json -o output.json --taxonomy taxonomy_minimal.json
```

### Disable Taxonomy (Fall back to legacy behavior)

```bash
python secrethound.py -t noseyparker -i report.json -o output.json --taxonomy /nonexistent/file.json
```

## Scanner Rule ID Mappings

### NoseyParker

All NoseyParker rules are mapped in the taxonomy files:

- **AWS**: `np.aws.*`, `np.appsync.1`
- **Azure**: `np.azure.*`, `np.msteams.1`
- **GCP**: `np.google.*`
- **GitHub**: `np.github.*`
- **GitLab**: `np.gitlab.*`
- **Kubernetes**: `np.kubernetes.*`
- **Docker**: `np.dockerhub.*`
- **Package Registries**: `np.npm.1`, `np.pypi.1`, `np.rubygems.1`, `np.nuget.1`, `np.cratesio.1`
- **AI Platforms**: `np.openai.1`, `np.anthropic.1`, `np.huggingface.1`, `np.groq.1`
- **Payment**: `np.stripe.*`, `np.square.*`, `np.shopify.*`
- **Monitoring**: `np.newrelic.*`, `np.grafana.*`, `np.dynatrace.1`
- **And 50+ more...**

### TruffleHog

TruffleHog has 700+ detectors, with 200+ mapped to technologies:

- **AWS**: `AWS`, `AWSSessionKey`
- **Azure**: `Azure`, `AzureStorage`, `AzureBatch`, `AzureContainerRegistry`, `AzureActiveDirectoryApplicationSecret`, `AzureCosmosDBKeyIdentifiable`, `AzureDevopsPersonalAccessToken`, `AzureFunctionKey`, `AzureSasToken`, `AzureSearchAdminKey`, `AzureSQL`, `AzureOpenAI`, and 10+ more
- **GCP**: `GCP`, `GCPApplicationDefaultCredentials`
- **GitHub**: `Github`, `GitHubApp`, `GitHubOld`, `GitHubOauth2`
- **GitLab**: `Gitlab`
- **Kubernetes**: `KubeConfig`
- **Docker**: `Docker`, `Dockerhub`
- **Package Registries**: `NpmToken`, `PyPI`, `RubyGems`, `NuGetApiKey`
- **AI Platforms**: `OpenAI`, `Anthropic`, `HuggingFace`, `Groq`, `ElevenLabs`
- **Payment**: `Stripe`, `StripePaymentIntent`, `Square`, `SquareApp`
- **Communication**: `Slack`, `SlackWebhook`, `Discord`, `DiscordBotToken`, `DiscordWebhook`, `Telegram`, `TelegramBotToken`
- **Infrastructure**: `Pulumi`, `HashiCorpVaultAuth`, `Tailscale`, `Ngrok`, `Portainer`, `PortainerToken`
- **Databases**: `MongoDB`, `Postgres`, `PostgreSQL`, `SQLServer`, `Couchbase`, `Supabase`, `SupabaseToken`
- **Dev Platforms**: `Vercel`, `Netlify`, `Heroku`, `FlyIO`, `RailwayApp`, `DenoDeploy`
- **CMS/Backend**: `Sanity`, `Contentful`, `Airtable`, `Coda`, `Budibase`
- **Monitoring**: `Grafana`, `GrafanaServiceAccount`, `NewRelicPersonalApiKey`, `Dynatrace`, `Datadog`, `Loggly`, `LogzIO`
- **And 150+ more...**

See `taxonomy.json` for complete mappings.

## Registering Icons in BloodHound

The `custom_icons.py` script now reads from taxonomy files:

```bash
# Register all icons from comprehensive taxonomy
python custom_icons.py --token YOUR_TOKEN

# Register icons from minimal taxonomy only
python custom_icons.py --token YOUR_TOKEN --taxonomy taxonomy_minimal.json
```

Each technology gets its brand color:
- AWS: Orange (#FF9900)
- Azure: Blue (#0078D4)
- GCP: Light Blue (#4285F4)
- GitHub: Dark Gray (#181717)
- Stripe: Purple (#635BFF)
- etc.

## BloodHound Queries

With the taxonomy system, you can now query by technology:

```cypher
// Find all AWS secrets
MATCH (s:AWSBase) RETURN s

// Find all AWS secrets in GitHub repositories
MATCH (r:GHRepository)-[:ContainsCredentialsFor]->(s:AWSSecret)
RETURN r, s

// Find all cloud provider secrets (AWS, Azure, GCP)
MATCH (s)
WHERE s:AWSBase OR s:AZBase OR s:GCPBase
RETURN s

// Count secrets by technology (using *Base kinds)
MATCH (s)
WHERE any(kind IN labels(s) WHERE kind ENDS WITH 'Base')
RETURN labels(s), count(s)
ORDER BY count(s) DESC
```

## Extending the Taxonomy

### Adding a New Technology

Edit `taxonomy.json`:

```json
{
  "technologies": {
    "newtechnology": {
      "base_kind": "NewTechBase",
      "secret_kind": "NewTechSecret",
      "color": "#HEXCOLOR",
      "display_name": "New Technology"
    }
  },
  "scanner_mappings": {
    "noseyparker": {
      "np.newtech.1": "newtechnology",
      "np.newtech.2": "newtechnology"
    }
  }
}
```

### Adding Support for Another Scanner

GitHub and Nemesis scanners can follow the same pattern:

```json
{
  "scanner_mappings": {
    "github": {
      "aws_access_key_id": "aws",
      "azure_storage_key": "azure"
    },
    "nemesis": {
      "AWS_KEY": "aws"
    }
  }
}
```

## Migration from Legacy Mappings

If you were using custom mappings via the `-c` flag:

**Old Way** (example_mappings.json):
```json
{
  "mappings": [
    {"pattern": "AWS", "node_kind": "AWSSecret", "color": "#FF9900"}
  ]
}
```

**New Way**: Built into `taxonomy.json` - no `-c` flag needed!

The taxonomy system provides:
- More accurate mapping (by exact rule ID instead of regex)
- Automatic `*Base` kind assignment
- Centralized configuration for all scanners
- Better maintainability

## Files Created

- **taxonomy.py**: Core taxonomy module
- **taxonomy.json**: Comprehensive taxonomy (70+ technologies)
- **taxonomy_minimal.json**: Minimal taxonomy (~25 technologies)
- **TAXONOMY_GUIDE.md**: This documentation

## Backward Compatibility

- Legacy `-c` custom mappings still work
- Taxonomy lookup happens first, then falls back to custom mappings
- If no taxonomy file exists, tool continues with warnings
- All existing parsers and functionality remain intact
