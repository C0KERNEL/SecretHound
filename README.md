# SecretHound - A BloodHound OpenGraph Extension for Secrets
<p align="center">
  <img src="assets/logo.png" alt="SecretHound Logo" width="400"/>
</p>

SecretHound converts secret scanning results from various sources into a BloodHound OpenGraph format. You can read the blog [here](https://specterops.io/blog/2025/11/13/taming-the-attack-graph-a-many-subgraphs-approach-to-attack-path-analysis/). It leverages @p0dalirius's [bhopengraph](https://github.com/p0dalirius/bhopengraph) library.

**Supported Scanners:**
- GitHub Secret Scanning
- NoseyParker
- TruffleHog
- Nemesis

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![BloodHound](https://img.shields.io/badge/BloodHound-OpenGraph-red.svg)](https://bloodhound.specterops.io/)

## Installation
```bash
git clone https://github.com/C0KERNEL/SecretHound.git
cd SecretHound
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Quick Start

```bash
# Retrieve GitHub Secret Scanning alerts for an org:
gh api /orgs/ORG/secret-scanning/alerts > github_alerts.json

# Parse GitHub Secret Scanning alerts with SecretHound (redacts by default)
python secrethound.py -t github -i github_alerts.json -o og_secrets.json

# Register technology icons in BloodHound (one-time setup)
python custom_icons.py --token YOUR_BLOODHOUND_TOKEN

# Upload og_secrets.json to BloodHound via the UI
```

## Workflow Example using NoseyParker

```bash
# 1. Scan this repository with NoseyParker
git clone https://github.com/C0KERNEL/SecretHound.git
noseyparker scan --datastore np.db SecretHound
noseyparker report --datastore np.db --format json > noseyparker_output.json

# 2. Convert to BloodHound format
python secrethound.py -t noseyparker -i noseyparker_output.json -o bloodhound_secrets.json -v

# 3. Register technology icons in BloodHound (one-time setup)
python custom_icons.py --token YOUR_BLOODHOUND_TOKEN

# 4. Upload bloodhound_secrets.json to BloodHound CE via web UI

# 5. Query using Cypher in BloodHound interface
```

## Usage

### Command Line Interface
```bash
python secrethound.py -t {github,noseyparker,trufflehog,nemesis} -i INPUT -o OUTPUT [OPTIONS]
```
### Arguments

| Argument | Description |
|----------|-------------|
| `-t, --type` | Scanner type: github, noseyparker, trufflehog, or nemesis (required) |
| `-i, --input` | Input file path (JSON or JSONL) (required) |
| `-o, --output` | Output BloodHound JSON file path (required) |
| `--taxonomy` | Taxonomy configuration file (default: taxonomy/taxonomy.json) |
| `--no-redact` | Include full secrets (DANGEROUS - use with caution as your nodes in BloodHound will contain the secrets) |
| `--source-kind` | Source kind for BloodHound OpenGraph (default: StargateNetwork) |
| `-v, --verbose` | Enable verbose logging |

## Technology Taxonomy System
SecretHound uses a centralized taxonomy system to automatically categorize secrets by technology with colors. The taxonomy maps scanner-specific rule IDs to BloodHound node types.

### Built-in Taxonomy Files
- **taxonomy.json** - Comprehensive taxonomy (default)
  - Covers 200+ TruffleHog detectors
  - All NoseyParker and GitHub Secret Scanning rules mapped
  - Ideal for detailed analysis

- **taxonomy_minimal.json** - Minimal taxonomy highlighting ~25 major technologies
  - Focuses on most common cloud providers and services
  - Cleaner BloodHound graphs with less node kinds

- **taxonomy_flat.json** - Flat taxonomy with no technology classification
  - All secrets categorized as generic "Secret" kind
  - Simplest graph structure
  - Ideal for basic secret discovery without technology-specific analysis

See [TAXONOMY_GUIDE.md](taxonomy/TAXONOMY_GUIDE.md) for complete documentation.

### Using Different Taxonomies

```bash
# Use default comprehensive taxonomy
python secrethound.py -t trufflehog -i input.jsonl -o output.json

# Use minimal taxonomy for cleaner graphs
python secrethound.py -t noseyparker -i input.json -o output.json --taxonomy taxonomy/taxonomy_minimal.json

# Use flat taxonomy - all secrets as generic "Secret"
python secrethound.py -t github -i input.json -o output.json --taxonomy taxonomy/taxonomy_flat.json
```

### Node Kind System
Nodes and edges produced by this tool all have a `StargateNetwork` source_kind. I enjoyed the SG-1 TV show :nerd_face:, and it felt like a nice analogy to describe the behavior. You find a credential-at-rest somewhere in an environment and it can be used to teleport you into another subgraph. This reminded me of the Stargate Network in the TV show. I might switch to an analogy involving the Valve game: Portal at somepoint. Either way, I needed to categorize everything that this tool produces. Secrets are assigned either a specific `*Secret` kind based on a `*Base` or generically a `Secret` kind.

Specific specific `AWSSecret` kind based on a `AWSBase` example:
```json
{
  "kinds": ["AWSSecret", "AWSBase"],
  "properties": {
    "secret_type": "AWS Secret Access Key",
    "secret_value_redacted": "AKIA...KEY"
  }
}
```

Generic `Secret` example:
```json
{
  "kinds": ["Secret"],
  "properties": {
    "secret_type": "Generic Secret",
    "secret_value_redacted": "pass...word"
  }
}
```

Note: `StargateNetwork` appears in the `metadata.source_kind` field of the OpenGraph JSON, not in individual node kinds.

This enables powerful Cypher queries across `kind` values:
- `MATCH (s:StargateNetwork) RETURN s` - All nodes generated by this tool
- `MATCH (s:Secret) RETURN s` - All secrets
- `MATCH (s:AWSBase) RETURN s` - All AWS-related nodes
- `MATCH (s:AWSSecret) RETURN s` - Only AWS Secrets
- `MATCH (s:GHBase) RETURN s` - All GitHub nodes
- `MATCH (s:GHSecret) RETURN s` - All GitHub secrets

### Technology Color Scheme

Each technology uses colors for visualization:

| Technology | Node Kinds | Hex Color |
|------------|-----------|-----------|
| AWS | AWSSecret | `#FF9900` |
| Azure |AZSecret | `#0078D4` |
| GCP | GCPSecret | `#4285F4` |
| GitHub | GHSecret | `#181717` |
| ... | ... | `...` |
| Default | Secret | `#ffc800` |

See `taxonomy/taxonomy.json` for the complete list technologies.

### Registering Icons in BloodHound
After generating your BloodHound data, register the technology icons:

```bash
# Register icons from comprehensive taxonomy
python custom_icons.py --token YOUR_BLOODHOUND_TOKEN

# Register icons from minimal taxonomy
python custom_icons.py --token YOUR_TOKEN --taxonomy taxonomy/taxonomy_minimal.json

# Use custom BloodHound URL
python custom_icons.py --token YOUR_TOKEN --url http://bloodhound.local:8080/api/v2/custom-nodes
```

## Scanner-Specific Examples
### GitHub Secret Scanning
```bash
# Export alerts from GitHub
gh api /orgs/YOUR_ORG/secret-scanning/alerts > github_alerts.json

# Convert to BloodHound OpenGraph
python secrethound.py -t github -i github_alerts.json -o og_secrets.json
```

### NoseyParker
```bash
# Scan a repository
noseyparker scan --datastore np.db --git-url https://github.com/example/repo.git

# Generate JSON report
noseyparker report --datastore np.db --format json > noseyparker_output.json

# Convert to BloodHound OpenGraph
python secrethound.py -t noseyparker -i noseyparker_output.json -o og_secrets.json
```

### TruffleHog
```bash
# Scan with TruffleHog
trufflehog git https://github.com/example/repo.git --json > trufflehog_output.jsonl

# Convert to BloodHound OpenGraph
python secrethound.py -t trufflehog -i trufflehog_output.jsonl -o og_secrets.json
```

### Nemesis
```bash
# Export data from Nemesis and convert
python scripts/fetch_nemesis_findings.py --api-key <Hasura GraphQL API key> > nemesis_export.json

# Convert to BloodHound OpenGraph
python secrethound.py -t nemesis -i nemesis_export.json -o og_secrets.json
```

## Example BloodHound Queries
Taking advantage of the kind system:

```cypher
// Find all secrets
MATCH (s:Secret) RETURN s


// Find only AWS Secret Access Keys
MATCH (s:AWSSecret) RETURN s

// Find nodes added by SecretHound
MATCH (s:StargateNetwork) RETURN s

// Find paths using secrets
MATCH p=(r:StargateNetwork)-[:ContainsCredentialsFor]->(s:StargateNetwork)
RETURN p

// Find hybrid attack paths to Azure
MATCH p=(s:StargateNetwork)-[r*..]->(t:AZBase)
RETURN p

// Find hybrid attack paths to AWS
MATCH p=(s:StargateNetwork)-[r*..]->(t:AWSBase)
RETURN p

// Find hybrid attack paths to GCP
MATCH p=(s:StargateNetwork)-[r*..]->(t:GCPBase)
RETURN p
```

### OpenGraph Compatibility
SecretHound is designed to be compatible with existing BloodHound OpenGraph extensions:

**Compatible Extensions:**
- [ ] [GitHound](https://github.com/SpecterOps/GitHound) - GitHub repository and user mapping (work in progress)
- [x] [GCP-Hound](https://github.com/F41zK4r1m/GCP-Hound) - GCP technology subgraph - Adds nodes with `GCPBase` kind

## Acknowledgments
- **SpecterOps** - BloodHound, OpenGraph, GitHound, Nemesis, and everyone that has let me bounce ideas off of them 😃
- **Praetorian** - NoseyParker
- **TruffleSecurity** - TruffleHog
- **LeakTK** - fake-leaks testing repository
- **p0dalirius** - bhopengraph library

## References

- [BloodHound Enterprise](https://specterops.io/bloodhound-enterprise/) / [BloodHound CE](https://github.com/SpecterOps/BloodHound)
- [OpenGraph](https://bloodhound.specterops.io/opengraph/best-practices)
- [GitHound](https://github.com/SpecterOps/GitHound)
- [Nemesis](https://github.com/SpecterOps/Nemesis)
- [NoseyParker](https://github.com/praetorian-inc/noseyparker)
- [TruffleHog](https://github.com/trufflesecurity/trufflehog)
- [LeakTK](https://github.com/leaktk/fake-leaks)
- [bhopengraph](https://github.com/p0dalirius/bhopengraph)
