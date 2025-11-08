# SecretHound

> **BloodHound OpenGraph Extension for Secrets**

SecretHound converts secret scanning results from various sources into BloodHound OpenGraph format for attack path visualization and analysis. It uses @p0dalirius's bhopengraph library to create compatible BloodHound data.

Supported secret scanners:
- GitHub Secret Scanning
- NoseyParker
- TruffleHog
- Nemesis (work in progress)

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![BloodHound](https://img.shields.io/badge/BloodHound-OpenGraph-red.svg)](https://bloodhound.specterops.io/)

## Features

- **Centralized Taxonomy System** - 70+ technologies with scanner-specific rule ID mapping
  - Covers 200+ TruffleHog detectors and all NoseyParker rules
  - Brand-accurate colors for each technology
  - Choose between comprehensive or minimal taxonomy

- **Dual Node Kind System** - Query secrets by specific type or technology category
  - Example: `AWSSecret` (specific) + `AWSBase` (all AWS secrets)
  - Enables powerful Cypher queries in BloodHound

- **Multi-Scanner Support** - Unified BloodHound format across different tools
  - GitHub Secret Scanning, NoseyParker, TruffleHog, Nemesis (WIP)

- **Flexible Input** - File or stdin for easy pipeline integration

- **Security-First** - Secrets redacted by default to prevent accidental exposure

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/C0KERNEL/SecretHound.git
cd SecretHound

# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Basic Usage

```bash
# Parse GitHub Secret Scanning output
# (Export alerts from GitHub and save to github_alerts.json first)
python secrethound.py -t github -i github_alerts.json -o secrets.json

# Parse NoseyParker output
noseyparker scan --datastore np.db /path/to/repo
noseyparker report --datastore np.db --format json > noseyparker_output.json
python secrethound.py -t noseyparker -i noseyparker_output.json -o secrets.json

# Parse TruffleHog output (or pipe directly through stdin)
trufflehog git file:///path/to/repo --json | python secrethound.py -t trufflehog -o secrets.json

# Register technology icons in BloodHound (one-time setup)
python custom_icons.py --token YOUR_BLOODHOUND_TOKEN

# Import the output JSON to BloodHound
# Upload secrets.json to BloodHound via the UI
```

## Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager
- At least one secret scanner:
  - GitHub Secret Scanning
  - NoseyParker
  - TruffleHog
  - Nemesis (work in progress)
- BloodHound Community Edition or Enterprise

### Install Dependencies

```bash
pip install bhopengraph requests
```

Or use the requirements file:

```bash
pip install -r requirements.txt
```

### Verify Installation

```bash
python secrethound.py --help
```

## Usage

### Command Line Interface

```bash
python secrethound.py [-h] -t {github,noseyparker,trufflehog,nemesis}
                      [-i INPUT] -o OUTPUT [--taxonomy TAXONOMY]
                      [-c CONFIG] [--no-redact]
                      [--source-kind SOURCE_KIND]
                      [--nemesis-url URL] [--nemesis-api-key KEY]
                      [-v]
```

### Arguments

| Argument | Description |
|----------|-------------|
| `-t, --type` | Scanner type: github, noseyparker, trufflehog, or nemesis |
| `-i, --input` | Input file path (JSON or JSONL). If omitted, reads from stdin |
| `-o, --output` | Output BloodHound JSON file path (required) |
| `--taxonomy` | Taxonomy configuration file (default: taxonomy.json) |
| `-c, --config` | Legacy custom mappings configuration file (optional) |
| `--no-redact` | Include full secrets (DANGEROUS - use with caution!) |
| `--source-kind` | Source kind for BloodHound OpenGraph (default: StargateNetwork) |
| `--nemesis-url` | Nemesis API URL (for nemesis type) |
| `--nemesis-api-key` | Nemesis API key (for nemesis type) |
| `-v, --verbose` | Enable verbose logging |

### Scanner-Specific Examples

#### GitHub Secret Scanning

```bash
# Parse from a previously exported JSON file
python secrethound.py \
    -t github \
    -i github_alerts.json \
    -o bloodhound_secrets.json

# With verbose logging
python secrethound.py \
    -t github \
    -i github_alerts.json \
    -o bloodhound_secrets.json \
    -v
```

#### NoseyParker

```bash
# Scan a repository
noseyparker scan --datastore np.db https://github.com/example/repo.git

# Generate JSON report
noseyparker report --datastore np.db --format json > noseyparker_output.json

# Convert to BloodHound (with redaction - default)
python secrethound.py \
    -t noseyparker \
    -i noseyparker_output.json \
    -o bloodhound_secrets.json
```

#### TruffleHog

```bash
# Scan with TruffleHog and save to file
trufflehog git https://github.com/example/repo.git --json > trufflehog_output.jsonl

# Convert to BloodHound
python secrethound.py \
    -t trufflehog \
    -i trufflehog_output.jsonl \
    -o bloodhound_secrets.json \
    -v

# Or pipe directly through stdin
trufflehog git file://. --json | python secrethound.py -t trufflehog -o bloodhound_secrets.json
```

#### Nemesis (work in progress)

```bash
# Export data from Nemesis and convert to BloodHound
python secrethound.py \
    -t nemesis \
    -i nemesis_export.json \
    -o bloodhound_secrets.json
```

## Technology Taxonomy System

SecretHound uses a centralized taxonomy system to automatically categorize secrets by technology with brand-accurate colors. The taxonomy maps scanner-specific rule IDs to BloodHound node types.

### Built-in Taxonomy Files

- **taxonomy.json** - Comprehensive taxonomy with 70+ technologies
  - Covers 200+ TruffleHog detectors
  - All NoseyParker rules mapped
  - Ideal for detailed analysis

- **taxonomy_minimal.json** - Minimal taxonomy with ~25 major technologies
  - Focuses on most common cloud providers and services
  - Cleaner BloodHound graphs with less node kinds
  - Good for high-level overviews

See [TAXONOMY_GUIDE.md](TAXONOMY_GUIDE.md) for complete documentation.

### Using the Taxonomy System

```bash
# Use default comprehensive taxonomy (taxonomy.json)
python secrethound.py -t trufflehog -i input.jsonl -o output.json

# Use minimal taxonomy for cleaner graphs
python secrethound.py -t noseyparker -i input.json -o output.json --taxonomy taxonomy_minimal.json

# Use custom taxonomy file
python secrethound.py -t trufflehog -i input.jsonl -o output.json --taxonomy my_custom_taxonomy.json
```

### Dual Node Kind System

Secrets are assigned both specific and base node kinds for flexible querying:

```json
{
  "kinds": ["Secret", "AWSSecret", "AWSBase", "StargateNetwork"],
  "properties": {
    "secret_type": "AWS Secret Access Key",
    "secret_value_redacted": "AKIA...KEY"
  }
}
```

This enables powerful Cypher queries:
- `MATCH (s:Secret)` - All secrets
- `MATCH (s:AWSBase)` - All AWS-related secrets (access keys, tokens, etc.)
- `MATCH (s:AWSSecret)` - Only specific AWS Secret Access Keys
- `MATCH (s:GHBase)` - All GitHub secrets (PATs, app tokens, OAuth, etc.)

### Technology Color Scheme

Each technology uses its official brand color:

| Technology | Node Kinds | Color | Hex Code |
|------------|-----------|-------|----------|
| AWS | AWSBase, AWSSecret, AWSAccessToken, etc. | 🟠 Orange | `#FF9900` |
| Azure | AZBase, AZSecret, AZToken, etc. | 🔵 Blue | `#0078D4` |
| GCP | GCPBase, GCPSecret, GCPToken, etc. | 🔵 Light Blue | `#4285F4` |
| GitHub | GHBase, GHPAT, GHApp, etc. | 🟣 Purple | `#6e5494` |
| Slack | SlackBase, SlackWebhook, SlackToken | 🟣 Purple | `#4A154B` |
| Stripe | StripeBase, StripeKey | 🟣 Purple | `#635BFF` |
| Default | Secret | 🟡 Yellow | `#ffc800` |

See `taxonomy.json` for the complete list of 70+ technologies.

### Legacy Custom Mappings (Deprecated)

Pattern-based custom mappings are still supported via `-c/--config` but are deprecated in favor of the taxonomy system:

```bash
# Legacy pattern-based mappings (still works)
python secrethound.py -t noseyparker -i input.json -o output.json -c example_mappings.json
```

The taxonomy system is more accurate because it maps specific scanner rule IDs instead of pattern matching, ensuring correct categorization.

### Registering Icons in BloodHound

After generating your BloodHound data, register the technology icons with brand-accurate colors:

```bash
# Register icons from comprehensive taxonomy (70+ technologies)
python custom_icons.py --token YOUR_BLOODHOUND_TOKEN

# Register icons from minimal taxonomy (~25 technologies)
python custom_icons.py --token YOUR_TOKEN --taxonomy taxonomy_minimal.json

# Use custom BloodHound URL
python custom_icons.py --token YOUR_TOKEN --url http://bloodhound.local:8080/api/v2/custom-nodes
```

**How to get your BloodHound token:**
1. Log in to BloodHound CE web interface
2. Go to your user profile or API settings
3. Generate an API token
4. Use it with the `--token` flag

## Additional Utilities

### Graph Utilities (graph_utils.py)

Modify existing BloodHound graphs programmatically:

```bash
python graph_utils.py
```

Features:
- Import and export BloodHound graphs
- Add/update nodes and edges
- Query nodes by kind or ID
- Get graph statistics
- Merge multiple graphs

### OpenGraph Compatibility

SecretHound is designed to be compatible with existing BloodHound OpenGraph extensions:

**Compatible Extensions:**
- [GitHound](https://github.com/SpecterOps/GitHound) - GitHub repository and user mapping
- [GCP-Hound](https://github.com/F41zK4r1m/GCP-Hound) - GCP technology subgraph

**Planned Integrations:**
- `GHPersonalAccessToken` - Link PAT to GitHub users
- `GHRepo` - Repository as starting node
- `GHCommit` - Commit-level secret tracking
- `AWSUser`, `AWSAccount` - AWS identity mapping
- `AZUser` - Azure identity mapping
- `GCPUser` - GCP identity mapping


## Security

### Redaction (Default)

By default, SecretHound **redacts secret values**: `AKIA...MPLE`

### Disabling Redaction

**WARNING**: Only use `--no-redact` in secure, isolated environments!





### Example BloodHound Queries

Take advantage of the dual node kind system for powerful querying:

```cypher
// Find all secrets
MATCH (s:Secret) RETURN s

// Find all AWS-related secrets (access keys, tokens, etc.)
MATCH (s:AWSBase) RETURN s

// Find only AWS Secret Access Keys (specific type)
MATCH (s:AWSSecret) RETURN s

// Find all GitHub secrets (PATs, app tokens, OAuth, etc.)
MATCH (s:GHBase) RETURN s

// Find secrets in a specific repository
MATCH (r:GHRepository)-[:ContainsCredentialsFor]->(s:Secret)
WHERE r.name =~ '.*myrepo.*'
RETURN r, s

// Find all cloud provider secrets (AWS, Azure, GCP)
MATCH (s:Secret)
WHERE s:AWSBase OR s:AzureBase OR s:GCPBase
RETURN s.secret_type, s.secret_value_redacted, labels(s)

// Count secrets by technology
MATCH (s:Secret)
WITH s, [label IN labels(s) WHERE label ENDS WITH 'Base'] AS tech_labels
UNWIND tech_labels AS tech
RETURN tech, count(s) as count
ORDER BY count DESC

// Find high-risk secrets (verified by scanner)
MATCH (s:Secret)
WHERE s.verified = true
RETURN s.secret_type, s.file_path, s.repository

// Find secrets with specific commit information
MATCH (s:Secret)
WHERE s.commit IS NOT NULL
RETURN s.secret_type, s.file_path, s.commit
```

### Complete Workflow Example

```bash
# 1. Scan repositories with NoseyParker
noseyparker scan --datastore np.db https://github.com/myorg/myrepo.git
noseyparker report --datastore np.db --format json > noseyparker_output.json

# 2. Convert to BloodHound format with taxonomy
python secrethound.py \
    -t noseyparker \
    -i noseyparker_output.json \
    -o bloodhound_secrets.json \
    -v

# 3. Register technology icons in BloodHound (one-time setup)
python custom_icons.py --token YOUR_BLOODHOUND_TOKEN

# 4. Upload bloodhound_secrets.json to BloodHound CE
# Via web UI: File Upload → Select bloodhound_secrets.json

# 5. Query secrets in BloodHound
# Use Cypher queries in the BloodHound interface
```

### Pipeline Example (stdin)

```bash
# TruffleHog pipeline - scan and convert in one command
trufflehog git file://. --json | \
    python secrethound.py -t trufflehog -o secrets.json

# NoseyParker pipeline
noseyparker report --datastore np.db --format json | \
    python secrethound.py -t noseyparker -o secrets.json
```

## Acknowledgments

- **SpecterOps** - BloodHound, OpenGraph, GitHound, Nemesis
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

