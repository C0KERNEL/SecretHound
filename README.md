# SecretHound

> **BloodHound OpenGraph Extension for Secrets**

SecretHound converts secret scanning results from various sources into BloodHound OpenGraph format for attack path visualization and analysis. It uses @p0dalirius's bhopengraph library to create compatible BloodHound data.

Supported secret scanners:
- GitHub Secret Scanning API (work in progress)
- NoseyParker
- TruffleHog
- Nemesis (work in progress)

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![BloodHound](https://img.shields.io/badge/BloodHound-OpenGraph-red.svg)](https://bloodhound.specterops.io/)

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
# Fetch from GitHub Secret Scanning API (work in progress)
export GITHUB_TOKEN="ghp_your_token_here"
python secrethound.py -t github --github-owner myorg --github-repo myrepo -o secrets.json

# Parse NoseyParker output
noseyparker scan --datastore np.db /path/to/repo
noseyparker report --datastore np.db --format json > noseyparker_output.json
python secrethound.py -t noseyparker -i noseyparker_output.json -o secrets.json

# Parse TruffleHog output
trufflehog git file:///path/to/repo --json > trufflehog_output.jsonl
python secrethound.py -t trufflehog -i trufflehog_output.jsonl -o secrets.json

# Import the output JSON to BloodHound
# Upload secrets.json to BloodHound via the UI
```

## Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager
- At least one secret scanner:
  - GitHub Secret Scanning (requires repository access and GitHub token)
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
                      [-i INPUT] -o OUTPUT [-c CONFIG] [--no-redact]
                      [--source-kind SOURCE_KIND]
                      [--github-token TOKEN] [--github-owner OWNER] [--github-repo REPO]
                      [--nemesis-url URL] [--nemesis-api-key KEY]
                      [-v]
```

### Arguments

| Argument | Description |
|----------|-------------|
| `-t, --type` | Scanner type: github, noseyparker, trufflehog, or nemesis |
| `-i, --input` | Input file path (JSON or JSONL) - not required for GitHub API mode |
| `-o, --output` | Output BloodHound JSON file path (required) |
| `-c, --config` | Custom mappings configuration file (optional) |
| `--no-redact` | Include full secrets (DANGEROUS - use with caution!) |
| `--source-kind` | Source kind for BloodHound OpenGraph (default: StargateNetwork) |
| `--github-token` | GitHub personal access token (or use GITHUB_TOKEN env var) |
| `--github-owner` | GitHub repository owner/organization (for API mode) |
| `--github-repo` | GitHub repository name (for API mode) |
| `--github-include-locations` | Include location details for GitHub alerts (default: True) |
| `--nemesis-url` | Nemesis API URL (for nemesis type) |
| `--nemesis-api-key` | Nemesis API key (for nemesis type) |
| `-v, --verbose` | Enable verbose logging |

### Scanner-Specific Examples

#### GitHub Secret Scanning (work in progress)

```bash
# Set your GitHub token (requires repo access and secret scanning permissions)
export GITHUB_TOKEN="ghp_your_token_here"

# Fetch secrets directly from GitHub API
python secrethound.py \
    -t github \
    --github-owner myorganization \
    --github-repo myrepository \
    -o bloodhound_secrets.json

# Or parse from a previously exported JSON file
# (export from GitHub API and save to file first)
python secrethound.py \
    -t github \
    -i github_alerts.json \
    -o bloodhound_secrets.json

# With custom token (not using environment variable)
python secrethound.py \
    -t github \
    --github-token ghp_your_token \
    --github-owner myorganization \
    --github-repo myrepository \
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
# Scan with TruffleHog
trufflehog git https://github.com/example/repo.git --json > trufflehog_output.jsonl

# Convert to BloodHound
python secrethound.py \
    -t trufflehog \
    -i trufflehog_output.jsonl \
    -o bloodhound_secrets.json \
    -v
```

#### Nemesis (work in progress)

```bash
# Export data from Nemesis and convert to BloodHound
python secrethound.py \
    -t nemesis \
    -i nemesis_export.json \
    -o bloodhound_secrets.json
```

### Custom Mappings

```bash
# Create custom mappings file (see example_mappings.json)
python secrethound.py \
    -t noseyparker \
    -i input.json \
    -o output.json \
    -c custom_mappings.json
```

## Custom Mappings & Visualization

SecretHound supports custom mappings to categorize secrets by technology and visualize them with color-coded icons in BloodHound.

### Mapping Configuration

Create a JSON file to customize how secrets map to BloodHound node types and colors:

```json
{
  "mappings": [
    {
      "pattern": "AWS",
      "node_kind": "AWSBase",
      "color": "#FF9900"
    },
    {
      "pattern": "Azure",
      "node_kind": "AZBase",
      "color": "#0078D4"
    },
    {
      "pattern": "GCP",
      "node_kind": "GCPBase",
      "color": "#4285F4"
    },
    {
      "pattern": "GitHub",
      "node_kind": "GHBase",
      "color": "#6e5494"
    }
  ],
  "default_color": "#ffc800"
}
```

### Mapping Fields

- **pattern**: Regex pattern to match secret type (case-insensitive)
- **node_kind**: BloodHound node kind to add (e.g., AWSBase, AZBase, GCPBase, GHBase)
- **color**: Hex color code for the icon in BloodHound
- **default_color**: Color for secrets that don't match any pattern

### Default Color Scheme

| Secret Type | Node Kind | Color | Hex Code |
|-------------|-----------|-------|----------|
| AWS | AWSBase | 🟠 Orange | `#FF9900` |
| Azure | AZBase | 🔵 Blue | `#0078D4` |
| GCP | GCPBase | 🔵 Light Blue | `#4285F4` |
| GitHub | GHBase | 🟣 Purple | `#6e5494` |
| Default/Other | Secret | 🟡 Yellow | `#ffc800` |

### Using Custom Mappings

```bash
# Without mappings - all secrets are just "Secret" nodes
python secrethound.py -t noseyparker -i input.json -o output.json

# With mappings - secrets get categorized (e.g., AWSBase, AZBase)
python secrethound.py -t noseyparker -i input.json -o output.json -c example_mappings.json
```

### Registering Custom Icons in BloodHound

After generating your BloodHound data, register the custom icons:

```bash
# Register icons with default mappings
python custom_icons.py --token YOUR_BLOODHOUND_TOKEN

# Register icons with custom mappings file
python custom_icons.py --token YOUR_TOKEN -m custom_mappings.json

# Use custom BloodHound URL
python custom_icons.py --token YOUR_TOKEN --url http://bloodhound.local:8080/api/v2/custom-nodes
```

**How to get your BloodHound token:**
1. Log in to BloodHound CE web interface
2. Go to your user profile or API settings
3. Generate an API token
4. Use it with the `--token` flag

### Node Structure

When using custom mappings, secret nodes have multiple kinds for filtering:

```json
{
  "kinds": ["Secret", "AWSBase", "StargateNetwork"],
  "properties": {
    "secret_type": "AWS Secret Access Key",
    "secret_value_redacted": "AKIA...KEY"
  }
}
```

This allows you to query by:
- `MATCH (s:Secret)` - All secrets
- `MATCH (s:AWSBase)` - Only AWS secrets
- `MATCH (s:Secret:AWSBase)` - AWS secrets (explicit)

## OpenGraph Compatibility

SecretHound is designed to be compatible with existing BloodHound OpenGraph extensions and plan for future extensions.

### Compatibility OpenGraph extensions
-  https://github.com/SpecterOps/GitHound/tree/main
- [ ] `source_kind: GHBase` technology subgraph
- [ ] `GHPersonalAccessToken` - PAT belongs to which user? (Dest Node)
- [ ] `GHRepo` - Secret is in which repo? (Starting Node)
- [ ] `GHCommit` - Secret was in which commit? Useful when GH Secret Scanner not set up and need to trace back the other tool's results.
- [ ] `GHSecretScanningAlert` - Starting node - See https://github.com/SpecterOps/GitHound/blob/main/githound.ps1#L1233-L1244
- Others
- [ ] `AWSUser` - Dest node
- [ ] `AWSAccount` - Dest node
- [ ] `AZUser` - Dest node
- https://github.com/F41zK4r1m/GCP-Hound
- [ ] `source_kind: GCP` technology subgraph
  - [ ] node `kind: GCPUser` Dest node
- Future


## Security

### Redaction (Default)

By default, SecretHound **redacts secret values**: `AKIA...MPLE`

### Disabling Redaction

**WARNING**: Only use `--no-redact` in secure, isolated environments!





### Example BloodHound Queries

```cypher
// Find all secrets
MATCH (s:Secret) RETURN s

// Find all AWS secrets
MATCH (s:AWSBase) RETURN s

// Find secrets in a specific repository
MATCH (r:GHRepository)-[:ContainsCredentialsFor]->(s:Secret)
WHERE r.name =~ '.*myrepo.*'
RETURN r, s

// Find all AWS secrets in GitHub repositories
MATCH (r:GHRepository)-[:ContainsCredentialsFor]->(s:Secret:AWSBase)
RETURN r, s

// Count secrets by type
MATCH (s:Secret)
RETURN s.secret_type, count(s) as count
ORDER BY count DESC

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

# 2. Convert to BloodHound format with custom mappings
python secrethound.py \
    -t noseyparker \
    -i noseyparker_output.json \
    -o bloodhound_secrets.json \
    -c example_mappings.json \
    -v

# 3. Register custom icons in BloodHound (one-time setup)
python custom_icons.py --token YOUR_BLOODHOUND_TOKEN

# 4. Upload bloodhound_secrets.json to BloodHound CE
# Via web UI: File Upload → Select bloodhound_secrets.json

# 5. Query secrets in BloodHound
# Use Cypher queries in the BloodHound interface
```

## Acknowledgments

- **SpecterOps** - BloodHound, OpenGraph, GitHound, Nemesis
- **Praetorian** - NoseyParker
- **TruffleSecurity** - TruffleHog
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

