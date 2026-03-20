# Tooling Integration

This repository is part of the [nostalgia2812 security tools organization](https://github.com/nostalgia2812) and is integrated into the centralized tooling and filing system.

## Catalog Entry

- **Tool ID:** `adk-python`
- **Category:** Development Frameworks
- **Central Manifest:** [.github/.tooling/tool_manifest.json](https://github.com/nostalgia2812/.github/blob/claude/tooling-filing-system-uG7Gs/.tooling/tool_manifest.json)
- **Full Documentation:** [TOOLS_INDEX.md](https://github.com/nostalgia2812/.github/blob/claude/tooling-filing-system-uG7Gs/TOOLS_INDEX.md#adk-python)

## Integration

This tool is managed via the central hub repository at [nostalgia2812/.github](https://github.com/nostalgia2812/.github).

### Quick Install

```bash
# Clone the hub and run the installer
git clone https://github.com/nostalgia2812/.github.git nostalgia2812-hub
cd nostalgia2812-hub
./scripts/install_all.sh adk-python
```

### Health Check

```bash
./scripts/check_health.sh
```

## Metadata

See [.tooling/tool.json](.tooling/tool.json) for machine-readable metadata about this tool.

## Security

This repository is automatically scanned for secrets on every commit using:
- [Gitleaks](https://github.com/gitleaks/gitleaks) (see [.github/workflows/secret-scan.yml](.github/workflows/secret-scan.yml))
- [TruffleHog](https://github.com/trufflesecurity/trufflehog)

Results are available in the [GitHub Security tab](https://github.com/nostalgia2812/adk-python/security/code-scanning).
