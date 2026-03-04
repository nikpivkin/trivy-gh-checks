# trivy-gh-checks

## How to use

Using additional checks for GitHub Actions is straightforward.

1. Clone the repository containing the checks:
```bash
git clone --depth=1 git@github.com:nikpivkin/trivy-gh-checks
```

2. Specify the path to the checks and their namespace when scanning a repository:
```bash
trivy conf -d .github \
    --misconfig-scanners yaml \
    --config-check trivy-gh-checks/checks \
    --check-namespaces github
```

## Configuration

Some checks support configuration to modify their behavior. 
Configuration is defined using a YAML file and passed to Trivy using the 
`--config-data` flag.

Example usage:
```bash
trivy conf . --config-data config.yaml
```

### trusted-dependency-sources

By default, the `trusted-dependency-sources` check is not applied until it is 
explicitly configured.

To enable it, you must specify a list of trusted action and dependency sources.

Example configuration:

```yaml
github:
    actions:
        config:
            trusted_sources:
                patterns:
                    - actions/
                    - docker/
                    - oras-project/setup-oras/
```

The `patterns` field accepts a list of repository or organization path prefixes 
that are considered trusted.