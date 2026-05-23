# Publishing Aegis (PyPI + MCP Registry)

The repository ships everything needed to publish to:

1. **PyPI** as `aegis-sec`.
2. **MCP Registry** as `io.github.verrysimatupang99/aegis`.

## One-time setup (browser steps)

These steps need a human at a browser; they cannot be automated from the CLI.

### A. PyPI trusted publishing

1. Sign in at https://pypi.org/.
2. Either reserve the project first by uploading a manual sdist as
   `aegis-sec`, or wait for the GitHub Action to do the first upload via
   token. Trusted publishing is preferred long term.
3. Go to https://pypi.org/manage/account/publishing/.
4. Add a *pending publisher* with:
   - Project name: `aegis-sec`
   - Owner: `verrysimatupang99`
   - Repository name: `aegis`
   - Workflow filename: `release.yml`
   - Environment name: `pypi`
5. In the GitHub repo, add an Environment named `pypi` under
   `Settings → Environments`.

After that, every `git tag v* && git push origin v*` will:

- Build the sdist + wheel.
- Sign with sigstore (provenance attached to the artifacts).
- Publish to PyPI via OIDC, no password required.

### B. GitHub topics + branch protection

Already set: topics `mcp`, `mcp-server`, `security`, `claude`, `codex`,
`anthropic`, `audit`, `defensive-security`, `ai-copilot`. Optionally enable
branch protection on `main`:

```bash
gh api -X PUT repos/verrysimatupang99/aegis/branches/main/protection \
  -f required_status_checks.strict=true \
  -F required_status_checks.contexts='["pytest + eval (py3.12)"]' \
  -F enforce_admins=true \
  -F required_pull_request_reviews.required_approving_review_count=0 \
  -f restrictions=
```

## Cutting v0.1.0

```bash
cd /home/mrtrickster99/Documents/Coding/arctryx
git tag -a v0.1.0 -m "Aegis 0.1.0: defensive security copilot with MCP server"
git push origin v0.1.0
```

Watch the workflow:

```bash
gh run watch --repo verrysimatupang99/aegis
```

## Publishing to the MCP Registry

The MCP Registry retired the README server list in favor of a programmatic
registry. Aegis already ships:

- `server.json` at the repo root with the published name
  `io.github.verrysimatupang99/aegis`.
- A `mcp-name: io.github.verrysimatupang99/aegis` HTML comment at the top of
  `README.md`, which becomes the `long_description` on PyPI - this is what
  the registry uses to verify ownership of the PyPI package.

Once `aegis-sec 0.1.0` is on PyPI:

```bash
# 1. Install the publisher CLI (Linux/macOS)
curl -L "https://github.com/modelcontextprotocol/registry/releases/latest/download/mcp-publisher_$(uname -s | tr '[:upper:]' '[:lower:]')_$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/').tar.gz" \
  | tar xz mcp-publisher && sudo mv mcp-publisher /usr/local/bin/

# 2. Authenticate with GitHub (device flow)
mcp-publisher login github

# 3. Publish
cd /home/mrtrickster99/Documents/Coding/arctryx
mcp-publisher publish

# 4. Verify
curl "https://registry.modelcontextprotocol.io/v0.1/servers?search=io.github.verrysimatupang99/aegis"
```

## Troubleshooting

- **"Registry validation failed for package"** — the PyPI long description
  must contain the `mcp-name: ...` marker. Confirm with:
  `pip download --no-deps aegis-sec -d /tmp/x && tar tf /tmp/x/aegis_sec-*.tar.gz | grep README` and inspect.
- **"You do not have permission to publish this server"** — the `name` in
  `server.json` must start with `io.github.<your-username>/`. Ours does.
- **Tag already exists** — delete and retry:
  `git tag -d v0.1.0 && git push origin :refs/tags/v0.1.0`.
