# NPM Versioning Best Practices

## Distribution Tags

NPM uses distribution tags (dist-tags) to manage different release channels:

### 1. **latest** (Default Tag)
- The stable, production-ready version
- Installed by default when users run `npm install <package>`
- Should always be the most recent stable release

### 2. **beta** Tag
- Pre-release versions for testing
- Users must explicitly install: `npm install <package>@beta`
- For features that need community testing before stable release

### 3. **next** Tag
- Often used for release candidates
- More stable than beta, less than latest
- Common pattern: alpha → beta → next → latest

## Best Practices

### Version Numbering
```
1.2.3-beta.1  → 1.2.3-beta.2  → 1.2.3-rc.1  → 1.2.3
│ │ │   │  │      │ │ │   │  │      │ │ │  │  │    │ │ │
│ │ │   │  └──────┴─┴─┴───┴──┴──────┴─┴─┴──┴──┴────┴─┴─┴── Stable
│ │ │   └── Pre-release identifier
│ │ └── Patch version
│ └── Minor version  
└── Major version
```

### Publishing Workflow

1. **Development Phase**
   ```bash
   npm version 1.3.0-alpha.1
   npm publish --tag alpha
   ```

2. **Beta Testing**
   ```bash
   npm version 1.3.0-beta.1
   npm publish --tag beta
   ```

3. **Release Candidate**
   ```bash
   npm version 1.3.0-rc.1
   npm publish --tag next
   ```

4. **Stable Release**
   ```bash
   npm version 1.3.0
   npm publish  # Automatically tags as 'latest'
   ```

### Managing Tags

```bash
# View all tags
npm dist-tag ls @re-shell/cli

# Add/move tags
npm dist-tag add @re-shell/cli@1.3.0 latest
npm dist-tag add @re-shell/cli@1.4.0-beta.1 beta

# Remove tags
npm dist-tag rm @re-shell/cli beta
```

### Installation Commands

```bash
# Install latest stable
npm install @re-shell/cli

# Install specific tag
npm install @re-shell/cli@beta
npm install @re-shell/cli@next

# Install specific version
npm install @re-shell/cli@1.3.0-beta.1
```

## Recommended Strategy for @re-shell/cli

1. **Stable Releases** (latest)
   - Production-ready versions
   - Thoroughly tested
   - Follow semantic versioning strictly

2. **Beta Releases** (beta)
   - New features for community testing
   - May have minor bugs
   - Version format: `X.Y.Z-beta.N`

3. **Experimental** (experimental)
   - Cutting-edge features
   - May have breaking changes
   - Version format: `X.Y.Z-experimental.N`

### Example Release Cycle

```
Feature Development
    ↓
1.3.0-experimental.1 (tag: experimental)
    ↓
1.3.0-beta.1 (tag: beta)
    ↓
1.3.0-beta.2 (tag: beta)
    ↓
1.3.0-rc.1 (tag: next)
    ↓
1.3.0 (tag: latest)
```

## Common Pitfalls to Avoid

1. **Don't publish unstable code as latest**
   - Always use pre-release tags for testing

2. **Don't skip version numbers**
   - Maintain sequential versioning

3. **Don't forget to update tags**
   - Move beta tag to new beta versions
   - Update latest tag for stable releases

4. **Don't use latest tag for pre-releases**
   - This confuses users and breaks installations

## Automation Tips

Add to package.json scripts:
```json
{
  "scripts": {
    "release:beta": "npm version prerelease --preid=beta && npm publish --tag beta",
    "release:stable": "npm version patch && npm publish",
    "release:minor": "npm version minor && npm publish",
    "release:major": "npm version major && npm publish"
  }
}
```

## Current Status Check

Run this to see current tags:
```bash
npm view @re-shell/cli dist-tags
```

This will show something like:
```
{
  latest: '0.2.9',
  beta: '0.2.10-beta.1'
}
```