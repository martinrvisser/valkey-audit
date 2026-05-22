# How to Release ValkeyAudit

## Version Format

Versions follow semantic versioning (`MAJOR.MINOR.PATCH`) with an optional pre-release suffix.

The version is encoded as a 32-bit integer in `src/version.h`:

32          24          16          8           0

|-----------|-----------|-----------|-----------|

|   MAJOR   |   MINOR   |   PATCH   |  DEV, RC  |

DEV byte values:
- `0x01` = dev (e.g. `1.0.0-dev`)
- `0x02` = rc1, `0x03` = rc2, etc.
- `0xFF` = GA release (e.g. `1.0.0`)

## Release Process

### 1. Create a release branch

```bash
git checkout -b 1.0
```

### 2. Update the version

Edit `src/version.h`:
```c
#define VALKEYAUDIT_VERSION_MAJOR 1
#define VALKEYAUDIT_VERSION_MINOR 0
#define VALKEYAUDIT_VERSION_PATCH 0
#define VALKEYAUDIT_VERSION_DEV   0x02  /* rc1 */
```

Edit `CMakeLists.txt`:
```cmake
project(ValkeyAudit VERSION 1.0.0 ...)
```

### 3. Update CHANGELOG.md

Move items from `[Unreleased]` to a new versioned section:
```markdown
## [1.0.0-rc1] - YYYY-MM-DD
```

### 4. Commit and tag

```bash
git add src/version.h CMakeLists.txt CHANGELOG.md
git commit -m "Bump to 1.0.0-rc1"
git tag -s -a v1.0.0-rc1 -m "version 1.0.0-rc1"
git push origin 1.0 --tags
```

### 5. GA release

Once the release candidate is validated, update `VALKEYAUDIT_VERSION_DEV` to `0xFF`,
update `CHANGELOG.md` with the GA date, commit, tag `v1.0.0`, and push.

```bash
git tag -s -a v1.0.0 -m "version 1.0.0"
git push origin 1.0 --tags
```
### 6. Verify the GitHub Release

After pushing the tag, the `release.yml` CI workflow will automatically:
- Build `libvalkeyaudit.so`
- Create a draft GitHub Release with the `.so` attached

Go to [Releases](https://github.com/martinrvisser/valkey-audit/releases), review the
draft, add release notes from `CHANGELOG.md`, and publish it.

### 7. Back-merge to main

```bash
git checkout main
git merge 1.0
git push origin main
```

### 8. Start the next development cycle

On `main`, bump `src/version.h` to the next version with `DEV = 0x01` and
update `CMakeLists.txt` to match.
