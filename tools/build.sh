#!/bin/sh
# build.sh — package the runtime extension into a Chrome Web Store ZIP.
# The Web Store accepts a ZIP (manifest at the root) and produces the signed
# CRX after review. Dev files (tools/, test/, README, the 1.2MB icon source)
# are excluded.
set -e
cd "$(dirname "$0")/.."

VERSION=$(python3 -c "import json;print(json.load(open('manifest.json'))['version'])")
OUT="dist"
STAGE="$OUT/dlp-guard"
ZIP="$OUT/dlp-guard-$VERSION.zip"

rm -rf "$STAGE" "$ZIP"
mkdir -p "$STAGE/src" "$STAGE/icons"

# top-level runtime files
cp manifest.json popup.html options.html "$STAGE/"

# runtime scripts (everything referenced by the manifest / the two HTML pages)
for f in patterns.generated.js patterns.extra.js engine.js pageguard.js \
         content.js background.js popup.js options.js yaml.js; do
  cp "src/$f" "$STAGE/src/"
done

# icons referenced by the manifest
cp icons/icon16.png icons/icon48.png icons/icon128.png "$STAGE/icons/"

( cd "$STAGE" && zip -rqX "../dlp-guard-$VERSION.zip" . )
rm -rf "$STAGE"

echo "Built $ZIP"
python3 - "$ZIP" <<'PY'
import sys, zipfile, os
z = sys.argv[1]
size = os.path.getsize(z)
with zipfile.ZipFile(z) as f:
    names = f.namelist()
print(f"  {len(names)} files, {size/1024:.0f} KB")
for n in sorted(names):
    print("   ", n)
PY
