#!/usr/bin/env bash
# Check out the system under test at the commit pinned in config/sut.yaml and install it (editable,
# because the package reads its config/, detections/ and data/ folders from the source tree).
#   scripts/fetch_sut.sh            clone or update .sut/azure-ai-soc and pip install -e it
set -euo pipefail
cd "$(dirname "$0")/.."
repo=$(awk '/^ *repo:/ {print $2; exit}' config/sut.yaml)
commit=$(awk '/^ *commit:/ {print $2; exit}' config/sut.yaml)
dest=.sut/azure-ai-soc
if [[ ! -d "$dest/.git" ]]; then
  git clone --quiet "$repo" "$dest"
fi
git -C "$dest" fetch --quiet origin "$commit" 2>/dev/null || git -C "$dest" fetch --quiet origin
git -C "$dest" checkout --quiet "$commit"
echo "system under test: $(git -C "$dest" rev-parse HEAD)"
pip install --quiet -e "$dest"
