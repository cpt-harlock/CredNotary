#!/bin/sh
# Builds docs/design.pdf from docs/design.md: the Mermaid diagrams are rendered
# to SVG with mermaid-cli, the Markdown is converted to HTML with marked, and
# headless Chrome (puppeteer) prints the PDF.
#   scripts/design-pdf.sh            (or: make docs)
# Needs node and npm; the first run downloads the tools into build/docs-tools.
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
TOOLS=$ROOT/build/docs-tools
WORK=$ROOT/build/docs

mkdir -p "$TOOLS" "$WORK"
cp "$ROOT/scripts/docs/package.json" "$ROOT/scripts/docs/md2pdf.mjs" "$TOOLS/"
if [ ! -d "$TOOLS/node_modules/@mermaid-js/mermaid-cli" ] || [ ! -d "$TOOLS/node_modules/marked" ]; then
	(cd "$TOOLS" && npm install --no-audit --no-fund)
fi
# puppeteer's browser download is a postinstall script that npm may skip
(cd "$TOOLS" && npx puppeteer browsers install chrome-headless-shell >/dev/null)

echo '{"args":["--no-sandbox"]}' > "$TOOLS/puppeteer.json"
rm -f "$WORK"/design*.svg "$WORK/design.md"
cp "$ROOT/docs/design.md" "$WORK/src.md"
(cd "$TOOLS" && npx mmdc -q -p puppeteer.json -b white -e svg -i "$WORK/src.md" -o "$WORK/design.md")
(cd "$TOOLS" && node md2pdf.mjs "$WORK" "$ROOT/docs/design.pdf")
