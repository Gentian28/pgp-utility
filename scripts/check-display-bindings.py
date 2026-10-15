"""Reject writable inline display bindings before they can corrupt their source or recurse."""
import argparse
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1] / "src/PgpUtility.App")
arguments = parser.parse_args()
if not arguments.root.is_dir():
    parser.error("The XAML source directory does not exist.")

failures = []
checked = 0
for path in sorted(arguments.root.rglob("*.axaml")):
    for inline in ET.parse(path).iter("{https://github.com/avaloniaui}Run"):
        expression = inline.get("Text", "").strip()
        if not re.match(r"\{(?:Binding|CompiledBinding|ReflectionBinding)\b", expression):
            continue
        checked += 1
        # Run.Text defaults to TwoWay. A StringFormat can therefore repeatedly write its
        # formatted value into the source and overflow the stack when a key menu opens.
        if not re.search(r"\bMode\s*=\s*(?:OneWay|OneTime)\b", expression):
            failures.append(f"{path}: Run.Text display binding must explicitly use Mode=OneWay or Mode=OneTime.")
if failures:
    print("\n".join(failures), file=sys.stderr)
    sys.exit(1)
print(f"Checked {checked} inline display bindings: no source writeback.")
