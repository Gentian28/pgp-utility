"""Reject unsafe display bindings and passphrase controls before desktop acceptance."""
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
passphrases = 0
for path in sorted(arguments.root.rglob("*.axaml")):
    for inline in ET.parse(path).iter():
        if inline.get("PasswordChar") is not None:
            passphrases += 1
            if inline.tag != "{using:PgpUtility.App.Controls}PassphraseTextBox":
                failures.append(f"{path}: masked passphrases must use PassphraseTextBox to keep plaintext out of accessibility values and events.")
        if inline.tag != "{https://github.com/avaloniaui}Run":
            continue
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
print(f"Checked {checked} inline display bindings and {passphrases} protected passphrase controls.")
