# Biniam Demissie
# Standalone integrity gate for the vendored Mermaid bundle. Verifies
# every file listed in webui/static/vendor/mermaid/manifest.json against its recorded
# SHA-256 and byte length.
import hashlib
import json
import pathlib
import sys

BASE = pathlib.Path(__file__).resolve().parent / "static" / "vendor" / "mermaid"


def main() -> int:
    manifest_path = BASE / "manifest.json"
    if not manifest_path.exists():
        print(f"vendored Mermaid manifest missing: {manifest_path}", file=sys.stderr)
        return 1
    manifest = json.loads(manifest_path.read_text())
    if manifest.get("algorithm") != "sha256":
        print(f"unexpected manifest algorithm: {manifest.get('algorithm')}", file=sys.stderr)
        return 1
    files = manifest.get("files", {})
    if not files:
        print("manifest lists no files", file=sys.stderr)
        return 1
    for name, meta in files.items():
        path = BASE / name
        if not path.exists():
            print(f"vendored file missing: {name}", file=sys.stderr)
            return 1
        data = path.read_bytes()
        if len(data) != meta.get("bytes"):
            print(f"size mismatch for {name}", file=sys.stderr)
            return 1
        if hashlib.sha256(data).hexdigest() != meta.get("sha256"):
            print(f"sha256 mismatch for {name}", file=sys.stderr)
            return 1
    print(
        f"vendored Mermaid {manifest.get('version')} integrity OK "
        f"({len(files)} files)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
