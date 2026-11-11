"""Create a clean distributable source ZIP without local secrets or build caches."""
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

ROOT = Path(__file__).resolve().parents[1]
DESTINATION = ROOT.parent / "SkyGuard-project.zip"
EXCLUDED_DIRS = {
    ".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache",
    ".mypy_cache", ".ruff_cache", ".pytest-tmp", "dist", "build", "coverage",
}
EXCLUDED_SUFFIXES = {".pyc", ".db", ".sqlite", ".sqlite3"}


def include(path: Path) -> bool:
    relative = path.relative_to(ROOT)
    if any(part in EXCLUDED_DIRS for part in relative.parts):
        return False
    if path.suffix.lower() in EXCLUDED_SUFFIXES or path.name.endswith(".zip"):
        return False
    if path.name.lower() == ".env":
        return relative.as_posix() == "examples/demo-project/.env"
    if path.name.lower().startswith(".env."):
        return path.name.lower() == ".env.example"
    return path.is_file()


def main() -> None:
    files = sorted(path for path in ROOT.rglob("*") if path.is_file() and include(path))
    with ZipFile(DESTINATION, "w", ZIP_DEFLATED) as archive:
        for path in files:
            archive.write(path, Path(ROOT.name) / path.relative_to(ROOT))
    print(f"Created {DESTINATION} ({len(files)} files)")


if __name__ == "__main__":
    main()
