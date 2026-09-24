"""Import boundary assertions shared by scenario acceptance checks.

Demo role: inspect production imports without granting agent capabilities.
Gemini action it addresses: #1–3, keeping execution authority outside agent/.
Must never import: World or CROA implementations; inspect source text only.
"""

import ast
from pathlib import Path


def assert_import_boundaries() -> None:
    """Keep infrastructure out of agent imports and restrict production World access."""
    root = Path(__file__).resolve().parents[1]
    files = list(root.glob("*.py"))
    for package in ("agent", "world", "croa"):
        files.extend((root / package).rglob("*.py"))
    for path in files:
        relative = path.relative_to(root).as_posix()
        for node in ast.walk(ast.parse(path.read_text())):
            imports: list[str] = []
            if isinstance(node, ast.Import):
                imports = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                if node.level:
                    package = path.relative_to(root).parts[:-node.level]
                    module = ".".join((*package, module)).strip(".")
                imports = [module, *(f"{module}.{alias.name}" for alias in node.names)]
            for module in imports:
                if relative.startswith("agent/"):
                    forbidden = (
                        "world", "runtime", "croa.c6_firewall", "croa.c7_compiler",
                    )
                    assert not any(module == item or module.startswith(item + ".")
                                   for item in forbidden), (relative, module)
                if module == "world" or module.startswith("world."):
                    assert relative in ("runtime.py", "croa/c6_firewall.py"), relative
                if relative.startswith("world/"):
                    assert not module.startswith("agent"), (relative, module)
                    assert not module.startswith("croa.") or module.startswith(
                        "croa.reasons"
                    ), (relative, module)
