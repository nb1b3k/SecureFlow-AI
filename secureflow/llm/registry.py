"""Versioned prompt registry.

Prompts live as YAML files under `secureflow/llm/prompts/<agent>/<version>.yaml`
so they can be reviewed and version-bumped independently of code changes.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import yaml


@dataclass(frozen=True)
class PromptSpec:
    """A loaded prompt template."""

    agent: str
    version: str
    description: str
    system: str
    user_template: str

    @property
    def prompt_version(self) -> str:
        """Versioned identifier persisted on findings: e.g. `ai_discovery@v1`."""
        return f"{self.agent}@{self.version}"

    def render_user(self, **kwargs: str) -> str:
        """Render the user template by str.format substitution."""
        return self.user_template.format(**kwargs)


class PromptRegistry:
    """Loads versioned prompt YAMLs from the package's `prompts/` tree."""

    def __init__(self, root: Path | None = None) -> None:
        if root is None:
            # The prompts/ subpackage ships YAML data files alongside its
            # __init__.py. Resolve the directory via the package's module
            # path — works for both source checkouts and installed wheels.
            try:
                import secureflow.llm.prompts as _prompts_pkg

                init_path = getattr(_prompts_pkg, "__file__", None)
                if init_path:
                    root = Path(init_path).parent
                else:
                    # Namespace package; pick the first __path__ entry.
                    root = Path(next(iter(_prompts_pkg.__path__)))
            except ImportError:
                root = Path(__file__).parent / "prompts"
        self.root = root

    def get(self, agent: str, version: str = "v1") -> PromptSpec:
        """Load the requested prompt or raise FileNotFoundError."""
        path = self.root / agent / f"{version}.yaml"
        if not path.exists():
            raise FileNotFoundError(
                f"Prompt not found: agent={agent} version={version} (looked in {path})"
            )
        with path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        return PromptSpec(
            agent=agent,
            version=version,
            description=data.get("description", ""),
            system=data["system"],
            user_template=data["user_template"],
        )

    def iter_all(self) -> Iterator[PromptSpec]:
        """Yield every prompt in the registry."""
        if not self.root.exists():
            return
        for agent_dir in sorted(self.root.iterdir()):
            if not agent_dir.is_dir():
                continue
            for version_file in sorted(agent_dir.glob("*.yaml")):
                version = version_file.stem
                yield self.get(agent_dir.name, version)
