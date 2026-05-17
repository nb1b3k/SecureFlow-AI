"""PR context — what was changed, where, and what code surrounds it."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class FunctionBoundary(BaseModel):
    """An enclosing function or class around a span of lines."""

    model_config = ConfigDict(extra="ignore")

    file: str
    symbol: str
    start_line: int
    end_line: int
    language: str


class ChangedLineRange(BaseModel):
    """A contiguous range of lines changed in a file."""

    model_config = ConfigDict(extra="ignore")

    file: str
    start: int
    end: int


class PRContext(BaseModel):
    """Everything downstream agents need to know about the PR."""

    model_config = ConfigDict(extra="ignore")

    repo_path: str
    repo_name: str | None = None
    pr_number: int | None = None
    base_branch: str | None = None
    head_branch: str | None = None

    changed_files: list[str] = Field(default_factory=list)
    changed_line_ranges: list[ChangedLineRange] = Field(default_factory=list)
    function_boundaries: list[FunctionBoundary] = Field(default_factory=list)

    diff: str = ""
    language_summary: dict[str, int] = Field(default_factory=dict)

    sensitive_files_changed: bool = False
    sensitive_signals: list[str] = Field(default_factory=list)
