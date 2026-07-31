"""Configuration loading with schema validation."""

from pathlib import Path

import yaml
from pydantic import BaseModel, Field

from .models import AgentDefinition


class ControlConfig(BaseModel):
    agents: list[AgentDefinition] = Field(min_length=1)


def load_control_config(path: Path) -> ControlConfig:
    """Load endpoint control definitions from YAML."""

    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("control configuration must be a YAML mapping")
    return ControlConfig.model_validate(raw)
