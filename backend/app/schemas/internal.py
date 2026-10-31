from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from .common import KillChainStage


class RawEvent(BaseModel):
    source_id: str = Field(description="ID in the log source.")
    timestamp: datetime = Field(description="When it happened (timezone.utc).")
    host: str = Field(description="Machine.")
    source: str = Field(description="Log source name (auditd, jsonlines, syslog, csv).")
    payload: dict[str, Any] = Field(description="Decoded dictionary returned by source parser.")
    raw_log: str = Field(description="The original log text line.")
    source_file: str | None = Field(default=None, description="Path of source file.")
    byte_offset: int | None = Field(default=None, description="Offset position in file.")
    byte_length: int | None = Field(default=None, description="Length of line in bytes.")


class LlmResult(BaseModel):
    parsed: Any = Field(description="The response parsed into requested Pydantic model.")
    model_name: str = Field(description="The model that answered.")
    input_tokens: int = Field(default=0, description="Prompt tokens.")
    output_tokens: int = Field(default=0, description="Output tokens.")


class TechniqueRule(BaseModel):
    technique_id: str = Field(description="ATT&CK ID.")
    name: str = Field(description="Technique name.")
    tactic: str = Field(description="ATT&CK tactic.")
    kill_chain_stage: KillChainStage = Field(default=KillChainStage.EXECUTION, description="Cyber Kill Chain stage.")
    command_patterns: list[str] = Field(default_factory=list, description="Regexes matching command lines.")
    path_patterns: list[str] = Field(default_factory=list, description="Regexes matching file paths.")
    process_names: list[str] = Field(default_factory=list, description="Process names indicating technique.")


class DetectionRuleConfig(BaseModel):
    rule_id: str = Field(description="Unique rule ID (e.g. sigma_01).")
    name: str = Field(description="Rule name.")
    description: str = Field(description="What attack activity is detected.")
    technique_id: str = Field(description="ATT&CK ID.")
    kill_chain_stage: KillChainStage = Field(description="Mapped Kill Chain stage.")
    severity: str = Field(default="medium", description="Severity: low, medium, high, critical.")
    conditions: dict[str, Any] = Field(default_factory=dict, description="Rule conditions or threshold logic.")
