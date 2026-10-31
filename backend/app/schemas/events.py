from datetime import datetime

from pydantic import BaseModel, Field

from .common import EventCategory, KillChainStage


class NormalizedEvent(BaseModel):
    event_id: str = Field(description="ID from log source or generated hash. Cited by stories.")
    timestamp: datetime = Field(description="When the event happened (timezone.utc).")
    host: str = Field(description="Machine the event came from.")
    source: str = Field(description="Log source, for example auditd, syslog, winlog.")
    category: EventCategory = Field(description="Kind of event.")
    user: str | None = Field(default=None, description="User account involved.")
    pid: int | None = Field(default=None, description="Process ID.")
    ppid: int | None = Field(default=None, description="Parent process ID. Used to build process tree.")
    process_name: str | None = Field(default=None, description="Short process name.")
    executable: str | None = Field(default=None, description="Full path of the program.")
    command_line: str | None = Field(default=None, description="Full command line, when logged.")
    file_path: str | None = Field(default=None, description="File touched, when relevant.")
    remote_address: str | None = Field(default=None, description="Remote IP for network events.")
    remote_port: int | None = Field(default=None, description="Remote port for network events.")
    wazuh_rule_id: int | None = Field(default=None, description="Rule ID that matched, if any.")
    wazuh_rule_level: int | None = Field(default=None, description="Level of rule, 0 to 15.")
    mitre_ids: list[str] = Field(default_factory=list, description="MITRE technique IDs. Empty if none.")
    kill_chain_stage: KillChainStage | None = Field(default=None, description="Cyber Kill Chain stage.")
    is_noise: bool = Field(default=False, description="True if marked benign.")
    noise_reason: str | None = Field(default=None, description="Why it was marked as noise.")
    group_id: str | None = Field(default=None, description="Activity group it belongs to. Null for unassigned.")
    summary: str = Field(description="One readable line built by the normalizer. This is what the LLM sees.")
    raw_log: str | None = Field(default=None, description="The original log line, loaded lazily from offset.")

    # v2 Big-Log index fields
    source_file: str | None = Field(default=None, description="File path on disk where raw line exists.")
    byte_offset: int | None = Field(default=None, description="Byte position in source file for O(1) lookup.")
    byte_length: int | None = Field(default=None, description="Byte length of raw line.")
    rarity_score: float | None = Field(default=None, description="Mathematical rarity score calculated by reducer.")
    is_seed: bool = Field(default=False, description="True if event was chosen as top-K attack seed.")

    # Anti-Evasion & De-Masking Fields
    is_evasion: bool = Field(default=False, description="True if adversary evasion/obfuscation was unmasked.")
    evasion_notes: list[str] = Field(default_factory=list, description="Forensic notes detailing unmasked evasion.")
    decoded_payload: str | None = Field(default=None, description="De-obfuscated or decoded command/payload.")


class EventList(BaseModel):
    items: list[NormalizedEvent] = Field(description="Events in time order.")
    total: int = Field(description="Total events matching filters.")
    offset: int = Field(description="Offset used.")
    limit: int = Field(description="Limit used.")


class ActivityGroup(BaseModel):
    group_id: str = Field(description="Group ID, unique within the case.")
    host: str = Field(description="Primary machine the group is on.")
    first_seen: datetime = Field(description="Time of its earliest event.")
    last_seen: datetime = Field(description="Time of its latest event.")
    event_count: int = Field(description="Number of events in group.")
    root_process: str | None = Field(default=None, description="Process at the top of its process tree.")
    top_event_ids: list[str] = Field(description="First 10 event IDs for preview.")
    candidate_technique_ids: list[str] = Field(description="Techniques suggested by stage mapper.")


class GroupList(BaseModel):
    items: list[ActivityGroup] = Field(description="Groups in time order.")
    total: int = Field(description="Number of groups.")
