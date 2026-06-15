from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, model_validator


class ActionType(str, Enum):
    CONNECT = "connect"
    SQL = "sql"
    VERIFY = "verify"
    SET_ROLE = "set_role"
    FINAL_REPORT = "final_report"
    STOP = "stop"
    ASK_HUMAN = "ask_human"


class AgentAction(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    action_type: ActionType
    reason: str = Field(min_length=1, max_length=2000)
    sql: str | None = Field(default=None, max_length=10000)
    expected_result: str | None = Field(default=None, max_length=2000)
    safety_notes: str | None = Field(default=None, max_length=2000)
    verification_sql: str | None = Field(default=None, max_length=10000)
    next_goal: str | None = Field(default=None, max_length=2000)
    username: str | None = Field(default=None, max_length=128)
    password: str | None = Field(default=None, max_length=512)

    @model_validator(mode="after")
    def validate_action_payload(self) -> "AgentAction":
        if self.action_type in {ActionType.SQL, ActionType.VERIFY, ActionType.SET_ROLE} and not self.sql:
            raise ValueError(f"sql is required for action_type={self.action_type.value}")
        if self.action_type == ActionType.SET_ROLE and not self.sql.upper().startswith("SET ROLE "):
            raise ValueError("set_role action must contain SET ROLE SQL")
        return self


ACTION_JSON_SCHEMA = AgentAction.model_json_schema()
