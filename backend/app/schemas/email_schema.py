from typing import Any

from pydantic import BaseModel, Field


class IngestionResponse(BaseModel):
    success: bool
    email_id: str
    case_id: str
    filename: str
    sha256: str
    status: str
    message: str


class EmailSummaryResponse(BaseModel):
    email_id: str
    case_id: str
    filename: str
    sha256: str

    sender: dict[str, Any] | None = None

    recipients: list[str] = Field(
        default_factory=list
    )

    subject: str | None = None

    timestamp: Any = None

    message_id: str | None = None

    status: str

    created_at: Any

    module: dict[str, Any] = Field(
        default_factory=dict
    )