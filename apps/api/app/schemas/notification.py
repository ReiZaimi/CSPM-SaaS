from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from app.core.enums import NotificationKind


class NotificationOut(BaseModel):
    """One thing worth telling somebody, as it was true when it happened.

    ``title`` and ``detail`` are stored rather than composed at render. A
    sentence assembled now from a finding that has since been fixed would
    describe a state nobody was ever notified about.
    """

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    kind: NotificationKind
    title: str
    detail: str | None = None
    #: A path for the client to route to, never an absolute URL.
    link: str | None = None
    #: When it happened, which is not when the row was written.
    event_at: datetime
