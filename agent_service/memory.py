from __future__ import annotations

import sqlite3
from pathlib import Path


class VisibleConversationStore:
    """Stores only user-visible messages.

    Internal tool calls/results stay in mode-specific OpenAI Agents SDK sessions and
    are never copied into this cross-mode transcript.
    """

    def __init__(self, db_path: str):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS visible_messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    conversation_id TEXT NOT NULL,
                    role TEXT NOT NULL CHECK(role IN ('user', 'assistant')),
                    mode TEXT NOT NULL,
                    content TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_visible_messages_conversation ON visible_messages(conversation_id, id)"
            )

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path, timeout=5)

    def recent(self, conversation_id: str, limit: int = 12) -> list[dict[str, str]]:
        safe_limit = max(1, min(limit, 30))
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT role, mode, content
                FROM visible_messages
                WHERE conversation_id = ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (conversation_id, safe_limit),
            ).fetchall()
        rows.reverse()
        return [{"role": role, "mode": mode, "content": content} for role, mode, content in rows]

    def append_exchange(self, conversation_id: str, mode: str, user_message: str, assistant_message: str) -> None:
        with self._connect() as conn:
            conn.executemany(
                "INSERT INTO visible_messages(conversation_id, role, mode, content) VALUES (?, ?, ?, ?)",
                [
                    (conversation_id, "user", mode, user_message),
                    (conversation_id, "assistant", mode, assistant_message),
                ],
            )
