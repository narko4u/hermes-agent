#!/usr/bin/env python3
"""
Memory Tool Module - Persistent Curated Memory (Sovereign Tiered Edition)

Provides bounded, file-backed memory that persists across sessions. Two stores:
  - MEMORY.md: agent's personal notes and observations (environment facts, project
    conventions, tool quirks, things learned)
  - USER.md: what the agent knows about the user (preferences, communication style,
    expectations, workflow habits)

TIERED STORAGE (Sovereign patch v1):
  - HOT tier: MEMORY.md / USER.md (flat files, char-limited, in system prompt)
  - WARM tier: Sovereign Vault (SQLite, unlimited, available on request)
  When HOT tier reaches its char limit, oldest entries automatically overflow to
  WARM tier. The system prompt shows both tiers' usage.
"""

import json
import logging
import os
import sys
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from hermes_constants import get_hermes_home
from typing import Dict, Any, List, Optional

from utils import atomic_replace

# fcntl is Unix-only; on Windows use msvcrt for file locking
msvcrt = None
try:
    import fcntl
except ImportError:
    fcntl = None
    try:
        import msvcrt
    except ImportError:
        pass

logger = logging.getLogger(__name__)


def get_memory_dir() -> Path:
    """Return the profile-scoped memories directory."""
    return get_hermes_home() / "memories"

ENTRY_DELIMITER = "\n§\n"


# ---------------------------------------------------------------------------
# Sovereign Vault warm-tier integration
# ---------------------------------------------------------------------------

_VAULT_IMPORTED = False
_set_value = None
_get_value = None
_list_section = None
_delete_key = None

def _import_vault():
    """Lazy-import the Sovereign Vault module. Fails silently if not available."""
    global _VAULT_IMPORTED, _set_value, _get_value, _list_section, _delete_key
    if _VAULT_IMPORTED:
        return True
    try:
        vault_path = "/mnt/c/VaultSentinel/Sovereign"
        vault_file = os.path.join(vault_path, "sovereign_vault.py")
        if os.path.isfile(vault_file):
            if vault_path not in sys.path:
                sys.path.insert(0, vault_path)
            import sovereign_vault
            _set_value = sovereign_vault.set_value
            _get_value = sovereign_vault.get_value
            _list_section = sovereign_vault.list_section
            _delete_key = sovereign_vault.delete_key
            _VAULT_IMPORTED = True
            return True
    except Exception:
        pass
    return False


def _warm_count(target: str) -> int:
    """Return number of warm-tier entries for a target (memory or user)."""
    if not _import_vault():
        return 0
    try:
        prefix = f"memory_warm_" if target == "memory" else f"user_warm_"
        results = _list_section(target)
        if isinstance(results, list):
            return len([r for r in results if r.get("key", "").startswith(prefix)])
    except Exception:
        pass
    return 0


def _warm_entries_list(target: str) -> List[Dict[str, str]]:
    """Return list of {key, value} dicts from the warm tier."""
    if not _import_vault():
        return []
    try:
        prefix = f"memory_warm_" if target == "memory" else f"user_warm_"
        results = _list_section(target)
        if isinstance(results, list):
            entries = []
            for r in results:
                key = r.get("key", "")
                if key.startswith(prefix):
                    # Need to fetch full value — list_section only returns preview (100 chars)
                    val = _get_value(target, key)
                    entries.append({"key": key, "value": val if val else ""})
            return entries
    except Exception:
        pass
    return []


def _warm_get(target: str, key: str) -> Optional[str]:
    """Get a specific warm-tier entry by key suffix."""
    if not _import_vault():
        return None
    try:
        full_key = f"memory_warm_{key}" if target == "memory" else f"user_warm_{key}"
        result = _get_value(target, full_key)
        if result is not None:
            return str(result)
    except Exception:
        pass
    return None


def _warm_set(target: str, key: str, content: str) -> bool:
    """Store an entry in the warm tier."""
    if not _import_vault():
        return False
    try:
        full_key = f"memory_warm_{key}" if target == "memory" else f"user_warm_{key}"
        _set_value(target, full_key, content, expires_in="90d")
        return True
    except Exception:
        return False


def _warm_remove(target: str, key: str) -> bool:
    """Remove a warm-tier entry via raw SQLite."""
    if not _import_vault():
        return False
    try:
        full_key = f"memory_warm_{key}" if target == "memory" else f"user_warm_{key}"
        _delete_key(target, full_key)
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Threat scanning (unchanged from upstream)
# ---------------------------------------------------------------------------

from tools.threat_patterns import first_threat_message as _first_threat_message


def _scan_memory_content(content: str) -> Optional[str]:
    """Scan memory content for injection/exfil patterns. Returns error string if blocked."""
    return _first_threat_message(content, scope="strict")


def _drift_error(path: "Path", bak_path: str) -> Dict[str, Any]:
    """Build the error dict returned when external drift is detected."""
    return {
        "success": False,
        "error": (
            f"Refusing to write {path.name}: file on disk has content that "
            f"wouldn't round-trip through the memory tool (likely added by "
            f"the patch tool, a shell append, a manual edit, or a "
            f"concurrent session). A snapshot was saved to {bak_path}. "
            f"Resolve the drift first — either rewrite the file as a clean "
            f"§-delimited list of entries, or move the extra content out — "
            f"then retry. This guard exists to prevent silent data loss "
            f"(issue #26045)."
        ),
        "drift_backup": bak_path,
        "remediation": (
            "Open the .bak file, integrate the missing entries into the "
            "memory tool one at a time via memory(action=add, content=...), "
            "then remove or rewrite the original file to a clean state."
        ),
    }


class MemoryStore:
    """
    Bounded curated memory with file persistence and Sovereign warm-tier overflow.

    Two tiers:
      - HOT: MEMORY.md / USER.md flat files (char-limited, in system prompt)
      - WARM: Sovereign Vault SQLite (unlimited, available on request via read_warm)

    When HOT tier reaches char_limit, oldest entries automatically overflow to
    WARM tier. The system prompt header shows both tiers' status.
    """

    def __init__(self, memory_char_limit: int = 2200, user_char_limit: int = 1375):
        self.memory_entries: List[str] = []
        self.user_entries: List[str] = []
        self.memory_char_limit = memory_char_limit
        self.user_char_limit = user_char_limit
        # Frozen snapshot for system prompt -- set once at load_from_disk()
        self._system_prompt_snapshot: Dict[str, str] = {"memory": "", "user": ""}

    def load_from_disk(self):
        """Load entries from MEMORY.md and USER.md, capture system prompt snapshot."""
        mem_dir = get_memory_dir()
        mem_dir.mkdir(parents=True, exist_ok=True)

        self.memory_entries = self._read_file(mem_dir / "MEMORY.md")
        self.user_entries = self._read_file(mem_dir / "USER.md")

        # Deduplicate entries (preserves order, keeps first occurrence)
        self.memory_entries = list(dict.fromkeys(self.memory_entries))
        self.user_entries = list(dict.fromkeys(self.user_entries))

        # Sanitize entries for the system-prompt snapshot only.
        sanitized_memory = self._sanitize_entries_for_snapshot(self.memory_entries, "MEMORY.md")
        sanitized_user = self._sanitize_entries_for_snapshot(self.user_entries, "USER.md")

        # Capture frozen snapshot for system prompt injection
        self._system_prompt_snapshot = {
            "memory": self._render_block("memory", sanitized_memory),
            "user": self._render_block("user", sanitized_user),
        }

    @staticmethod
    def _sanitize_entries_for_snapshot(entries: List[str], filename: str) -> List[str]:
        """Return ``entries`` with any threat-matching entry replaced by a placeholder."""
        from tools.threat_patterns import scan_for_threats

        sanitized: List[str] = []
        for entry in entries:
            if not entry or entry.startswith("[BLOCKED:"):
                sanitized.append(entry)
                continue
            findings = scan_for_threats(entry, scope="strict")
            if findings:
                logger.warning(
                    "Memory entry from %s blocked at load time: %s",
                    filename, ", ".join(findings),
                )
                sanitized.append(
                    f"[BLOCKED: {filename} entry contained threat pattern(s): "
                    f"{', '.join(findings)}. Removed from system prompt; "
                    f"use memory(action=read) to inspect and memory(action=remove) "
                    f"to delete the original.]"
                )
            else:
                sanitized.append(entry)
        return sanitized

    @staticmethod
    @contextmanager
    def _file_lock(path: Path):
        """Acquire an exclusive file lock for read-modify-write safety."""
        lock_path = path.with_suffix(path.suffix + ".lock")
        lock_path.parent.mkdir(parents=True, exist_ok=True)

        if fcntl is None and msvcrt is None:
            yield
            return

        fd = open(lock_path, "a+", encoding="utf-8")
        try:
            if fcntl:
                fcntl.flock(fd, fcntl.LOCK_EX)
            else:
                fd.seek(0)
                msvcrt.locking(fd.fileno(), msvcrt.LK_LOCK, 1)
            yield
        finally:
            if fcntl:
                try:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                except (OSError, IOError):
                    pass
            elif msvcrt:
                try:
                    fd.seek(0)
                    msvcrt.locking(fd.fileno(), msvcrt.LK_UNLCK, 1)
                except (OSError, IOError):
                    pass
            fd.close()

    @staticmethod
    def _path_for(target: str) -> Path:
        mem_dir = get_memory_dir()
        if target == "user":
            return mem_dir / "USER.md"
        return mem_dir / "MEMORY.md"

    def _reload_target(self, target: str) -> Optional[str]:
        """Re-read entries from disk into in-memory state."""
        path = self._path_for(target)
        bak = self._detect_external_drift(target)
        fresh = self._read_file(path)
        fresh = list(dict.fromkeys(fresh))  # deduplicate
        self._set_entries(target, fresh)
        return bak

    def save_to_disk(self, target: str):
        """Persist entries to the appropriate file. Called after every mutation."""
        get_memory_dir().mkdir(parents=True, exist_ok=True)
        self._write_file(self._path_for(target), self._entries_for(target))

    def _entries_for(self, target: str) -> List[str]:
        if target == "user":
            return self.user_entries
        return self.memory_entries

    def _set_entries(self, target: str, entries: List[str]):
        if target == "user":
            self.user_entries = entries
        else:
            self.memory_entries = entries

    def _char_count(self, target: str) -> int:
        entries = self._entries_for(target)
        if not entries:
            return 0
        return len(ENTRY_DELIMITER.join(entries))

    def _char_limit(self, target: str) -> int:
        if target == "user":
            return self.user_char_limit
        return self.memory_char_limit

    def add(self, target: str, content: str) -> Dict[str, Any]:
        """Append a new entry. Overflow to warm tier if hot tier is full."""
        content = content.strip()
        if not content:
            return {"success": False, "error": "Content cannot be empty."}

        # Scan for injection/exfiltration before accepting
        scan_error = _scan_memory_content(content)
        if scan_error:
            return {"success": False, "error": scan_error}

        with self._file_lock(self._path_for(target)):
            bak = self._reload_target(target)
            if bak:
                return _drift_error(self._path_for(target), bak)

            entries = self._entries_for(target)
            limit = self._char_limit(target)

            # Reject exact duplicates
            if content in entries:
                return self._success_response(target, "Entry already exists (no duplicate added).")

            # Calculate what the new total would be
            new_entries = entries + [content]
            new_total = len(ENTRY_DELIMITER.join(new_entries))

            if new_total > limit:
                # --- Sovereign tiered overflow ---
                # Move oldest entries to warm tier until the new entry fits
                overflow_count = 0
                while new_total > limit and len(entries) > 0:
                    oldest = entries.pop(0)
                    # Try to store in warm tier
                    if _warm_set(target, f"auto_{int(time.time())}_{overflow_count}", oldest):
                        overflow_count += 1
                    else:
                        # Vault not available — put it back and reject
                        entries.insert(0, oldest)
                        return {
                            "success": False,
                            "error": (
                                f"Memory at capacity and warm tier unavailable. "
                                f"Remove entries or configure Sovereign Vault."
                            ),
                            "current_entries": entries,
                            "usage": f"{self._char_count(target):,}/{limit:,}",
                        }
                    new_entries = entries + [content]
                    new_total = len(ENTRY_DELIMITER.join(new_entries))

                entries.append(content)
                self._set_entries(target, entries)
                self.save_to_disk(target)

                response = self._success_response(
                    target,
                    f"Entry added. {overflow_count} old entr{'y' if overflow_count == 1 else 'ies'} overflowed to warm tier."
                )
                response["warm_overflow"] = overflow_count
                return response

            entries.append(content)
            self._set_entries(target, entries)
            self.save_to_disk(target)

        return self._success_response(target, "Entry added.")

    def replace(self, target: str, old_text: str, new_content: str) -> Dict[str, Any]:
        """Find entry containing old_text substring, replace it with new_content."""
        old_text = old_text.strip()
        new_content = new_content.strip()
        if not old_text:
            return {"success": False, "error": "old_text cannot be empty."}
        if not new_content:
            return {"success": False, "error": "new_content cannot be empty. Use 'remove' to delete entries."}

        scan_error = _scan_memory_content(new_content)
        if scan_error:
            return {"success": False, "error": scan_error}

        with self._file_lock(self._path_for(target)):
            bak = self._reload_target(target)
            if bak:
                return _drift_error(self._path_for(target), bak)

            entries = self._entries_for(target)
            matches = [(i, e) for i, e in enumerate(entries) if old_text in e]

            if not matches:
                return {"success": False, "error": f"No entry matched '{old_text}'."}

            if len(matches) > 1:
                unique_texts = {e for _, e in matches}
                if len(unique_texts) > 1:
                    previews = [e[:80] + ("..." if len(e) > 80 else "") for _, e in matches]
                    return {
                        "success": False,
                        "error": f"Multiple entries matched '{old_text}'. Be more specific.",
                        "matches": previews,
                    }

            idx = matches[0][0]
            limit = self._char_limit(target)

            test_entries = entries.copy()
            test_entries[idx] = new_content
            new_total = len(ENTRY_DELIMITER.join(test_entries))

            if new_total > limit:
                return {
                    "success": False,
                    "error": (
                        f"Replacement would put memory at {new_total:,}/{limit:,} chars. "
                        f"Shorten the new content or remove other entries first."
                    ),
                }

            entries[idx] = new_content
            self._set_entries(target, entries)
            self.save_to_disk(target)

        return self._success_response(target, "Entry replaced.")

    def remove(self, target: str, old_text: str) -> Dict[str, Any]:
        """Remove the entry containing old_text substring."""
        old_text = old_text.strip()
        if not old_text:
            return {"success": False, "error": "old_text cannot be empty."}

        with self._file_lock(self._path_for(target)):
            bak = self._reload_target(target)
            if bak:
                return _drift_error(self._path_for(target), bak)

            entries = self._entries_for(target)
            matches = [(i, e) for i, e in enumerate(entries) if old_text in e]

            if not matches:
                return {"success": False, "error": f"No entry matched '{old_text}'."}

            if len(matches) > 1:
                unique_texts = {e for _, e in matches}
                if len(unique_texts) > 1:
                    previews = [e[:80] + ("..." if len(e) > 80 else "") for _, e in matches]
                    return {
                        "success": False,
                        "error": f"Multiple entries matched '{old_text}'. Be more specific.",
                        "matches": previews,
                    }

            idx = matches[0][0]
            entries.pop(idx)
            self._set_entries(target, entries)
            self.save_to_disk(target)

        return self._success_response(target, "Entry removed.")

    def read_warm(self, target: str, query: str = "") -> Dict[str, Any]:
        """Read entries from the warm tier (Sovereign Vault)."""
        entries = _warm_entries_list(target)
        if query:
            query_lower = query.lower()
            entries = [e for e in entries if query_lower in e["value"].lower()]
        return {
            "success": True,
            "target": target,
            "tier": "warm",
            "entries": entries,
            "entry_count": len(entries),
            "vault_available": _VAULT_IMPORTED,
        }

    def warm_to_hot(self, target: str, key: str) -> Dict[str, Any]:
        """Recall a warm-tier entry back into hot tier. Key is the warm entry's key suffix."""
        content = _warm_get(target, key)
        if content is None:
            return {"success": False, "error": f"No warm entry found with key '{key}'."}

        # Remove from warm tier
        _warm_remove(target, key)

        # Add to hot tier
        with self._file_lock(self._path_for(target)):
            bak = self._reload_target(target)
            if bak:
                return _drift_error(self._path_for(target), bak)

            entries = self._entries_for(target)
            limit = self._char_limit(target)

            # Overflow if needed
            new_entries = entries + [content]
            new_total = len(ENTRY_DELIMITER.join(new_entries))
            overflow_count = 0
            while new_total > limit and len(entries) > 0:
                oldest = entries.pop(0)
                _warm_set(target, f"auto_{int(time.time())}_{overflow_count}", oldest)
                overflow_count += 1
                new_entries = entries + [content]
                new_total = len(ENTRY_DELIMITER.join(new_entries))

            entries.append(content)
            self._set_entries(target, entries)
            self.save_to_disk(target)

        return self._success_response(target, f"Entry recalled from warm tier. {overflow_count} overflowed to warm." if overflow_count else "Entry recalled from warm tier.")

    def format_for_system_prompt(self, target: str) -> Optional[str]:
        """
        Return the frozen snapshot for system prompt injection.
        """
        block = self._system_prompt_snapshot.get(target, "")
        return block if block else None

    # -- Internal helpers --

    def _success_response(self, target: str, message: str = None) -> Dict[str, Any]:
        entries = self._entries_for(target)
        current = self._char_count(target)
        limit = self._char_limit(target)
        pct = min(100, int((current / limit) * 100)) if limit > 0 else 0
        warm = _warm_count(target)

        resp = {
            "success": True,
            "target": target,
            "entries": entries,
            "usage": f"{pct}% — {current:,}/{limit:,} chars",
            "entry_count": len(entries),
            "warm_entries": warm,
        }
        if message:
            resp["message"] = message
        return resp

    def _render_block(self, target: str, entries: List[str]) -> str:
        """Render a system prompt block with header showing both hot and warm tier usage."""
        if not entries:
            # Still show header if warm tier has data
            warm = _warm_count(target)
            if warm == 0:
                return ""

            limit = self._char_limit(target)
            if target == "user":
                header = f"USER PROFILE (who the user is) [0% — 0/{limit:,} chars] [+{warm} warm entries]"
            else:
                header = f"MEMORY (your personal notes) [0% — 0/{limit:,} chars] [+{warm} warm entries]"
            separator = "═" * 46
            return f"{separator}\n{header}\n{separator}\n"

        limit = self._char_limit(target)
        content = ENTRY_DELIMITER.join(entries)
        current = len(content)
        pct = min(100, int((current / limit) * 100)) if limit > 0 else 0
        warm = _warm_count(target)

        if target == "user":
            header = f"USER PROFILE (who the user is) [{pct}% — {current:,}/{limit:,} chars]"
        else:
            header = f"MEMORY (your personal notes) [{pct}% — {current:,}/{limit:,} chars]"

        if warm > 0:
            header += f" [+{warm} warm — use memory(action='read_warm') to browse]"

        separator = "═" * 46
        return f"{separator}\n{header}\n{separator}\n{content}"

    @staticmethod
    def _read_file(path: Path) -> List[str]:
        """Read a memory file and split into entries."""
        if not path.exists():
            return []
        try:
            raw = path.read_text(encoding="utf-8")
        except (OSError, IOError):
            return []

        if not raw.strip():
            return []

        entries = [e.strip() for e in raw.split(ENTRY_DELIMITER)]
        return [e for e in entries if e]

    def _detect_external_drift(self, target: str) -> Optional[str]:
        """Return a backup-path string if on-disk content shows external drift."""
        path = self._path_for(target)
        if not path.exists():
            return None
        try:
            raw = path.read_text(encoding="utf-8")
        except (OSError, IOError):
            return None
        if not raw.strip():
            return None

        parsed = [e.strip() for e in raw.split(ENTRY_DELIMITER) if e.strip()]
        roundtrip = ENTRY_DELIMITER.join(parsed)

        char_limit = self._char_limit(target)
        max_entry_len = max((len(e) for e in parsed), default=0)

        drift_detected = (raw.strip() != roundtrip) or (max_entry_len > char_limit)
        if not drift_detected:
            return None

        ts = int(time.time())
        bak_path = path.with_suffix(path.suffix + f".bak.{ts}")
        try:
            bak_path.write_text(raw, encoding="utf-8")
        except (OSError, IOError):
            return str(bak_path) + " (BACKUP FAILED — file unchanged on disk)"
        return str(bak_path)

    @staticmethod
    def _write_file(path: Path, entries: List[str]):
        """Write entries to a memory file using atomic temp-file + rename."""
        content = ENTRY_DELIMITER.join(entries) if entries else ""
        try:
            fd, tmp_path = tempfile.mkstemp(
                dir=str(path.parent), suffix=".tmp", prefix=".mem_"
            )
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    f.write(content)
                    f.flush()
                    os.fsync(f.fileno())
                atomic_replace(tmp_path, path)
            except BaseException:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
                raise
        except (OSError, IOError) as e:
            raise RuntimeError(f"Failed to write memory file {path}: {e}")


def memory_tool(
    action: str,
    target: str = "memory",
    content: str = None,
    old_text: str = None,
    store: Optional[MemoryStore] = None,
) -> str:
    """
    Single entry point for the memory tool. Dispatches to MemoryStore methods.

    Supports actions: add, replace, remove, read_warm, warm_to_hot.

    Returns JSON string with results.
    """
    if store is None:
        return tool_error("Memory is not available. It may be disabled in config or this environment.", success=False)

    if target not in {"memory", "user"}:
        return tool_error(f"Invalid target '{target}'. Use 'memory' or 'user'.", success=False)

    if action == "add":
        if not content:
            return tool_error("Content is required for 'add' action.", success=False)
        result = store.add(target, content)

    elif action == "replace":
        if not old_text:
            return tool_error("old_text is required for 'replace' action.", success=False)
        if not content:
            return tool_error("content is required for 'replace' action.", success=False)
        result = store.replace(target, old_text, content)

    elif action == "remove":
        if not old_text:
            return tool_error("old_text is required for 'remove' action.", success=False)
        result = store.remove(target, old_text)

    elif action == "read":
        # Read current hot tier entries
        entries = store._entries_for(target)
        usage = store._char_count(target)
        limit = store._char_limit(target)
        warm = _warm_count(target)
        pct = min(100, int((usage / limit) * 100)) if limit > 0 else 0
        result = {
            "success": True,
            "target": target,
            "entries": entries,
            "usage": f"{pct}% — {usage:,}/{limit:,} chars",
            "entry_count": len(entries),
            "warm_entries": warm,
            "warm_available": _VAULT_IMPORTED,
        }

    elif action == "read_warm":
        query = content or ""
        result = store.read_warm(target, query)

    elif action == "warm_to_hot":
        if not old_text:
            return tool_error("old_text (warm entry key) is required for 'warm_to_hot' action.", success=False)
        result = store.warm_to_hot(target, old_text)

    else:
        return tool_error(f"Unknown action '{action}'. Use: add, replace, remove, read, read_warm, warm_to_hot", success=False)

    return json.dumps(result, ensure_ascii=False)


def check_memory_requirements() -> bool:
    """Memory tool has no external requirements -- always available."""
    return True


# =============================================================================
# OpenAI Function-Calling Schema
# =============================================================================

MEMORY_SCHEMA = {
    "name": "memory",
    "description": (
        "Save durable information to persistent memory that survives across sessions. "
        "Memory is injected into future turns, so keep it compact and focused on facts "
        "that will still matter later.\n\n"
        "WHEN TO SAVE (do this proactively, don't wait to be asked):\n"
        "- User corrects you or says 'remember this' / 'don't do that again'\n"
        "- User shares a preference, habit, or personal detail (name, role, timezone, coding style)\n"
        "- You discover something about the environment (OS, installed tools, project structure)\n"
        "- You learn a convention, API quirk, or workflow specific to this user's setup\n"
        "- You identify a stable fact that will be useful again in future sessions\n\n"
        "PRIORITY: User preferences and corrections > environment facts > procedural knowledge. "
        "The most valuable memory prevents the user from having to repeat themselves.\n\n"
        "Do NOT save task progress, session outcomes, completed-work logs, or temporary TODO "
        "state to memory; use session_search to recall those from past transcripts.\n"
        "If you've discovered a new way to do something, solved a problem that could be "
        "necessary later, save it as a skill with the skill tool.\n\n"
        "TWO TIERS:\n"
        "- HOT (default): in-context, always available, char-limited\n"
        "- WARM: Sovereign Vault, unlimited, browse with action='read_warm'\n\n"
        "ACTIONS:\n"
        "- add: new entry (auto-overflows to warm on full)\n"
        "- replace: update existing (old_text identifies it)\n"
        "- remove: delete (old_text identifies it)\n"
        "- read: view hot tier\n"
        "- read_warm: browse warm tier (optional content=query filters results)\n"
        "- warm_to_hot: recall from warm to hot (old_text=key)\n\n"
        "TARGETS:\n"
        "- 'user': who the user is\n"
        "- 'memory': your notes\n\n"
        "SKIP: trivial/obvious info, things easily re-discovered, raw data dumps, temporary task state."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": ["add", "replace", "remove", "read", "read_warm", "warm_to_hot"],
                "description": "The action to perform."
            },
            "target": {
                "type": "string",
                "enum": ["memory", "user"],
                "description": "Which memory store: 'memory' for personal notes, 'user' for user profile."
            },
            "content": {
                "type": "string",
                "description": "Entry content (required for 'add', 'replace'). "
                               "For 'read_warm': optional query string to filter results."
            },
            "old_text": {
                "type": "string",
                "description": "Short unique substring identifying the hot entry to replace or remove. "
                               "For 'warm_to_hot': the warm entry key."
            },
        },
        "required": ["action", "target"],
    },
}


# --- Registry ---
from tools.registry import registry, tool_error

registry.register(
    name="memory",
    toolset="memory",
    schema=MEMORY_SCHEMA,
    handler=lambda args, **kw: memory_tool(
        action=args.get("action", ""),
        target=args.get("target", "memory"),
        content=args.get("content"),
        old_text=args.get("old_text"),
        store=kw.get("store")),
    check_fn=check_memory_requirements,
    emoji="🧠",
)
