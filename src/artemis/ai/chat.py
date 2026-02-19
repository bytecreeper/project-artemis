"""Natural Language Chat Interface — "Siri for Security"

Translates plain English questions into database queries, event lookups,
and human-readable answers. Inspired by Endgame's Artemis (2017).

Non-technical users ask: "What happened today?"
They get: "Your system has been quiet. 12 events logged, all routine. No threats detected."

Security pros ask: "Show me all failed SSH attempts from 192.168.1.50 in the last 6 hours"
They get: structured results + AI analysis.
"""

from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger("artemis.ai.chat")


class QueryIntent(Enum):
    """What the user is trying to do."""
    STATUS = "status"              # "How's my system?" / "Am I safe?"
    EVENTS = "events"              # "What happened today?"
    ALERTS = "alerts"              # "Any alerts?" / "Show me threats"
    NETWORK = "network"            # "What's on my network?" / "Show connected devices"
    PROCESS = "process"            # "What processes are running?" / "Is X running?"
    SEARCH = "search"              # Free-text search across events
    FINDINGS = "findings"          # "Any security issues?" / "What's wrong?"
    SCORE = "score"                # "What's my security score?"
    HELP = "help"                  # "What can you do?" / "Help"
    ANALYZE = "analyze"            # Deep analysis — pass to AI
    UNKNOWN = "unknown"


@dataclass
class ChatMessage:
    role: str  # "user" or "assistant"
    content: str
    timestamp: float = field(default_factory=time.time)
    data: dict[str, Any] | None = None  # Structured data attached to response


@dataclass
class ChatSession:
    messages: list[ChatMessage] = field(default_factory=list)
    max_history: int = 20

    def add(self, role: str, content: str, data: dict | None = None) -> ChatMessage:
        msg = ChatMessage(role=role, content=content, data=data)
        self.messages.append(msg)
        if len(self.messages) > self.max_history:
            self.messages = self.messages[-self.max_history:]
        return msg

    def history_text(self, last_n: int = 6) -> str:
        """Format recent history for AI context."""
        recent = self.messages[-last_n:]
        lines = []
        for m in recent:
            lines.append(f"{m.role.upper()}: {m.content}")
        return "\n".join(lines)


# ── Intent Detection (deterministic first, AI fallback) ──────────────

# Pattern → intent mapping (checked in order)
_INTENT_PATTERNS: list[tuple[list[str], QueryIntent]] = [
    # Status / overview
    (["status", "how's my", "how is my", "am i safe", "overview", "summary",
      "what's going on", "what is going on", "sitrep"], QueryIntent.STATUS),

    # Security score
    (["score", "security score", "rating", "grade", "how secure"], QueryIntent.SCORE),

    # Findings / issues
    (["finding", "issue", "problem", "what's wrong", "what is wrong",
      "vulnerability", "vulnerabilities", "threats found"], QueryIntent.FINDINGS),

    # Alerts
    (["alert", "alarm", "warning", "threat", "danger", "critical",
      "urgent", "incident"], QueryIntent.ALERTS),

    # Network
    (["network", "device", "host", "connected", "who's on",
      "who is on", "ip address", "subnet", "scan"], QueryIntent.NETWORK),

    # Process
    (["process", "running", "pid", "executable", "service",
      "what's running", "what is running", "task"], QueryIntent.PROCESS),

    # Events
    (["event", "happened", "log", "activity", "recent",
      "today", "last hour", "yesterday"], QueryIntent.EVENTS),

    # Help
    (["help", "what can you", "how do i", "commands", "guide",
      "tutorial", "explain"], QueryIntent.HELP),
]


def detect_intent(text: str) -> QueryIntent:
    """Fast deterministic intent detection — no AI needed for common queries."""
    lower = text.lower().strip()

    for patterns, intent in _INTENT_PATTERNS:
        for p in patterns:
            if p in lower:
                return intent

    # If it looks like a question or request, treat as search/analyze
    if "?" in text or len(text.split()) > 8:
        return QueryIntent.ANALYZE

    return QueryIntent.SEARCH


# ── Time Parsing ──────────────────────────────────────────────────────

def parse_time_reference(text: str) -> int | None:
    """Extract time window from natural language. Returns hours or None."""
    lower = text.lower()

    # Explicit hours/minutes
    m = re.search(r'(\d+)\s*hour', lower)
    if m:
        return int(m.group(1))
    m = re.search(r'(\d+)\s*min', lower)
    if m:
        return max(1, int(m.group(1)) // 60)

    # Named periods
    if "today" in lower or "this morning" in lower:
        return 24
    if "yesterday" in lower:
        return 48
    if "this week" in lower or "past week" in lower:
        return 168
    if "last hour" in lower:
        return 1
    if "last night" in lower:
        return 12

    return None


# ── Response Builders ─────────────────────────────────────────────────

class ChatEngine:
    """Processes chat messages and generates responses.

    Uses deterministic handlers for common queries (fast, no AI cost).
    Falls back to AI for complex analysis.
    """

    def __init__(self, db, ai_provider, classifier=None):
        self.db = db
        self.ai = ai_provider
        self.classifier = classifier
        self.sessions: dict[str, ChatSession] = {}

    def get_session(self, session_id: str = "default") -> ChatSession:
        if session_id not in self.sessions:
            self.sessions[session_id] = ChatSession()
        return self.sessions[session_id]

    async def process(self, text: str, session_id: str = "default") -> ChatMessage:
        """Main entry point — process a user message and return response."""
        session = self.get_session(session_id)
        session.add("user", text)

        intent = detect_intent(text)
        hours = parse_time_reference(text)

        try:
            handler = {
                QueryIntent.STATUS: self._handle_status,
                QueryIntent.SCORE: self._handle_score,
                QueryIntent.FINDINGS: self._handle_findings,
                QueryIntent.ALERTS: self._handle_alerts,
                QueryIntent.NETWORK: self._handle_network,
                QueryIntent.PROCESS: self._handle_process,
                QueryIntent.EVENTS: self._handle_events,
                QueryIntent.HELP: self._handle_help,
                QueryIntent.SEARCH: self._handle_search,
                QueryIntent.ANALYZE: self._handle_analyze,
                QueryIntent.UNKNOWN: self._handle_search,
            }[intent]

            content, data = await handler(text, hours)
        except Exception as e:
            logger.error("Chat error: %s", e, exc_info=True)
            content = f"Something went wrong processing that: {e}"
            data = None

        return session.add("assistant", content, data)

    # ── Handlers ──────────────────────────────────────────────────────

    async def _handle_status(self, text: str, hours: int | None) -> tuple[str, dict]:
        """Overall system status — the "How am I doing?" answer."""
        events_24h = self.db.count_events_since(24)
        open_alerts = self.db.count_open_alerts()
        host_count = self.db.count_hosts()

        score = 100
        score_label = "Healthy"
        finding_count = 0
        if self.classifier:
            score = self.classifier.security_score
            score_label = self.classifier.score_label
            finding_count = len(self.classifier.active_findings)

        # Build human-readable response
        if open_alerts == 0 and finding_count == 0:
            status_line = "Your system looks good. No active threats or alerts."
        elif open_alerts > 0 and finding_count == 0:
            status_line = f"There {'is' if open_alerts == 1 else 'are'} {open_alerts} open alert{'s' if open_alerts != 1 else ''} to review."
        elif finding_count > 0:
            status_line = f"Found {finding_count} security issue{'s' if finding_count != 1 else ''} that need{'s' if finding_count == 1 else ''} attention."
        else:
            status_line = "All quiet."

        response = (
            f"**Security Score: {score}/100 ({score_label})**\n\n"
            f"{status_line}\n\n"
            f"- {events_24h} events in the last 24 hours\n"
            f"- {open_alerts} open alert{'s' if open_alerts != 1 else ''}\n"
            f"- {host_count} device{'s' if host_count != 1 else ''} on network\n"
            f"- {finding_count} active finding{'s' if finding_count != 1 else ''}"
        )

        data = {
            "score": score, "label": score_label, "events_24h": events_24h,
            "open_alerts": open_alerts, "hosts": host_count, "findings": finding_count,
        }
        return response, data

    async def _handle_score(self, text: str, hours: int | None) -> tuple[str, dict]:
        score = 100
        label = "Healthy"
        breakdown = {}
        if self.classifier:
            score = self.classifier.security_score
            label = self.classifier.score_label
            for f in self.classifier.active_findings:
                cat = f.category.value
                breakdown[cat] = breakdown.get(cat, 0) + 1

        if score >= 80:
            emoji = "green"
            comment = "Looking solid."
        elif score >= 50:
            emoji = "yellow"
            comment = "Some issues to address."
        else:
            emoji = "red"
            comment = "Needs immediate attention."

        parts = [f"**Security Score: {score}/100** — {label}\n\n{comment}"]
        if breakdown:
            parts.append("\nBreakdown by category:")
            for cat, count in sorted(breakdown.items()):
                parts.append(f"  - {cat}: {count} finding{'s' if count != 1 else ''}")

        return "\n".join(parts), {"score": score, "label": label, "color": emoji, "breakdown": breakdown}

    async def _handle_findings(self, text: str, hours: int | None) -> tuple[str, dict]:
        if not self.classifier or not self.classifier.active_findings:
            return "No active security findings. Your system is clean.", {"findings": []}

        findings = self.classifier.active_findings
        parts = [f"**{len(findings)} Active Finding{'s' if len(findings) != 1 else ''}:**\n"]
        for f in findings[:10]:  # Cap at 10
            sev_icon = {"critical": "!!!", "high": "!!", "medium": "!", "low": "."}.get(f.severity.value, "?")
            mitre = f" ({f.mitre_id})" if f.mitre_id else ""
            parts.append(f"[{sev_icon}] **{f.title}**{mitre}\n    {f.description}\n")

        if len(findings) > 10:
            parts.append(f"\n... and {len(findings) - 10} more. Check the Security Status page for full list.")

        data = {
            "findings": [
                {"id": f.id, "title": f.title, "severity": f.severity.value,
                 "category": f.category.value, "mitre_id": f.mitre_id}
                for f in findings
            ]
        }
        return "\n".join(parts), data

    async def _handle_alerts(self, text: str, hours: int | None) -> tuple[str, dict]:
        alerts = self.db.get_open_alerts()
        if not alerts:
            return "No open alerts. Everything is quiet.", {"alerts": []}

        parts = [f"**{len(alerts)} Open Alert{'s' if len(alerts) != 1 else ''}:**\n"]
        for a in alerts[:10]:
            sev = a[4]
            title = a[2]
            ts = str(a[1])[:19]
            parts.append(f"[sev:{sev}] **{title}** — {ts}")

        data = {"alerts": [{"id": a[0], "title": a[2], "severity": a[4]} for a in alerts]}
        return "\n".join(parts), data

    async def _handle_network(self, text: str, hours: int | None) -> tuple[str, dict]:
        hosts = self.db.get_hosts()
        count = len(hosts)
        if count == 0:
            return "No hosts discovered yet. The network scanner may still be running its first sweep.", {"hosts": []}

        parts = [f"**{count} Device{'s' if count != 1 else ''} on Network:**\n"]
        for h in hosts[:20]:
            name = h.get("hostname") or "unknown"
            ip = h["ip"]
            mac = h.get("mac") or "?"
            os_g = h.get("os_guess") or ""
            line = f"- **{ip}** ({name}) — MAC: {mac}"
            if os_g:
                line += f" — {os_g}"
            parts.append(line)

        if count > 20:
            parts.append(f"\n... and {count - 20} more. See the Network page.")

        return "\n".join(parts), {"hosts": hosts}

    async def _handle_process(self, text: str, hours: int | None) -> tuple[str, dict]:
        # Get recent process events from DB
        rows = self.db.get_recent_events(limit=20, event_type="edr.process")
        if not rows:
            return "No recent process events recorded.", {"processes": []}

        parts = ["**Recent Process Activity:**\n"]
        for r in rows[:15]:
            data = r[5]
            if isinstance(data, str):
                try:
                    data = json.loads(data)
                except Exception:
                    data = {}
            name = data.get("name", "unknown") if isinstance(data, dict) else "unknown"
            pid = data.get("pid", "?") if isinstance(data, dict) else "?"
            ts = str(r[1])[:19]
            parts.append(f"- [{ts}] **{name}** (PID: {pid})")

        return "\n".join(parts), {"count": len(rows)}

    async def _handle_events(self, text: str, hours: int | None) -> tuple[str, dict]:
        h = hours or 24
        count = self.db.count_events_since(h)
        events = self.db.get_recent_events(limit=10)

        if count == 0:
            return f"No events in the last {h} hour{'s' if h != 1 else ''}.", {"count": 0}

        parts = [f"**{count} event{'s' if count != 1 else ''} in the last {h} hour{'s' if h != 1 else ''}.**\n"]
        parts.append("Most recent:")
        for r in events:
            ts = str(r[1])[:19]
            etype = r[2]
            sev = r[4]
            parts.append(f"- [{ts}] {etype} (severity: {sev})")

        return "\n".join(parts), {"count": count, "hours": h}

    async def _handle_help(self, text: str, hours: int | None) -> tuple[str, dict]:
        return (
            "**I'm Artemis — your security assistant.** Here's what you can ask me:\n\n"
            "- **\"How's my system?\"** — Overall security status\n"
            "- **\"What's my security score?\"** — Score breakdown\n"
            "- **\"Any alerts?\"** — Open alerts and threats\n"
            "- **\"What's on my network?\"** — Connected devices\n"
            "- **\"What happened today?\"** — Recent events\n"
            "- **\"Any security issues?\"** — Active findings\n"
            "- **\"Show me process activity\"** — Running processes\n"
            "- Or just ask anything in plain English — I'll figure it out.\n\n"
            "I work best with simple questions. For deep analysis, switch to Hunt mode."
        ), {}

    async def _handle_search(self, text: str, hours: int | None) -> tuple[str, dict]:
        h = hours or 24
        rows = self.db.search_events(text, limit=20, hours=h)
        if not rows:
            return f"No events matching \"{text}\" in the last {h} hours.", {"results": []}

        parts = [f"**{len(rows)} result{'s' if len(rows) != 1 else ''} for \"{text}\":**\n"]
        for r in rows[:10]:
            ts = str(r[1])[:19]
            etype = r[2]
            src = r[3]
            parts.append(f"- [{ts}] {etype} from {src}")

        return "\n".join(parts), {"count": len(rows)}

    async def _handle_analyze(self, text: str, hours: int | None) -> tuple[str, dict]:
        """Complex query — gather context and pass to AI for analysis."""
        # Build context from recent data
        h = hours or 24
        events = self.db.get_recent_events(limit=20)
        alerts = self.db.get_open_alerts()

        finding_data = []
        if self.classifier:
            finding_data = [
                {"title": f.title, "severity": f.severity.value, "category": f.category.value}
                for f in self.classifier.active_findings[:10]
            ]

        context = {
            "recent_events_count": self.db.count_events_since(h),
            "open_alerts": len(alerts),
            "active_findings": finding_data,
            "network_hosts": self.db.count_hosts(),
            "recent_events_sample": [
                {"time": str(r[1])[:19], "type": r[2], "severity": r[4]}
                for r in events[:10]
            ],
        }

        prompt = (
            f"User question: {text}\n\n"
            f"Current system context:\n{json.dumps(context, indent=2)}\n\n"
            "Answer the user's question based on this security data. "
            "Be concise, direct, and use plain language a non-technical user can understand. "
            "If there are concerning findings, explain what they mean and what to do."
        )

        try:
            result = await self.ai.generate(
                prompt,
                system=(
                    "You are Artemis, a security assistant for small businesses and nonprofits. "
                    "Speak plainly. No jargon unless the user used it first. "
                    "If things are fine, say so clearly. If there's a problem, explain it simply "
                    "and give one clear action to take."
                ),
                temperature=0.4,
            )
            return result, {"ai_generated": True, "context_events": len(events)}
        except Exception as e:
            logger.error("AI analyze failed: %s", e)
            # Fallback to deterministic status
            return await self._handle_status(text, hours)
