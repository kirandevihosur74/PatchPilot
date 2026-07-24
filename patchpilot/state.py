"""Run state — the single object that flows through the loop and drives both the
goal tracker and the streamed UI. Idempotent nodes read/write this."""

from __future__ import annotations

import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Optional


class Node(str, Enum):
    DETECT = "detect"
    PROVE = "prove"
    UPGRADE = "upgrade"
    OBSERVE = "observe"
    FIX = "fix"
    VERIFY = "verify"
    GUARD = "guard"
    REPROVE = "reprove"
    SUBMIT = "submit"
    GATE = "gate"
    MERGE = "merge"
    ESCALATE = "escalate"
    DONE = "done"


@dataclass
class GoalTracker:
    """The four beats a judge watches turn green."""
    exploit_proven: Optional[bool] = None      # step 2: exploit accepted on vulnerable code
    cve_resolved: Optional[bool] = None        # steps 3-7: patched + security preserved
    tests_green: Optional[bool] = None         # step 6: suite passes after repair
    exploit_blocked: Optional[bool] = None     # step 8: same exploit now rejected

    def render(self) -> str:
        def mark(v: Optional[bool]) -> str:
            return "PASS" if v else ("FAIL" if v is False else "....")
        return (
            f"[{mark(self.exploit_proven)}] Exploitable: proven   "
            f"[{mark(self.cve_resolved)}] CVE resolved   "
            f"[{mark(self.tests_green)}] Tests green   "
            f"[{mark(self.exploit_blocked)}] Exploit blocked"
        )


@dataclass
class TestResult:
    passed: int = 0
    failed: int = 0
    errors: int = 0
    failing: list[dict[str, str]] = field(default_factory=list)  # {name, traceback}
    raw: str = ""

    @property
    def all_green(self) -> bool:
        return self.failed == 0 and self.errors == 0


@dataclass
class RunState:
    run_id: str
    target_path: str
    package: str = ""
    installed_version: str = ""
    patched_version: str = ""
    cve_id: str = ""

    node: Node = Node.DETECT
    iteration: int = 0
    max_iterations: int = 3

    # step outputs
    exploit_accepted_before: Optional[bool] = None
    exploit_evidence_before: str = ""
    tests: Optional[TestResult] = None
    fixes_applied: list[dict[str, str]] = field(default_factory=list)  # {file, diff}
    security_eval: Optional[dict[str, Any]] = None
    exploit_accepted_after: Optional[bool] = None
    exploit_evidence_after: str = ""

    # review / merge
    pr_url: str = ""
    pr_number: Optional[int] = None
    tests_check_ok: Optional[bool] = None
    review_ok: Optional[bool] = None
    merged: bool = False

    escalated: bool = False
    escalation_reason: str = ""

    goals: GoalTracker = field(default_factory=GoalTracker)
    events: list[dict[str, Any]] = field(default_factory=list)
    started_at: float = field(default_factory=time.time)

    def log(self, node: Node, message: str, **data: Any) -> None:
        """Append a streamable event, mirror it to stdout, and push it to any
        live subscriber (the web dashboard) via the optional on_event hook."""
        evt = {
            "t": round(time.time() - self.started_at, 2),
            "node": node.value,
            "message": message,
            "goals": self.goal_snapshot(),
            **data,
        }
        self.events.append(evt)
        print(f"  [{evt['t']:>6.2f}s] {node.value:<8} {message}")
        cb = getattr(self, "on_event", None)
        if cb:
            try:
                cb(evt)
            except Exception:
                pass

    def goal_snapshot(self) -> dict[str, Any]:
        return {
            "exploit_proven": self.goals.exploit_proven,
            "cve_resolved": self.goals.cve_resolved,
            "tests_green": self.goals.tests_green,
            "exploit_blocked": self.goals.exploit_blocked,
        }

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["node"] = self.node.value
        return d
