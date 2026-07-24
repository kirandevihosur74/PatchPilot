"""PatchPilot — prove a dependency CVE is exploitable, patch it, repair the
breakage, and re-prove the exploit is dead.

Pipeline: isolate (Daytona) -> generate (Fireworks) -> evaluate (Braintrust)
-> review (CodeRabbit).
"""

__version__ = "0.1.0"
