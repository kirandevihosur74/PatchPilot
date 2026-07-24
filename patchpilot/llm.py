"""Generate step (Fireworks). Two models:
  * triage  — fast/cheap: classify a pytest traceback (error type, root cause, file).
  * coder   — strong: rewrite the broken source so tests pass WITHOUT weakening security.

Model ids drift on Fireworks; these defaults come from 2026 SDK research and are
overridable via env (see config). Call `list_models()` to confirm live ids.

If no Fireworks key is set, an offline fallback produces the known-correct
SafeLoader fix so the whole loop still runs end-to-end for local dev/demo.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

DEFAULT_TRIAGE_MODEL = "accounts/fireworks/models/gpt-oss-20b"
DEFAULT_CODER_MODEL = "accounts/fireworks/models/kimi-k2p7-code"

SECURITY_RULE = (
    "SECURITY RULE (non-negotiable): when fixing PyYAML usage you MUST use "
    "yaml.SafeLoader. NEVER use yaml.Loader, yaml.FullLoader, yaml.UnsafeLoader, "
    "or yaml.unsafe_load — those keep the vulnerability alive. Restore functionality "
    "the safe way only."
)


@dataclass
class Triage:
    error_type: str
    root_cause: str
    fix_file: str


class LLM:
    def __init__(self, config) -> None:
        self.config = config
        self.triage_model = config.triage_model or DEFAULT_TRIAGE_MODEL
        self.coder_model = config.coder_model or DEFAULT_CODER_MODEL
        self.force_unsafe = getattr(config, "force_unsafe_fix", False)
        self._client = None
        if config.has_fireworks:
            from openai import OpenAI

            client = OpenAI(base_url=config.fireworks_base_url, api_key=config.fireworks_api_key)
            # Auto-trace LLM calls into Braintrust when that's also wired.
            if config.has_braintrust:
                try:
                    from braintrust import wrap_openai

                    client = wrap_openai(client)
                except Exception:
                    pass
            self._client = client

    @property
    def online(self) -> bool:
        return self._client is not None

    # --- triage: classify one failing traceback ---
    def triage(self, failure_output: str) -> Triage:
        if not self.online:
            return self._offline_triage(failure_output)
        schema = {
            "type": "object",
            "properties": {
                "error_type": {"type": "string"},
                "root_cause": {"type": "string"},
                "fix_file": {"type": "string"},
            },
            "required": ["error_type", "root_cause", "fix_file"],
        }
        resp = self._client.chat.completions.create(
            model=self.triage_model,
            response_format={"type": "json_schema", "json_schema": {"name": "Triage", "schema": schema}},
            messages=[
                {"role": "system", "content": "You classify Python test failures. Reply in JSON."},
                {"role": "user", "content": f"Classify this pytest failure and name the source file to fix:\n\n{failure_output[:6000]}"},
            ],
        )
        data = json.loads(resp.choices[0].message.content)
        return Triage(data["error_type"], data["root_cause"], data["fix_file"])

    # --- coder: rewrite broken source files ---
    def generate_fix(self, files: dict[str, str], failure_output: str) -> dict[str, str]:
        """Return {filename: new_full_content} for files that changed."""
        if not self.online:
            return self._offline_fix(files)
        file_blocks = "\n\n".join(f"=== {name} ===\n{content}" for name, content in files.items())
        prompt = (
            f"{SECURITY_RULE}\n\n"
            "The dependency was upgraded and these files now fail their tests. "
            "Rewrite ONLY the files that must change so the tests pass. "
            "Return a JSON object mapping each changed filename to its FULL new content. "
            "Do not include unchanged files.\n\n"
            f"--- pytest output ---\n{failure_output[:6000]}\n\n"
            f"--- current files ---\n{file_blocks}"
        )
        resp = self._client.chat.completions.create(
            model=self.coder_model,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": "You are a senior engineer who repairs dependency-upgrade breakage without weakening security. Reply with a JSON object of {filename: content}."},
                {"role": "user", "content": prompt},
            ],
        )
        raw = resp.choices[0].message.content
        try:
            changed = json.loads(raw)
        except json.JSONDecodeError:
            changed = self._extract_json_object(raw)
        return {k: v for k, v in changed.items() if isinstance(v, str)}

    def list_models(self) -> list[str]:
        if not self.online:
            return []
        return [m.id for m in self._client.models.list().data]

    # --- offline fallbacks (no key) ---
    @staticmethod
    def _offline_triage(failure_output: str) -> Triage:
        fix_file = "parser.py"
        m = re.search(r"([\w/]+\.py)", failure_output)
        if m:
            fix_file = m.group(1).split("/")[-1]
        etype = "TypeError" if "TypeError" in failure_output else "Error"
        return Triage(etype, "yaml.load called without an explicit Loader", fix_file)

    def _offline_fix(self, files: dict[str, str]) -> dict[str, str]:
        """Deterministic repair: pin yaml.load to a Loader. Uses SafeLoader
        normally; yaml.Loader when force_unsafe is set (to demo the guard)."""
        loader = "yaml.Loader" if self.force_unsafe else "yaml.SafeLoader"
        changed: dict[str, str] = {}
        pattern = re.compile(r"yaml\.load\(\s*([^,()]+?)\s*\)")
        for name, content in files.items():
            if "yaml.load(" not in content:
                continue
            new = pattern.sub(rf"yaml.load(\1, Loader={loader})", content)
            if new != content:
                changed[name] = new
        return changed

    @staticmethod
    def _extract_json_object(text: str) -> dict:
        start = text.find("{")
        end = text.rfind("}")
        if start >= 0 and end > start:
            try:
                return json.loads(text[start : end + 1])
            except json.JSONDecodeError:
                return {}
        return {}
