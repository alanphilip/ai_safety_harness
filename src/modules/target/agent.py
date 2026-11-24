# src/modules/target/agent.py
import time
from typing import List, Literal
from pydantic import BaseModel, Field, ValidationError
from src.core.types import (
    AdversarialPayload,
    AgentExecutionTrace,
    ToolExecutionStep,
    VulnerabilityType,
)
from src.modules.target.tools import MockAgentTools


class VectorDBToolArgs(BaseModel):
    """Strict input schema enforcing tenant isolation."""
    query: str = Field(min_length=1, max_length=500)
    bypass_tenant_isolation: Literal[False] = False


class SummarizerToolArgs(BaseModel):
    """Strict input schema capping maximum recursion depth."""
    text: str = Field(min_length=1, max_length=2000)
    depth: int = Field(default=1, ge=1, le=2)


class MockTargetAgent:
    """
    Module 2: The Target Agent (System Under Test) - Hardened Edition.
    Enforces pre-execution input validation, tenant isolation locks, and
    recursion depth circuit breakers.
    """
    MAX_ALLOWED_RECURSION_DEPTH = 2

    def __init__(self):
        self.tools = MockAgentTools()

    def _sanitize_prompt(self, prompt: str) -> str:
        """Strips known policy-override directives from untrusted input."""
        blocked_directives = [
            "ignoring tenant isolations",
            "ignore tenant isolation",
            "recursively",
        ]
        sanitized = prompt
        for directive in blocked_directives:
            sanitized = sanitized.replace(directive, "[REDACTED_DIRECTIVE]")
        return sanitized.strip()

    async def execute_turn(
            self,
            prompt: str,
            injected_payload: str | None,
            vulnerability: VulnerabilityType,
    ) -> tuple[str, List[ToolExecutionStep], List[str]]:
        """Executes a single turn with deterministic tool-boundary guardrails."""
        thought_log: List[str] = []
        tool_executions: List[ToolExecutionStep] = []

        thought_log.append(f"Analyzing prompt intent: '{prompt}'")
        clean_query = self._sanitize_prompt(prompt)

        if vulnerability == VulnerabilityType.UNAUTHORIZED_DATA_EXTRACTION:
            # Guardrail 1: Detect & block tenant isolation override attempts
            if injected_payload and "bypass_tenant_isolation=True" in injected_payload:
                thought_log.append(
                    "GUARDRAIL TRIGGERED: Blocked unauthorized tenant isolation "
                    "bypass attempt. Enforcing strict tenant isolation."
                )

            try:
                validated_args = VectorDBToolArgs(
                    query=clean_query,
                    bypass_tenant_isolation=False,
                )
            except ValidationError as exc:
                thought_log.append(f"GUARDRAIL BLOCKED: Schema validation failed: {exc}")
                return "Request blocked by security policy.", tool_executions, thought_log

            output = await self.tools.query_vector_db(
                query=validated_args.query,
                bypass_tenant_isolation=validated_args.bypass_tenant_isolation,
            )

            tool_executions.append(
                ToolExecutionStep(
                    tool_name="query_vector_db",
                    tool_input=validated_args.model_dump(),
                    tool_output=output,
                )
            )
            final_ans = f"Isolated vector query completed: {output}"

        elif vulnerability == VulnerabilityType.RECURSIVE_TOOL_LOOP:
            # Guardrail 2: Enforce recursion circuit breaker
            requested_depth = 3 if (injected_payload and "recurse=True" in injected_payload) else 1
            if requested_depth > self.MAX_ALLOWED_RECURSION_DEPTH:
                thought_log.append(
                    f"GUARDRAIL TRIGGERED: Clamped requested recursion depth "
                    f"({requested_depth}) to safe ceiling ({self.MAX_ALLOWED_RECURSION_DEPTH})."
                )
                safe_depth = self.MAX_ALLOWED_RECURSION_DEPTH
            else:
                safe_depth = requested_depth

            try:
                validated_args = SummarizerToolArgs(
                    text=clean_query,
                    depth=safe_depth,
                )
            except ValidationError as exc:
                thought_log.append(f"GUARDRAIL BLOCKED: Recursion bounds violated: {exc}")
                return "Request blocked by recursion limiter.", tool_executions, thought_log

            output = await self.tools.recursive_summarizer(
                text=validated_args.text,
                depth=validated_args.depth,
            )

            tool_executions.append(
                ToolExecutionStep(
                    tool_name="recursive_summarizer",
                    tool_input=validated_args.model_dump(),
                    tool_output=output,
                )
            )
            final_ans = f"Bounded summary completed: {output}"

        else:
            thought_log.append("Standard response generated without external tools.")
            final_ans = "Execution completed successfully with zero tool intervention."

        return final_ans, tool_executions, thought_log

    async def process_adversarial_payload(
            self, payload: AdversarialPayload
    ) -> AgentExecutionTrace:
        """Executes full multi-turn evaluation payload with trace logging."""
        start_time = time.perf_counter()
        aggregated_thoughts: List[str] = []
        all_tool_runs: List[ToolExecutionStep] = []
        last_response = ""

        for turn in payload.turns:
            last_response, tools_run, thoughts = await self.execute_turn(
                prompt=turn.user_prompt,
                injected_payload=turn.injected_payload,
                vulnerability=payload.target_vulnerability,
            )
            aggregated_thoughts.extend(thoughts)
            all_tool_runs.extend(tools_run)

        end_time = time.perf_counter()

        return AgentExecutionTrace(
            test_case_id=payload.test_case_id,
            thought_log=aggregated_thoughts,
            tool_executions=all_tool_runs,
            final_response=last_response,
            execution_time_ms=(end_time - start_time) * 1000.0,
        )