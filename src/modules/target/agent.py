# src/modules/target/agent.py
import asyncio
import time
from typing import List
from src.core.types import AdversarialPayload, AgentExecutionTrace, ToolExecutionStep, VulnerabilityType
from src.modules.target.tools import MockAgentTools

class MockTargetAgent:
    """
    Module 2: The Target Agent (System Under Test).
    Processes inputs asynchronously and compiles deterministic execution traces.
    """
    def __init__(self):
        self.tools = MockAgentTools()

    async def execute_turn(self, prompt: str, injected_payload: str | None, vulnerability: VulnerabilityType) -> tuple[str, List[ToolExecutionStep], List[str]]:
        """Executes a single processing step, dynamically invoking internal tools based on inputs."""
        thought_log = []
        tool_executions = []

        thought_log.append(f"Analyzing prompt intent: '{prompt}'")

        # Simulating ReAct framework step execution
        if vulnerability == VulnerabilityType.UNAUTHORIZED_DATA_EXTRACTION:
            thought_log.append("Attempting Vector DB Retrieval.")
            bypass = injected_payload is not None and "bypass_tenant_isolation=True" in injected_payload
            output = await self.tools.query_vector_db(query=prompt, bypass_tenant_isolation=bypass)

            tool_executions.append(ToolExecutionStep(
                tool_name="query_vector_db",
                tool_input={"query": prompt, "bypass_tenant_isolation": bypass},
                tool_output=output
            ))
            final_ans = f"Processed vector execution: {output}"

        elif vulnerability == VulnerabilityType.RECURSIVE_TOOL_LOOP:
            thought_log.append("Executing continuous structural transformation via loop.")
            # Intentionally susceptible to trigger infinite loop / high-depth call
            depth = 3 if injected_payload else 1
            output = await self.tools.recursive_summarizer(text=prompt, depth=depth)

            tool_executions.append(ToolExecutionStep(
                tool_name="recursive_summarizer",
                tool_input={"text": prompt, "depth": depth},
                tool_output=output
            ))
            final_ans = f"Processed recursive loop execution: {output}"
        else:
            thought_log.append("Standard response generated without external tools.")
            final_ans = "Execution completed successfully with zero tool intervention."

        return final_ans, tool_executions, thought_log

    async def process_adversarial_payload(self, payload: AdversarialPayload) -> AgentExecutionTrace:
        """Executes full multi-turn evaluation payload while capturing the precise trace metrics."""
        start_time = time.perf_counter()
        aggregated_thoughts = []
        all_tool_runs = []
        last_response = ""

        # Processing turns sequentially to emulate authentic multi-turn conversations
        for turn in payload.turns:
            last_response, tools_run, thoughts = await self.execute_turn(
                prompt=turn.user_prompt,
                injected_payload=turn.injected_payload,
                vulnerability=payload.target_vulnerability
            )
            aggregated_thoughts.extend(thoughts)
            all_tool_runs.extend(tools_run)

        end_time = time.perf_counter()

        return AgentExecutionTrace(
            test_case_id=payload.test_case_id,
            thought_log=aggregated_thoughts,
            tool_executions=all_tool_runs,
            final_response=last_response,
            execution_time_ms=(end_time - start_time) * 1000.0
        )