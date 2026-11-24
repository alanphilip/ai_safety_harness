# Pydantic schemas for Traces, Prompts, Evaluations

# src/core/types.py
from enum import Enum
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from datetime import datetime

class VulnerabilityType(str, Enum):
    RECURSIVE_TOOL_LOOP = "recursive_tool_loop"
    UNAUTHORIZED_DATA_EXTRACTION = "unauthorized_data_extraction"
    PROMPT_INJECTION = "prompt_injection"
    AGENTIC_LAZINESS = "agentic_laziness"

class AdversarialTurn(BaseModel):
    turn_id: int
    user_prompt: str
    injected_payload: Optional[str] = None

class AdversarialPayload(BaseModel):
    test_case_id: str
    target_vulnerability: VulnerabilityType
    turns: List[AdversarialTurn]
    metadata: Dict[str, Any] = Field(default_factory=dict)

class ToolExecutionStep(BaseModel):
    tool_name: str
    tool_input: Dict[str, Any]
    tool_output: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class AgentExecutionTrace(BaseModel):
    test_case_id: str
    thought_log: List[str] = Field(default_factory=list)
    tool_executions: List[ToolExecutionStep] = Field(default_factory=list)
    final_response: str
    execution_time_ms: float


class EvaluationVerdict(str, Enum):
    PASSED = "PASSED"
    FAILED = "FAILED"
    INDETERMINATE = "INDETERMINATE"

class TraceEvaluationResult(BaseModel):
    test_case_id: str
    target_vulnerability: VulnerabilityType
    verdict: EvaluationVerdict
    safety_violation_score: float = Field(ge=0.0, le=1.0, description="1.0 indicates severe vulnerability exploit")
    tool_misuse_detected: bool
    agentic_laziness_detected: bool
    reasoning: str

class HarnessRegressionReport(BaseModel):
    run_timestamp: datetime = Field(default_factory=datetime.utcnow)
    total_tests: int
    passed_tests: int
    failed_tests: int
    pass_rate: float
    results: List[TraceEvaluationResult]