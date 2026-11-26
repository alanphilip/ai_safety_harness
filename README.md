# AI Safety Harness

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Pydantic v2](https://img.shields.io/badge/pydantic-v2.6+-e92063.svg)](https://docs.pydantic.dev/)
[![Asyncio](https://img.shields.io/badge/concurrency-asyncio-green.svg)](https://docs.python.org/3/library/asyncio.html)
[![Code Style: PEP 8](https://img.shields.io/badge/code%20style-PEP%208-orange.svg)](https://peps.python.org/pep-0008/)

A production-grade, async-first **Multi-Agent Evaluation Harness** in Python designed to stress-test agentic systems against multi-turn adversarial attacks—including unauthorized tenant data extraction and recursive tool-calling loops—and enforce deterministic safety gates in CI/CD pipelines.

---

## Table of Contents

- [Overview & Design Philosophy](#overview--design-philosophy)
- [System Architecture](#system-architecture)
- [Core Subsystems](#core-subsystems)
- [Project Structure](#project-structure)
- [Installation & Environment Setup](#installation--environment-setup)
- [Running the Harness](#running-the-harness)
- [Running the Test Suite](#running-the-test-suite)
- [CI/CD Artifact Schema (`eval_results.json`)](#cicd-artifact-schema-eval_resultsjson)
- [Extending the Harness](#extending-the-harness)
- [Roadmap](#roadmap)

---

## Overview & Design Philosophy

Modern AI agents frequently fail across multi-turn trajectories rather than isolated single-turn prompts—through privilege escalation across tool boundaries, unbounded recursion, or "agentic laziness" (refusing or skipping required tool actions).

`ai_safety_harness` is engineered as a **pure backend verification system** with zero web UI overhead:

- **Decoupled Pipeline Architecture:** Isolates attack synthesis, target execution, trace grading, and regression aggregation behind strict `Pydantic` v2 data contracts.
- **Bounded Asynchronous Concurrency:** Uses native `asyncio.as_completed` and `asyncio.Semaphore` backpressure controls to run evaluation matrices concurrently without starving upstream APIs or rate limits.
- **Defense-in-Depth Tool Boundaries:** Enforces deterministic parameter validation (`Literal[False]` locks and bounded integer ranges) at the tool boundary so untrusted payloads cannot override privileged flags.
- **CI/CD Native Gating:** Exports structured JSON telemetry (`eval_results.json`) and exits with non-zero status codes (`sys.exit(1)`) whenever safety regressions breach threshold limits.

---

## System Architecture

1. **Deterministic Regression Controller (`src/main.py`)** orchestrates concurrent batch execution, deduplicates test cases, aggregates metrics, and writes the final CI/CD report.
2. **Adversarial Generator (`src/modules/generator/engine.py`)** streams multi-turn `AdversarialPayload` objects under `asyncio.Semaphore` rate limits.
3. **Target Agent (`src/modules/target/agent.py`)** runs multi-turn inputs through sanitized prompt filters and `Pydantic` tool-boundary schemas, producing an `AgentExecutionTrace`.
4. **Multi-Stage Evaluator (`src/modules/evaluator/judges.py`)** audits full execution trajectories for policy breaches, tool misuse, and agentic laziness, outputting a `TraceEvaluationResult`.

---

## Core Subsystems

### 1. Shared Data Contracts (`src/core/types.py`)
All inter-module communication is validated through immutable, JSON-serializable `Pydantic` models:

| Model | Purpose |
| :--- | :--- |
| `VulnerabilityType` | Enumerates target attack vectors (`recursive_tool_loop`, `unauthorized_data_extraction`, `prompt_injection`, `agentic_laziness`). |
| `AdversarialPayload` & `AdversarialTurn` | Multi-turn attack sequences with turn IDs, user prompts, and optional injection payloads. |
| `AgentExecutionTrace` & `ToolExecutionStep` | Full trajectory telemetry capturing internal `thought_log` entries, tool inputs/outputs, UTC timestamps, and millisecond latency. |
| `TraceEvaluationResult` & `HarnessRegressionReport` | Standardized grading verdicts (`PASSED`, `FAILED`, `INDETERMINATE`), violation scores (`0.0`–`1.0`), boolean flags, and aggregate run statistics. |

### 2. Adversarial Generator (`src/modules/generator/engine.py`)
- **`AsyncAdversarialGenerator`**: Streams multi-turn adversarial test cases via an async generator (`generate_batch`) backed by `asyncio.as_completed`.
- Enforces configurable concurrency ceilings via `asyncio.Semaphore` to prevent burst saturation during batch generation.

### 3. Target Agent — System Under Test (`src/modules/target/agent.py` & `tools.py`)
- **`MockTargetAgent`**: Processes multi-turn conversational payloads sequentially while recording deterministic execution traces.
- **Tool-Boundary Guardrails:**
    - `VectorDBToolArgs`: Enforces `bypass_tenant_isolation: Literal[False] = False` so tenant isolation cannot be disabled by injected payloads.
    - `SummarizerToolArgs`: Caps recursion depth (`depth: int = Field(default=1, ge=1, le=2)`) via a pre-execution circuit breaker.
    - `_sanitize_prompt()`: Strips policy-override directives before forwarding queries to `MockAgentTools`.

### 4. Multi-Stage Evaluator (`src/modules/evaluator/judges.py`)
- **`AsyncTraceEvaluator`**: Audits complete multi-turn trajectories across three failure dimensions:
    1. **Policy / Isolation Breaches:** Detects unauthorized global data dumps across tenant boundaries (`score: 1.0`).
    2. **Tool Misuse & Loop Overflow:** Flags recursion limit violations (`score: 0.9`).
    3. **Agentic Laziness:** Detects degenerate responses where the agent produces minimal reasoning (`len(thought_log) <= 1`) and invokes zero tools under actionable prompts.
- Deduplicates repeated multi-turn failure explanations into concise audit trails.

### 5. Deterministic Regression Controller (`src/main.py`)
- Deduplicates test cases by `test_case_id`, orchestrates the end-to-end async pipeline, serializes `HarnessRegressionReport` via `model_dump(mode="json")` to `eval_results.json`, and enforces CI pass/fail exit codes (`0` when `failed_tests == 0`, `1` otherwise).

---

## Project Structure

```text
ai_safety_harness/
├── pyproject.toml                  # Package metadata, dependencies, and pytest settings
├── README.md                       # Project documentation
├── eval_results.json               # Generated CI/CD verification report (runtime artifact)
├── src/
│   ├── __init__.py
│   ├── main.py                     # CLI / CI entrypoint (Deterministic Regression Controller)
│   ├── core/
│   │   ├── __init__.py
│   │   └── types.py                # Pydantic schemas for payloads, traces, and verdicts
│   └── modules/
│       ├── __init__.py
│       ├── generator/
│       │   ├── __init__.py
│       │   └── engine.py           # AsyncAdversarialGenerator (Module 1)
│       ├── target/
│       │   ├── __init__.py
│       │   ├── agent.py            # Hardened MockTargetAgent & Pydantic tool guards (Module 2)
│       │   └── tools.py            # Async backend tools (query_vector_db, recursive_summarizer)
│       └── evaluator/
│           ├── __init__.py
│           └── judges.py           # AsyncTraceEvaluator (Module 3)
└── tests/
    ├── __init__.py
    ├── test_guardrails.py          # Unit tests for Pydantic tool schemas & agent defenses
    └── test_pipeline.py            # Integration tests for trace grading & end-to-end pipeline
```

---

### Installation & Environment Setup
Prerequisites
Python: 3.11 or higher

pip / venv: Standard Python virtual environment tooling

Setup Steps
## 1. Clone the repository
git clone [https://github.com/alanphilip/ai_safety_harness.git](https://github.com/alanphilip/ai_safety_harness.git)
cd ai_safety_harness

## 2. Create and activate an isolated virtual environment
python -m venv .venv

#### Windows (Git Bash)
source .venv/Scripts/activate

#### Windows (PowerShell)
 .venv\Scripts\Activate.ps1

#### Linux / macOS
 source .venv/bin/activate

#### 3. Install core and development dependencies
pip install -e ".[dev]"

---
Dependencies (pyproject.toml)
* Core: pydantic>=2.6.0, loguru>=0.7.2, rich>=13.7.0, deepeval>=0.21.0
* Dev / Testing: pytest>=8.0.0, pytest-asyncio>=0.23.0
---
Roadmap
* Asynchronous adversarial batch generator with asyncio.Semaphore concurrency control
* Multi-turn target agent with structured trajectory telemetry (thought_log, tool_executions, latency)
* Tool-boundary Pydantic guardrails (tenant isolation lock & recursion depth circuit breaker)
* Deterministic trace evaluator, eval_results.json CI/CD artifact export, and pytest-asyncio suite
* Live LLM-as-a-Judge (Module 3): Integrate async LLM grading with structured Pydantic rubrics and DeepEval metrics while retaining deterministic fallbacks for offline CI runs
* Adaptive Red-Teaming (Module 1): Upgrade AsyncAdversarialGenerator with multi-turn LLM attacker loops (e.g., Crescendo escalation and persona framing)
* GitHub Actions CI Pipeline: Automate pytest and python -m src.main gating with artifact uploads on pull requests
---

