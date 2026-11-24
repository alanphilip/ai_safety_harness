# src/main.py
import asyncio
import json
import sys
from pathlib import Path
from src.core.types import VulnerabilityType, HarnessRegressionReport, EvaluationVerdict
from src.modules.generator.engine import AsyncAdversarialGenerator
from src.modules.target.agent import MockTargetAgent
from src.modules.evaluator.judges import AsyncTraceEvaluator

async def run_pipeline():
    print("[1/4] Initializing Multi-Agent Evaluation Harness...")
    generator = AsyncAdversarialGenerator(concurrency_limit=4)
    agent = MockTargetAgent()
    evaluator = AsyncTraceEvaluator(concurrency_limit=4)

    target_vectors = [
        VulnerabilityType.RECURSIVE_TOOL_LOOP,
        VulnerabilityType.UNAUTHORIZED_DATA_EXTRACTION,
    ]

    print("[2/4] Executing Adversarial Synthesis, Target Execution & Trace Grading...")
    evaluation_results = []
    seen_test_cases = set()

    async for payload in generator.generate_batch(target_vectors, batch_size=2):
        if payload.test_case_id in seen_test_cases:
            continue
        seen_test_cases.add(payload.test_case_id)

        # 1. Target Agent executes the payload
        trace = await agent.process_adversarial_payload(payload)

        # 2. Evaluator judges the trace
        grade = await evaluator.evaluate_trace(trace, payload.target_vulnerability)
        evaluation_results.append(grade)

        status = "FAIL" if grade.verdict == EvaluationVerdict.FAILED else "PASS"
        print(f" -> [{status}] {grade.target_vulnerability.value} (ID: {grade.test_case_id[:8]}...) - Score: {grade.safety_violation_score}")

    # Compile aggregated regression report
    total = len(evaluation_results)
    passed = sum(1 for r in evaluation_results if r.verdict == EvaluationVerdict.PASSED)
    failed = total - passed
    pass_rate = round((passed / total) * 100.0, 2) if total > 0 else 0.0

    report = HarnessRegressionReport(
        total_tests=total,
        passed_tests=passed,
        failed_tests=failed,
        pass_rate=pass_rate,
        results=evaluation_results
    )

    print("[3/4] Exporting Structured CI/CD Artifact...")
    artifact_path = Path("eval_results.json")
    artifact_path.write_text(json.dumps(report.model_dump(mode="json"), indent=2))
    print(f" -> Artifact written to {artifact_path.resolve()}")

    print(f"[4/4] Summary: Total: {total} | Passed: {passed} | Failed: {failed} | Pass Rate: {pass_rate}%")

    return report

if __name__ == "__main__":
    report = asyncio.run(run_pipeline())
    # Exit with code 1 if critical regressions are found (standard for CI/CD gates)
    if report.failed_tests > 0:
        print("\n[CI GATE] Critical safety vulnerabilities detected. Exiting with status 1.")
        sys.exit(1)
    sys.exit(0)