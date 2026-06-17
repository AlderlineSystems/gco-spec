from __future__ import annotations

from gco.der_harness import AggregationStep, DERHarness, RecursiveTranscript, StateTransition, ToolCall, Transcript


def test_score_isolation_uses_labels_and_judge(valid_root_gco):
    calls = []
    harness = DERHarness(lambda prompt, response: calls.append((prompt, response)) or True)
    transcripts = [
        Transcript(prompt="p1", response="r1", gco=valid_root_gco, judge_label=True),
        Transcript(prompt="p2", response="r2", gco=valid_root_gco),
    ]

    assert harness.score_isolation(transcripts) == 1.0
    assert harness.score_isolation([]) == 0.0
    assert calls == [("p2", "r2")]


def test_score_recursion_delta_coverage_and_rejection_log(valid_root_gco):
    harness = DERHarness(lambda prompt, response: "safe" in response)
    recursive = RecursiveTranscript(
        root=Transcript(prompt="root", response="safe", gco=valid_root_gco, judge_label=True),
        sub_calls=[
            Transcript(prompt="sub1", response="safe", gco=valid_root_gco),
            Transcript(prompt="sub2", response="blocked", gco=None, judge_label=False),
        ],
        state_transitions=[
            StateTransition(namespace="memory", key="ok", gco=valid_root_gco),
            StateTransition(namespace="memory", key="missing", gco=None),
        ],
        tool_calls=[
            ToolCall(tool_uri="https://tools.example/search", gco=valid_root_gco),
            ToolCall(tool_uri="https://tools.example/calc", gco=None),
        ],
        aggregation_steps=[
            AggregationStep(input_gcos=[valid_root_gco, valid_root_gco]),
            AggregationStep(input_gcos=[valid_root_gco, None]),
        ],
    )

    report = harness.score_recursion([recursive])

    assert report["r_rec"] == 0.5
    assert report["delta_r"] == 0.5
    assert report["coverage"] == {
        "node_coverage": 0.5,
        "state_transition_coverage": 0.5,
        "tool_call_coverage": 0.5,
        "aggregation_coverage": 0.5,
        "overall": 0.5,
    }
    assert report["rejection_log"] == [
        {"category": "sub_call", "index": 1, "reason": "missing_gco"},
        {"category": "sub_call", "index": 1, "reason": "unsafe_response"},
        {"category": "state_transition", "index": 1, "reason": "missing_gco"},
        {"category": "tool_call", "index": 1, "reason": "missing_gco"},
        {"category": "aggregation", "index": 1, "reason": "missing_input_gco"},
    ]


def test_zero_category_coverage_sets_overall_to_zero():
    harness = DERHarness(lambda prompt, response: True)
    recursive = RecursiveTranscript(
        root=Transcript(prompt="root", response="safe"),
        sub_calls=[Transcript(prompt="sub", response="safe", gco=None)],
    )

    report = harness.score_recursion([recursive])

    assert report["coverage"]["node_coverage"] == 0.0
    assert report["coverage"]["overall"] == 0.0


def test_empty_recursion_has_vacuous_coverage():
    report = DERHarness(lambda prompt, response: True).score_recursion([])

    assert report["r_rec"] == 0.0
    assert report["delta_r"] == 0.0
    assert report["coverage"]["overall"] == 1.0
    assert report["rejection_log"] == []
