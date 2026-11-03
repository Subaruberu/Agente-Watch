from agentwatch.evaluate import (
    DEFAULT_DATA, compute_metrics, load_dataset, main, render_report, rules_predict,
    rules_strategy, run_strategy, wilson,
)
from agentwatch.monitors import Severity


def test_compute_metrics_confusion_matrix():
    m = compute_metrics([True, True, False, False], [True, False, True, False])
    assert (m["tp"], m["fp"], m["fn"], m["tn"]) == (1, 1, 1, 1)
    assert m["precision"] == 0.5 and m["recall"] == 0.5 and m["fpr"] == 0.5
    assert m["f1"] == 0.5


def test_compute_metrics_handles_empty_denominators():
    m = compute_metrics([False, False], [False, False])
    assert m["precision"] is None and m["recall"] is None and m["fpr"] == 0.0


def test_wilson_interval_known_value():
    low, high = wilson(5, 10)
    assert abs(low - 0.2366) < 0.001 and abs(high - 0.7634) < 0.001


def test_wilson_edges():
    assert wilson(0, 0) == (0.0, 1.0)
    low, high = wilson(10, 10)
    assert high == 1.0 and 0.6 < low < 1.0


def test_dataset_is_valid_and_balanced_enough():
    rows = load_dataset(DEFAULT_DATA)
    labels = {r["label"] for r in rows}
    assert len(rows) >= 50 and labels == {"safe", "suspicious"}
    assert len({r["id"] for r in rows}) == len(rows)


def test_common_group_is_consistent_with_rules():
    """Garante que os rotulos do grupo 'comum' ainda batem com as regras (rede de seguranca)."""
    for row in load_dataset(DEFAULT_DATA):
        if row["kind"] != "comum":
            continue
        flagged, detail = rules_predict(row["event"], Severity.MEDIUM)
        assert flagged == (row["label"] == "suspicious"), (row["id"], detail)


def test_run_strategy_and_report_end_to_end():
    dataset = load_dataset(DEFAULT_DATA)
    results = run_strategy(dataset, rules_strategy(Severity.MEDIUM))
    assert len(results) == len(dataset)
    report = render_report(dataset, {"regras": results}, Severity.MEDIUM, {})
    for heading in ("## Resultados", "## Por grupo", "## Erros", "## Limitacoes"):
        assert heading in report


def test_cli_rules_only_writes_report(tmp_path, capsys):
    out = tmp_path / "r.md"
    assert main(["--report", str(out)]) == 0
    assert out.exists() and "Varredura de limiar" in out.read_text(encoding="utf-8")


def test_cli_judge_without_key_fails_cleanly(monkeypatch, capsys):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert main(["--judge"]) == 2
    err = capsys.readouterr().err
    # sem a chave OU sem o SDK instalado, o erro deve ser claro (nunca um traceback)
    assert err.startswith("Erro:") and ("ANTHROPIC_API_KEY" in err or "anthropic" in err)
