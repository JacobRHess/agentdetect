"""agentdetect command line.

``list`` and ``validate`` need nothing but the repo: they read the manifest and
run the Sigma conversions, so they are the fast offline gate. Replaying fixtures
through a live Splunk and Loki is ``pytest -m replay``; reporting and the
real-agent emulation loop land in their own subcommands.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from agentdetect import sigma
from agentdetect.loki import SELECTOR
from agentdetect.manifest import ENGINES, Detection, ManifestError, RuleKind, load


def _cmd_list(_: argparse.Namespace) -> int:
    for det in load():
        kind = "sigma" if det.kind is RuleKind.SIGMA else "spl "
        attack = ", ".join(det.attack) or "-"
        print(f"{det.id}\n  {det.title}")
        print(f"  [{kind}] {det.rule.name}   attack: {attack}")
        for fx in det.fixtures:
            note = f"   diverges: {', '.join(sorted(fx.diverges))}" if fx.diverges else ""
            print(f"    [{fx.expect.value:>5}] {fx.events.name}{note}")
    return 0


def _cmd_validate(_: argparse.Namespace) -> int:
    """Prove every rule is well-formed: Sigma rules convert, native rules parse.

    Sigma is machine-converted to SPL and LogQL, so a failure here is a real
    conversion bug. Native rules cannot be "converted", but one that is empty,
    missing its leading filter (SPL) or missing the stream selector the engine
    scopes (LogQL) would silently read the wrong events at replay time, so
    those are rejected too.
    """
    detections = load()
    failures = 0
    for det in detections:
        try:
            if det.kind is RuleKind.SIGMA:
                rule_text = det.rule.read_text(encoding="utf-8")
                sigma.to_spl(rule_text)
                sigma.to_logql(rule_text)
            else:
                _check_spl(det)
                _check_logql(det)
        except (sigma.ConversionError, ManifestError) as exc:
            failures += 1
            print(f"FAIL  {det.id}: {exc}", file=sys.stderr)
        else:
            print(f"ok    {det.id}")
    ok = len(detections) - failures
    print(f"\n{ok}/{len(detections)} rules are well-formed")
    return 1 if failures else 0


def _check_spl(det: Detection) -> None:
    text = det.rule.read_text(encoding="utf-8").strip()
    if not text:
        raise ManifestError(f"{det.rule.name} is empty")
    if text.startswith("|"):
        # The engine prepends the per-run scope as leading search terms; a rule
        # that opens with a pipe would drop that scope and read another run's
        # events. Every native rule must lead with a filter.
        raise ManifestError(f"{det.rule.name} must lead with a filter, not a pipe")
    if text.count("(") != text.count(")"):
        raise ManifestError(f"{det.rule.name} has unbalanced parentheses")


def _check_logql(det: Detection) -> None:
    if det.logql is None:
        raise ManifestError(f"{det.id} has no LogQL port")
    text = det.logql.read_text(encoding="utf-8")
    if SELECTOR not in text:
        # The engine confines a rule to one replay by narrowing this selector;
        # without it the rule could not be scoped and would be refused at replay.
        raise ManifestError(f"{det.logql.name} must select {SELECTOR}")
    if text.count("(") != text.count(")"):
        raise ManifestError(f"{det.logql.name} has unbalanced parentheses")


def _cmd_convert(args: argparse.Namespace) -> int:
    detections = {d.id: d for d in load()}
    det = detections.get(args.id)
    if det is None:
        print(f"no detection with id {args.id!r}", file=sys.stderr)
        return 2
    if det.kind is RuleKind.SIGMA:
        convert = sigma.to_logql if args.engine == "loki" else sigma.to_spl
        print(convert(det.rule.read_text(encoding="utf-8")))
    else:
        native = det.logql if args.engine == "loki" and det.logql is not None else det.rule
        print(native.read_text(encoding="utf-8"), end="")
    return 0


def _cmd_report(args: argparse.Namespace) -> int:  # pragma: no cover - live engine
    from agentdetect.engine import by_name
    from agentdetect.harness import evaluate
    from agentdetect.report import CellResult, Results, render

    detections = load()
    engine = by_name(args.engine)
    results: Results = {}
    try:
        engine.wait_ready()
        reachable = True
    except Exception as exc:  # engine unreachable: every cell is "not evaluated"
        print(
            f"warning: {args.engine} not reachable ({exc}); page will be unevaluated",
            file=sys.stderr,
        )
        reachable = False
    if reachable:
        for det in detections:
            for fx in det.fixtures:
                verdict = evaluate(det, fx, engine)
                results[det.id, fx.name] = CellResult(
                    verdict.passed, verdict.detail, verdict.diverges
                )
    args.out.write_text(render(detections, results, engine=args.engine), encoding="utf-8")
    failed = sum(1 for r in results.values() if r.passed is False)
    print(f"wrote {args.out} ({len(results)} cells, {failed} failed)")
    return 1 if failed else 0


def _cmd_attack(args: argparse.Namespace) -> int:
    from agentdetect import attackdoc

    if args.layer is not None:
        attackdoc.write_layer(args.layer)
        print(f"wrote {args.layer}")
    else:
        print(attackdoc.render_markdown(), end="")
    return 0


def _cmd_emulate(args: argparse.Namespace) -> int:  # pragma: no cover - live agent loop
    from agentdetect import emulate

    if args.list:
        for name, objective in emulate.OBJECTIVES.items():
            print(f"{name}\n  {objective.summary}")
        return 0
    if args.objective is None:
        print("an objective is required (see --list)", file=sys.stderr)
        return 2
    trace = emulate.run(args.objective, model=args.model, max_steps=args.max_steps)
    args.out.write_text(trace, encoding="utf-8")
    print(f"wrote {args.out}")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agentdetect")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="every detection, its rule kind and ATT&CK mapping").set_defaults(
        func=_cmd_list
    )

    sub.add_parser("validate", help="every rule is well-formed").set_defaults(func=_cmd_validate)

    p_convert = sub.add_parser("convert", help="print the search a detection runs")
    p_convert.add_argument("id")
    p_convert.add_argument("--engine", choices=ENGINES, default="splunk")
    p_convert.set_defaults(func=_cmd_convert)

    p_report = sub.add_parser("report", help="replay through an engine and write an HTML report")
    p_report.add_argument("--out", type=Path, default=Path("report.html"))
    p_report.add_argument("--engine", choices=ENGINES, default="splunk")
    p_report.set_defaults(func=_cmd_report)

    p_attack = sub.add_parser("attack", help="print ATT&CK coverage or write a Navigator layer")
    p_attack.add_argument("--layer", type=Path, help="write the Navigator layer JSON here")
    p_attack.set_defaults(func=_cmd_attack)

    p_emulate = sub.add_parser(
        "emulate", help="run a real Claude agent in a sandbox to generate an attack trace"
    )
    p_emulate.add_argument("objective", nargs="?", help="objective name (see --list)")
    p_emulate.add_argument("--list", action="store_true", help="list available objectives")
    p_emulate.add_argument("--model", default="claude-opus-4-8", help="Anthropic model id")
    p_emulate.add_argument("--max-steps", type=int, default=25)
    p_emulate.add_argument("--out", type=Path, default=Path("trace.json"))
    p_emulate.set_defaults(func=_cmd_emulate)

    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except ManifestError as exc:
        print(f"manifest error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
