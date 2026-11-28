import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

from app.estate import EstateError
from app.pipeline import run_pipeline

FIX_ORDER = ("proposed", "blocked", "needs a person", "not yet supported")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check a sample estate, then write the report and Terraform."
    )
    parser.add_argument("--estate", default="sample/estate.json", help="the estate file")
    parser.add_argument("--out", default="build/demo", help="where to write the output")
    parser.add_argument("--llm", action="store_true", help="let the local model reword explanations")
    args = parser.parse_args()

    out = Path(args.out).resolve()
    if out == Path.cwd().resolve() or out == Path(out.anchor):
        print("Refusing to use the project folder or a drive root as the output folder.")
        return 2

    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    try:
        result = run_pipeline(args.estate, out, use_llm=args.llm, generated_at=stamp)
    except (EstateError, OSError) as exc:
        print(f"Could not run: {exc}")
        return 1

    summary = result.report["summary"]
    sev, savings = summary["by_severity"], summary["savings"]
    prefix = "up to " if savings["includes_upper_bounds"] else ""
    fixes = ", ".join(f"{s} {summary['fixes'][s]}" for s in FIX_ORDER if s in summary["fixes"])

    print("SAMPLE DATA - nothing here was read from a real cloud account.")
    print()
    print(f"Estate:     {summary['resources_checked']} resources")
    print(f"Findings:   {summary['findings']} (high {sev['high']}, medium {sev['medium']}, low {sev['low']})")
    print(f"Savings:    {prefix}${savings['total_usd']:,.2f} per month (estimated; methods are in the report)")
    print(f"Fixes:      {fixes}")
    print(f"Terraform:  {len(result.gaps)} gaps (see terraform/GAPS.txt)")
    print()
    print(f"Written to {out}")
    for name in result.files:
        print(f"  {name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())