import json
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from app.estate import load_estate
from app.generation import generate_layers, unified_diff, write_files
from app.reporting import build_report, llm_explainer, render_markdown


@dataclass
class PipelineResult:
    report: dict
    gaps: list
    out_dir: Path
    files: list = field(default_factory=list)


def _fresh(folder: Path) -> None:
    """Remove a folder this program wrote earlier, so stale files cannot linger."""
    if folder.exists():
        shutil.rmtree(folder)


def run_pipeline(estate_path, out_dir, use_llm: bool = False, generated_at: str = "") -> PipelineResult:
    estate = load_estate(estate_path)
    scan, resources, dependencies = estate["scan"], estate["resources"], estate["dependencies"]

    current = generate_layers(scan["region"], resources, dependencies)
    proposed = generate_layers(scan["region"], resources, dependencies, fix=True)

    report = build_report(
        scan,
        resources,
        explainer=llm_explainer if use_llm else None,
        generated_at=generated_at,
        generated_ids=current.generated_ids,
        terraform_gaps=current.gaps,
    )

    out = Path(out_dir)
    terraform = out / "terraform"
    _fresh(terraform / "current")
    _fresh(terraform / "proposed")
    write_files(current.files, terraform / "current")
    write_files(proposed.files, terraform / "proposed")
    write_files(
        {
            "report.md": render_markdown(report),
            "report.json": json.dumps(report, indent=2),
            "terraform/fixes.diff": unified_diff(current.files, proposed.files),
            "terraform/GAPS.txt": "\n".join(current.gaps) + ("\n" if current.gaps else ""),
        },
        out,
    )

    files = sorted(
        str(p.relative_to(out)).replace("\\", "/") for p in out.rglob("*") if p.is_file()
    )
    return PipelineResult(report=report, gaps=current.gaps, out_dir=out, files=files)