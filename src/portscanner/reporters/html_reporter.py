"""HTML report writer using Jinja2."""
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..models import ScanResult


_TEMPLATE_DIR = Path(__file__).resolve().parent.parent.parent.parent / "templates"


def write_html(result: ScanResult, path: str, template_dir: str = None) -> None:
    tdir = Path(template_dir) if template_dir else _TEMPLATE_DIR
    env = Environment(
        loader=FileSystemLoader(str(tdir)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    template = env.get_template("report.html.j2")

    duration = (result.end_time - result.start_time).total_seconds() \
        if result.end_time else 0

    html = template.render(
        result=result,
        duration=round(duration, 2),
        generated=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
    )

    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(html, encoding="utf-8")
