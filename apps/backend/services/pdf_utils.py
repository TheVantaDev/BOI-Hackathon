"""Shared HTML → PDF helpers for report and actions downloads."""
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"


def render_template(template_name: str, **context) -> str:
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    return env.get_template(template_name).render(**context)


def html_to_pdf(html: str) -> bytes:
    # lazy import: WeasyPrint native libs only needed at PDF time (present in Docker)
    from weasyprint import HTML

    return HTML(string=html, base_url=str(TEMPLATES_DIR)).write_pdf()
