"""Turn a report dictionary into HTML, and HTML into a PDF.

Split in two on purpose, and the split is what makes this testable. HTML is a
first-class artifact here rather than an intermediate: it is what the templates
produce, it is what the tests assert against, and it is what the API can serve
directly for a reader who wants to look at a report rather than file it.

PDF generation is the thin layer on top. WeasyPrint needs native libraries --
pango, cairo, harfbuzz -- that are present in the deployed image and are not
present on every developer's machine, so it is imported at call time rather
than at module import. A missing library then produces one clear sentence about
the server's configuration instead of breaking every import that transitively
reaches this module, including the ones that only ever wanted HTML.
"""

from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from app.core.errors import NotConfigured

TEMPLATE_DIR = Path(__file__).parent / "templates"

# Autoescaped, and that is not a formality. Every string in a report comes from
# a customer's own cloud -- resource names, tag values, error text returned by
# Azure -- and a resource named ``<script>`` must render as a resource name.
_env = Environment(
    loader=FileSystemLoader(TEMPLATE_DIR),
    autoescape=select_autoescape(["html", "xml", "html.j2"], default_for_string=True),
    trim_blocks=True,
    lstrip_blocks=True,
)


def _format_datetime(value: str | None) -> str:
    """An ISO timestamp as a person reads it, in UTC.

    UTC and labelled, not the server's local time. A report is read in a
    different place from where it was generated, and an unlabelled local
    timestamp is the kind of detail that turns into an argument about whether
    a fix landed before or after an incident.
    """
    if not value:
        return "—"
    try:
        moment = datetime.fromisoformat(value)
    except ValueError:
        return value
    return moment.strftime("%d %b %Y %H:%M UTC")


_env.filters["datetime"] = _format_datetime


def render_html(report: dict[str, Any]) -> str:
    """The report as a standalone HTML document."""
    template = _env.get_template(f"{report['kind']}.html.j2")
    return template.render(report=report, css=_stylesheet())


def render_pdf(report: dict[str, Any]) -> bytes:
    """The same document, printed.

    The HTML carries its own stylesheet inline, so nothing here fetches
    anything: a report renders identically on a machine with no network, and a
    customer's resource name can never cause an outbound request.
    """
    html = render_html(report)
    try:
        from weasyprint import HTML
    except OSError as exc:
        # WeasyPrint imports fine and then fails to load its native libraries.
        # Worth its own message: "no module named weasyprint" would send an
        # operator to pip, and pip is not what is missing.
        raise NotConfigured(
            "This server cannot render PDFs: WeasyPrint's native libraries "
            f"(pango, cairo, harfbuzz) are not installed. {exc}"
        ) from exc
    except ImportError as exc:
        raise NotConfigured(
            "This server cannot render PDFs: WeasyPrint is not installed."
        ) from exc

    return bytes(HTML(string=html).write_pdf())


def _stylesheet() -> str:
    return (TEMPLATE_DIR / "report.css").read_text(encoding="utf-8")
