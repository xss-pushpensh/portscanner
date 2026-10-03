"""Report writers."""
from .json_reporter import write_json
from .html_reporter import write_html

__all__ = ["write_json", "write_html"]
