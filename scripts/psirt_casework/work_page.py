"""Compact only the two work pages, retaining the existing garden shell/assets."""
import re
from pathlib import Path

STYLE = Path(__file__).with_name('assets') / 'work-page.css'


def compact_shell(prefix):
    """Add a layout scope without copying data or altering the home-page renderer."""
    def body(match):
        tag = match.group(0)
        if re.search(r'\bclass=["\']', tag):
            return re.sub(r'(\bclass=["\'])', r'\1psirt-work-page ', tag, count=1)
        return tag[:-1] + ' class="psirt-work-page">'

    prefix = re.sub(r'<body\b[^>]*>', body, prefix, count=1)
    return prefix.replace('</head>', '<style data-work-layout="compact-v1">' + STYLE.read_text() + '</style></head>', 1)
