"""LinkLens — a URL safety analyzer.

A Flask app that inspects links statically (HTTP metadata, WHOIS, certs,
YARA) and dynamically (headless Chromium with network/popup/download
monitoring) and turns all of that into a readable risk verdict.
"""

__version__ = "1.0.0"
