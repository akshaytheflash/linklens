import glob
import logging
import os
from typing import Dict, List, Optional

import yara

logger = logging.getLogger(__name__)


class YaraScanner:
    """Compiles every .yar rule in a directory once and offers helpers to
    scan both files and raw content (HTML, JS).

    Rules are compiled per-file (one namespace each) so a single broken rule
    doesn't silently disable the whole scanner.
    """

    def __init__(self, rules_directory: str) -> None:
        self.rules_directory = rules_directory
        self.rule_files = self._get_rule_files(rules_directory)
        self._compiled: Dict[str, yara.Rules] = {}
        self._rule_count = 0
        self._load_rules()

    def _get_rule_files(self, directory: str) -> List[str]:
        if not os.path.isdir(directory):
            return []
        return [
            path
            for path in glob.glob(os.path.join(directory, "**", "*.yar"), recursive=True)
            if os.path.isfile(path)
        ]

    def _load_rules(self) -> None:
        if not self.rule_files:
            logger.warning("No YARA rule files found in %s", self.rules_directory)
            return
        ok = 0
        for index, path in enumerate(self.rule_files):
            # Each file compiles into its own standalone Rules object, so we
            # don't need namespaces — and this keeps one bad file from
            # taking the whole scanner down.
            try:
                self._compiled[f"rules_{index}"] = yara.compile(filepaths={os.path.basename(path): path})
                ok += 1
            except Exception as e:
                logger.warning("Skipping broken rule file %s: %s", os.path.basename(path), e)
        self._rule_count = len(self._compiled)
        logger.info("Compiled %d/%d YARA rule files", ok, len(self.rule_files))

    def _match(self, source: Dict[str, bytes]) -> List[str]:
        matched = []
        for rules in self._compiled.values():
            try:
                matched.extend(m.rule for m in rules.match(data=source["data"]))
            except Exception as e:
                logger.warning("Error during YARA match: %s", e)
        return matched

    def scan_file(self, path: str) -> List[str]:
        if not self._compiled or not os.path.isfile(path):
            return []
        try:
            with open(path, "rb") as handle:
                return self._match({"data": handle.read()})
        except Exception as e:
            logger.warning("Error reading file %s: %s", path, e)
            return []

    def scan_content(self, content: str) -> List[str]:
        if not self._compiled or not content:
            return []
        return self._match({"data": content.encode("utf-8", errors="ignore")})

    def get_rule_count(self) -> int:
        return self._rule_count
