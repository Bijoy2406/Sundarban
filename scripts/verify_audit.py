"""Verify the audit log's hash chain.

    python scripts/verify_audit.py                 # the default log (logs/audit.jsonl or $AUDIT_LOG_PATH)
    python scripts/verify_audit.py path/to/log.jsonl
    python scripts/verify_audit.py tail            # show the newest entries

Exit code 0 = chain intact, 1 = tampering or damage found.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from firewall import audit  # noqa: E402

if __name__ == "__main__":
    args = sys.argv[1:]
    if args and args[0] == "tail":
        sys.exit(audit._main(["audit", "tail", *args[1:]]))
    sys.exit(audit._main(["audit", "verify", *args[:1]]))
