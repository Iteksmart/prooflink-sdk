"""ProofLink CLI:  python -m prooflink <command>

  seal "<action>" [--category C] [--actor A] [--anchor]
  verify <receipt_id|hash_prefix>
  chain
  recent [N]
"""
import json
import sys

from . import seal, verify_id, verify_chain, recent, stats, ProofLinkError


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    if not argv:
        print(__doc__)
        return 2
    cmd, rest = argv[0], argv[1:]
    try:
        if cmd == "seal":
            kw = {}
            action_parts = []
            i = 0
            while i < len(rest):
                if rest[i] == "--category":
                    kw["category"] = rest[i + 1]; i += 2
                elif rest[i] == "--actor":
                    kw["actor"] = rest[i + 1]; i += 2
                elif rest[i] == "--anchor":
                    kw["anchor"] = True; i += 1
                else:
                    action_parts.append(rest[i]); i += 1
            print(json.dumps(seal(" ".join(action_parts), **kw)))
        elif cmd == "verify":
            from . import fetch as _fetch
            from .crypto import verify_receipt as _vr
            _r = _fetch(rest[0])
            print(json.dumps(_vr(_r), indent=2))
        elif cmd == "chain":
            print(json.dumps(verify_chain(), indent=2))
        elif cmd == "recent":
            print(json.dumps(recent(int(rest[0]) if rest else 25), indent=2))
        elif cmd == "stats":
            print(json.dumps(stats(), indent=2))
        else:
            print(f"unknown command: {cmd}\n{__doc__}", file=sys.stderr); return 2
    except (ProofLinkError, IndexError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr); return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
