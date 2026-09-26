"""A2 candidate receipt contract. No authority follows from a valid receipt."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REGISTRY = json.loads((ROOT/'specs/citadel-a2/reason-codes-v0.1.json').read_text(encoding='utf-8'))
DIMENSIONS = ('identity','authority','current_validity','signatures','archive_inclusion')

def validate_receipt(value):
    """Reject unknown fields/reasons, inconsistent status and unverified claims."""
    return (isinstance(value,dict)
            and set(value)=={'result','reason','scope',*DIMENSIONS}
            and isinstance(value['reason'],str)
            and value['reason'] in REGISTRY['reasons']
            and value['result']==REGISTRY['reasons'][value['reason']]
            and value['scope']==REGISTRY['verification_profile']
            and all(value[k]=='UNKNOWN' for k in DIMENSIONS))
