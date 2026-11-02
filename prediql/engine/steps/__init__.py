"""Step implementations.

Importing this package registers every step in ``STEP_REGISTRY``. Steps are
registered by import side effect, so a new capability is one module plus one
line here — the driver never changes.
"""

from prediql.engine.steps import adjudicate as _adjudicate  # noqa: F401
from prediql.engine.steps import compile as _compile  # noqa: F401
from prediql.engine.steps import cover as _cover  # noqa: F401
from prediql.engine.steps import execute_chains as _execute_chains  # noqa: F401
from prediql.engine.steps import identities as _identities  # noqa: F401
from prediql.engine.steps import introspect as _introspect  # noqa: F401
from prediql.engine.steps import plan_chains as _plan_chains  # noqa: F401
from prediql.engine.steps import probe as _probe  # noqa: F401
from prediql.engine.steps import report as _report  # noqa: F401
from prediql.engine.steps import score as _score  # noqa: F401
from prediql.engine.steps import validate as _validate  # noqa: F401

__all__ = [
    "_adjudicate", "_compile", "_cover", "_execute_chains", "_identities",
    "_introspect", "_plan_chains", "_probe", "_report", "_score", "_validate",
]
