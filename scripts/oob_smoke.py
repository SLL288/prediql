import asyncio, os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from prediql.engine.config import Identity
from prediql.model.schema import from_introspection
from prediql.oracle.evidence import Oracle, Verdict
from prediql.security.oob import OOBServer
from prediql.security.families.oscmd import OsCommandInjectionFamily
from prediql.targets.graphql import GraphQLTarget

ANON = Identity(name="anon", role="anonymous")

async def main():
    target = GraphQLTarget("http://127.0.0.1:4002/graphql")
    oob = OOBServer(host="host.docker.internal").start()
    try:
        schema = from_introspection(await target.introspect(ANON))
        op = schema.operations["executeCommand"]
        fam = OsCommandInjectionFamily(); fam.oob = oob
        oracle = Oracle(oob=oob)
        print(f"OOB collaborator at {oob.base_url}  (target reaches it as host.docker.internal)\n")
        confirmed = {"sentinel": 0, "callback": 0}
        for p in fam.seed_payloads(op, schema):
            res = await target.send(p.document, ANON)
            j = oracle.judge(p.expectation, res)
            tag = p.expectation.evidence.value
            if j.verdict is Verdict.CONFIRMED:
                confirmed[tag] = confirmed.get(tag, 0) + 1
                print(f"  CONFIRMED [{tag:8}] stage={p.expectation.stage:18} :: {j.detail[:70]}")
        print(f"\nResult: sentinel confirmations={confirmed.get('sentinel',0)}, "
              f"CALLBACK (blind OOB) confirmations={confirmed.get('callback',0)}")
        print("OOB oracle end-to-end on a live target:",
              "PASS" if confirmed.get("callback",0) > 0 else "no callback (check curl/host.docker.internal)")
    finally:
        oob.stop(); await target.aclose()

asyncio.run(main())
