# DefectDojo health is request-scoped

Startup and `/healthz` validate only static DefectDojo configuration and do not contact the remote service. A DefectDojo outage therefore leaves safe artifact requests available, while each enforced block makes one bounded synchronous report attempt with background import disabled and returns `503` unless the Test and Findings are complete; the proxy does not retry the non-idempotent Test creation automatically. Logs and admin status expose delivery failures without making the whole proxy unhealthy.
