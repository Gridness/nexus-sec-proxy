# Nexus owns requester authentication

Nexus Repository is the sole authority that authenticates Requesters and authorizes repository access. Deployments may configure Nexus Community Edition with local users or an AD-backed LDAP realm, but the proxy does not authenticate directly against AD; this avoids duplicating identity policy and preserves Nexus-specific authorization.
