# Resolve Docker Requesters from accepted tokens

For Docker manifest requests, the proxy treats a successful Nexus response as validation of the presented Bearer JWT, reads its standard `sub` claim as the Nexus user ID, and resolves the Recipient through Nexus users. This keeps replicas stateless and avoids maintaining token-to-user mappings; malformed, anonymous, rejected, or unresolved tokens cannot produce notifications.
