# Resolve Recipients through Nexus users

After Nexus verifies a blocked request, the proxy uses its existing least-privileged Nexus service account to find exactly one active local or LDAP user matching the authenticated Basic user ID and uses that user's email as the Recipient Login. Messaging-enabled startup requires service credentials with user-read access; ambiguous, absent, or incomplete user records never fall back to client-supplied identity.
