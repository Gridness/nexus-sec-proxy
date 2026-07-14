# Use Nexus email as the Yandex login

The proxy maps an authenticated Nexus user to Yandex Messenger through the user's Nexus email address. AD-backed deployments source that value through Nexus's LDAP email attribute, while local deployments maintain it on the Nexus user; the proxy does not fall back to an unverified username when the email is absent or invalid.
