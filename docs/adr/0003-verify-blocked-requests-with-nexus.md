# Verify blocked requests with Nexus

For a Basic-authenticated request that would otherwise be blocked, the proxy sends an authenticated `HEAD` request for the exact content URL to Nexus before creating a report or notifying a Recipient. A successful Nexus response permits reporting and notification, while authentication, authorization, missing-content, and availability failures remain blocked without producing a report or message. Docker manifest requests use their already-completed exact manifest `GET` instead of a second probe.
