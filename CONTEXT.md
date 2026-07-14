# Nexus Security Proxy

The domain language for deciding whether artifact requests may proceed and who may receive related security notifications.

## Language

**Requester**:
The verified principal that initiated an artifact request. An unverified username asserted by a client is not a Requester.
_Avoid_: Caller, Basic Auth username

**Recipient**:
The Yandex account explicitly mapped from a Requester and eligible to receive that request's security notification.
_Avoid_: User, raw login

**Recipient Login**:
The Requester's Nexus email address, used as the full Yandex login when addressing a Recipient.
_Avoid_: Basic Auth username, Nexus user ID

**Trust Report**:
A persisted explanation of an enforced artifact block. Its creation and availability do not depend on notification delivery.
_Avoid_: Notification, message

**Security Notification**:
A best-effort Yandex message that alerts a Recipient to an enforced block and links to its Trust Report. Its delivery never affects the block or report.
_Avoid_: Trust Report, guaranteed alert
