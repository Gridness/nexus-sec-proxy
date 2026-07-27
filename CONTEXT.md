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
A persisted explanation of one enforced artifact block, including its verified Requester when available and scanner-supported Mitigation. Repeated blocked requests produce distinct Trust Reports, and report creation does not depend on notification delivery.
_Avoid_: Notification, message

**Reporting Engagement**:
The pre-existing DefectDojo container that owns the Trust Reports produced by one proxy deployment.
_Avoid_: Product, Test, dynamically created engagement

**Mitigation**:
A scanner-supported action that addresses a vulnerability, such as upgrading to a reported fixed version. Missing mitigation data means unknown, not that no fix exists.
_Avoid_: Guessed remediation, policy exception

**Policy Finding**:
An issue recorded because an artifact could not be evaluated under the active policy, rather than because a vulnerability was identified.
_Avoid_: Vulnerability, scanner finding

**Security Notification**:
A best-effort Yandex message that alerts a Recipient to an enforced block and links to its Trust Report. Its delivery never affects the block or report.
_Avoid_: Trust Report, guaranteed alert
