# Messenger delivery is observable best effort

The proxy persists the Trust Report and enforces the block independently of Yandex Messenger, then delivers the Security Notification asynchronously with bounded capacity, bounded transient retries, stable Yandex deduplication, failure telemetry, and graceful-shutdown draining. Saturation drops the new notification instead of delaying the artifact request. It does not add a durable outbox, so overload or a process crash may lose a message without affecting the block or Trust Report.
