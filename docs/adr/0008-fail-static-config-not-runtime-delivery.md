# Fail static configuration, not runtime delivery

When Messenger is explicitly enabled, deterministic configuration errors fail startup, but startup does not depend on contacting Yandex. After startup, Yandex outages, recipient-resolution failures, and delivery failures degrade only Security Notifications; artifact blocking and Trust Report creation remain available.
