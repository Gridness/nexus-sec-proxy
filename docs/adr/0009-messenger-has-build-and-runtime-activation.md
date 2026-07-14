# Messenger has build-time and runtime activation

The standard binary and Docker image include the default `yandex-messenger` Cargo feature, but a deployment sends messages only when `NEXUS_SEC_PROXY_YANDEX_MESSENGER_ENABLED=true`. Featureless native and Docker builds remain available for hardened deployments, and requesting runtime activation from a featureless binary is a startup configuration error rather than a silent no-op.
