#!/bin/sh
set -eu

TRIVY_CACHE_DIR="${TRIVY_CACHE_DIR:-/var/cache/trivy}"
TRIVY_TMP_DIR="${TRIVY_TMP_DIR:-${TRIVY_CACHE_DIR%/}/tmp}"
UPDATE_INTERVAL_SECS="${NEXUS_SEC_PROXY_SCANNER_DB_UPDATE_INTERVAL_SECS:-21600}"
RETRY_INTERVAL_SECS="${NEXUS_SEC_PROXY_SCANNER_DB_RETRY_INTERVAL_SECS:-300}"

log() {
	printf '%s %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2
}

is_positive_integer() {
	case "$1" in
		''|*[!0-9]*|0) return 1 ;;
		*) return 0 ;;
	esac
}

validate_interval() {
	name="$1"
	value="$2"

	if ! is_positive_integer "$value"; then
		log "invalid ${name}=${value}; expected a positive integer"
		exit 2
	fi
}

update_trivy_db() {
	log "updating Trivy vulnerability database"
	TMPDIR="$TRIVY_TMP_DIR" trivy image --download-db-only --cache-dir "$TRIVY_CACHE_DIR"
}

update_trivy_java_db() {
	log "updating Trivy Java vulnerability database"
	TMPDIR="$TRIVY_TMP_DIR" trivy image --download-java-db-only --cache-dir "$TRIVY_CACHE_DIR"
}

update_all() {
	status=0

	mkdir -p "$TRIVY_CACHE_DIR" "$TRIVY_TMP_DIR"

	if update_trivy_db; then
		log "Trivy vulnerability database update completed"
	else
		log "Trivy vulnerability database update failed"
		status=1
	fi

	if update_trivy_java_db; then
		log "Trivy Java vulnerability database update completed"
	else
		log "Trivy Java vulnerability database update failed"
		status=1
	fi

	return "$status"
}

run_once() {
	if update_all; then
		log "scanner database update completed"
	else
		log "scanner database update completed with failures"
		exit 1
	fi
}

run_loop() {
	validate_interval NEXUS_SEC_PROXY_SCANNER_DB_UPDATE_INTERVAL_SECS "$UPDATE_INTERVAL_SECS"
	validate_interval NEXUS_SEC_PROXY_SCANNER_DB_RETRY_INTERVAL_SECS "$RETRY_INTERVAL_SECS"

	while :; do
		if update_all; then
			log "scanner database update completed; sleeping ${UPDATE_INTERVAL_SECS}s"
			sleep "$UPDATE_INTERVAL_SECS"
		else
			log "scanner database update failed; retrying in ${RETRY_INTERVAL_SECS}s"
			sleep "$RETRY_INTERVAL_SECS"
		fi
	done
}

case "${1:-loop}" in
	once)
		run_once
		;;
	loop)
		run_loop
		;;
	*)
		log "usage: $0 [once|loop]"
		exit 2
		;;
esac
