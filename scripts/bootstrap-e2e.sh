#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
COMPOSE_FILE="${NEXUS_SEC_PROXY_E2E_COMPOSE_FILE:-}"

BUILD_IMAGES=1
PRIME_SCANNER_DB=1
START_SCANNER_DB_UPDATER=1
NEXUS_BASE_URL=
PROXY_BASE_URL=
NEXUS_CATALOG_FILE=
TRUST_BLOCK_BODY_FILE=
TRUST_REPORT_FILE=
PROXY_ADMIN_TOKEN_SOURCE=
NEXUS_CREDENTIALS_SOURCE=none
NEXUS_ADMIN_USERNAME=
NEXUS_ADMIN_PASSWORD=

cleanup() {
	if [ -n "${NEXUS_CATALOG_FILE:-}" ]; then
		rm -f "$NEXUS_CATALOG_FILE"
	fi
	if [ -n "${TRUST_BLOCK_BODY_FILE:-}" ]; then
		rm -f "$TRUST_BLOCK_BODY_FILE"
	fi
	if [ -n "${TRUST_REPORT_FILE:-}" ]; then
		rm -f "$TRUST_REPORT_FILE"
	fi
}

trap cleanup EXIT INT TERM

usage() {
	cat <<EOF
Usage: $0 [options]

Bootstrap the local e2e environment from e2e.compose.yaml.

Options:
  --no-build                    Skip docker compose build.
  --no-prime-scanner-db         Skip the one-time scanner DB update.
  --no-start-scanner-db-updater Skip the long-running scanner DB updater.
  -h, --help                    Show this help.

Environment:
  NEXUS_OSS_PORT                              Host Nexus port. Default: 8081.
  NEXUS_SEC_PROXY_PORT                       Host proxy port. Default: 3000.
  NEXUS_SEC_PROXY_E2E_COMPOSE_FILE           Compose file path.
  NEXUS_SEC_PROXY_E2E_NEXUS_TIMEOUT_SECS     Nexus health timeout.
  NEXUS_SEC_PROXY_E2E_CATALOG_TIMEOUT_SECS   Nexus catalog timeout.
  NEXUS_SEC_PROXY_E2E_PROXY_TIMEOUT_SECS     Proxy health timeout.
  NEXUS_SEC_PROXY_E2E_ADMIN_TOKEN            Proxy admin token. Default: e2e-admin-token.
  NEXUS_SEC_PROXY_ADMIN_TOKEN                Proxy admin token override.
  NEXUS_SEC_PROXY_NEXUS_USERNAME             Optional Nexus catalog username.
  NEXUS_SEC_PROXY_NEXUS_PASSWORD             Optional Nexus catalog password.
EOF
}

log() {
	printf '%s %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*"
}

die() {
	printf '%s error: %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2
	exit 1
}

compose() {
	docker compose -f "$COMPOSE_FILE" "$@"
}

dotenv_value() {
	name="$1"

	if [ ! -f "$REPO_ROOT/.env" ]; then
		return 1
	fi

	awk -v key="$name" '
		function trim(value) {
			sub(/^[[:space:]]+/, "", value)
			sub(/[[:space:]]+$/, "", value)
			return value
		}
		/^[[:space:]]*(#|$)/ {
			next
		}
		{
			line = $0
			sub(/^[[:space:]]*/, "", line)
			if (index(line, key "=") == 1) {
				value = trim(substr(line, length(key) + 2))
				if (substr(value, 1, 1) == "\"" && substr(value, length(value), 1) == "\"") {
					value = substr(value, 2, length(value) - 2)
				}
				found = value
				has = 1
			}
		}
		END {
			if (has) {
				print found
			} else {
				exit 1
			}
		}
	' "$REPO_ROOT/.env"
}

set_env_from_dotenv_if_empty() {
	name="$1"
	eval "current=\${$name:-}"

	if [ -n "$current" ]; then
		return 0
	fi

	value=$(dotenv_value "$name" || true)
	if [ -n "$value" ]; then
		export "$name=$value"
	fi
}

load_dotenv_defaults() {
	set_env_from_dotenv_if_empty NEXUS_SEC_PROXY_E2E_COMPOSE_FILE
	set_env_from_dotenv_if_empty NEXUS_OSS_PORT
	set_env_from_dotenv_if_empty NEXUS_SEC_PROXY_PORT
	set_env_from_dotenv_if_empty NEXUS_SEC_PROXY_E2E_NEXUS_TIMEOUT_SECS
	set_env_from_dotenv_if_empty NEXUS_SEC_PROXY_E2E_CATALOG_TIMEOUT_SECS
	set_env_from_dotenv_if_empty NEXUS_SEC_PROXY_E2E_PROXY_TIMEOUT_SECS
	set_env_from_dotenv_if_empty NEXUS_SEC_PROXY_E2E_ADMIN_TOKEN
	set_env_from_dotenv_if_empty NEXUS_SEC_PROXY_ADMIN_TOKEN
	set_env_from_dotenv_if_empty NEXUS_SEC_PROXY_NEXUS_USERNAME
	set_env_from_dotenv_if_empty NEXUS_SEC_PROXY_NEXUS_PASSWORD
}

configure_proxy_admin_token() {
	if [ -n "${NEXUS_SEC_PROXY_ADMIN_TOKEN:-}" ]; then
		PROXY_ADMIN_TOKEN_SOURCE=configured
	elif [ -n "${NEXUS_SEC_PROXY_E2E_ADMIN_TOKEN:-}" ]; then
		NEXUS_SEC_PROXY_ADMIN_TOKEN="$NEXUS_SEC_PROXY_E2E_ADMIN_TOKEN"
		PROXY_ADMIN_TOKEN_SOURCE=e2e-configured
	else
		NEXUS_SEC_PROXY_ADMIN_TOKEN=e2e-admin-token
		PROXY_ADMIN_TOKEN_SOURCE=default
	fi

	export NEXUS_SEC_PROXY_ADMIN_TOKEN
}

require_command() {
	if ! command -v "$1" >/dev/null 2>&1; then
		die "required command not found: $1"
	fi
}

is_positive_integer() {
	case "$1" in
		''|*[!0-9]*|0) return 1 ;;
		*) return 0 ;;
	esac
}

validate_timeout() {
	name="$1"
	value="$2"

	if ! is_positive_integer "$value"; then
		die "${name} must be a positive integer, got: ${value}"
	fi
}

container_state() {
	container_id="$1"

	docker inspect --format '{{.State.Status}}' "$container_id" 2>/dev/null || true
}

container_health() {
	container_id="$1"

	docker inspect \
		--format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' \
		"$container_id" 2>/dev/null || true
}

print_service_debug() {
	service="$1"

	compose ps "$service" >&2 || true
	compose logs --tail=80 "$service" >&2 || true
}

service_host_port() {
	service="$1"
	container_port="$2"
	fallback_port="$3"
	endpoint=$(compose port "$service" "$container_port" 2>/dev/null || true)
	endpoint=$(printf '%s\n' "$endpoint" | sed -n '1p')

	if [ -n "$endpoint" ]; then
		printf '%s\n' "${endpoint##*:}"
	else
		printf '%s\n' "$fallback_port"
	fi
}

refresh_nexus_base_url() {
	host_port=$(service_host_port nexus 8081 "$NEXUS_OSS_PORT")
	NEXUS_BASE_URL="http://127.0.0.1:${host_port}"
}

refresh_proxy_base_url() {
	host_port=$(service_host_port nexus-sec-proxy 3000 "$NEXUS_SEC_PROXY_PORT")
	PROXY_BASE_URL="http://127.0.0.1:${host_port}"
}

wait_for_healthy() {
	service="$1"
	timeout_secs="$2"
	started_at=$(date +%s)

	log "waiting for ${service} to become healthy"

	while :; do
		container_id=$(compose ps -q "$service" 2>/dev/null || true)
		if [ -n "$container_id" ]; then
			state=$(container_state "$container_id")
			health=$(container_health "$container_id")

			if [ "$health" = "healthy" ]; then
				log "${service} is healthy"
				return 0
			fi

			if [ "$health" = "none" ] && [ "$state" = "running" ]; then
				log "${service} is running"
				return 0
			fi

			if [ "$state" = "exited" ] || [ "$state" = "dead" ]; then
				print_service_debug "$service"
				die "${service} stopped before becoming healthy"
			fi
		fi

		now=$(date +%s)
		if [ $((now - started_at)) -ge "$timeout_secs" ]; then
			print_service_debug "$service"
			die "timed out waiting for ${service} after ${timeout_secs}s"
		fi

		sleep 2
	done
}

curl_nexus_catalog() {
	output_file="$1"

	if [ -n "${NEXUS_SEC_PROXY_NEXUS_USERNAME:-}" ]; then
		curl -fsS \
			-u "${NEXUS_SEC_PROXY_NEXUS_USERNAME}:${NEXUS_SEC_PROXY_NEXUS_PASSWORD:-}" \
			-o "$output_file" \
			"${NEXUS_BASE_URL}/service/rest/v1/repositories"
	else
		curl -fsS \
			-o "$output_file" \
			"${NEXUS_BASE_URL}/service/rest/v1/repositories"
	fi
}

nexus_catalog_has_repositories() {
	grep -Eq '"name"[[:space:]]*:' "$1"
}

read_generated_nexus_admin_password() {
	container_id=$(compose ps -q nexus 2>/dev/null || true)
	if [ -z "$container_id" ]; then
		return 1
	fi

	docker exec "$container_id" sh -c 'cat /nexus-data/admin.password 2>/dev/null' \
		| tr -d '\r\n'
}

remember_generated_nexus_admin_password() {
	NEXUS_ADMIN_USERNAME=admin
	NEXUS_ADMIN_PASSWORD="$1"
}

capture_generated_nexus_admin_password() {
	if [ -n "$NEXUS_ADMIN_PASSWORD" ]; then
		return 0
	fi

	generated_password=$(read_generated_nexus_admin_password || true)
	if [ -n "$generated_password" ]; then
		remember_generated_nexus_admin_password "$generated_password"
	fi
}

wait_for_nexus_catalog_access() {
	started_at=$(date +%s)
	announced_generated_password=0
	announced_empty_catalog=0

	log "waiting for Nexus repository catalog access"
	NEXUS_CATALOG_FILE=$(mktemp "${TMPDIR:-/tmp}/nexus-sec-proxy-catalog.XXXXXX")

	if [ -z "${NEXUS_SEC_PROXY_NEXUS_USERNAME:-}" ] \
		&& [ -n "${NEXUS_SEC_PROXY_NEXUS_PASSWORD:-}" ]; then
		NEXUS_SEC_PROXY_NEXUS_USERNAME=admin
		export NEXUS_SEC_PROXY_NEXUS_USERNAME
		NEXUS_CREDENTIALS_SOURCE=configured
	fi

	while :; do
		if curl_nexus_catalog "$NEXUS_CATALOG_FILE" >/dev/null 2>&1; then
			if nexus_catalog_has_repositories "$NEXUS_CATALOG_FILE"; then
				if [ -n "${NEXUS_SEC_PROXY_NEXUS_USERNAME:-}" ]; then
					if [ "$NEXUS_CREDENTIALS_SOURCE" = "none" ]; then
						NEXUS_CREDENTIALS_SOURCE=configured
					fi
					log "Nexus repository catalog has repositories with configured credentials"
				else
					log "Nexus repository catalog has repositories without credentials"
				fi
				return 0
			fi

			if [ "$announced_empty_catalog" -eq 0 ]; then
				log "Nexus repository catalog is reachable but empty; waiting for repositories"
				announced_empty_catalog=1
			fi
		fi

		if [ -z "${NEXUS_SEC_PROXY_NEXUS_USERNAME:-}" ] \
			&& [ -z "${NEXUS_SEC_PROXY_NEXUS_PASSWORD:-}" ]; then
			generated_password=$(read_generated_nexus_admin_password || true)
			if [ -n "$generated_password" ]; then
				remember_generated_nexus_admin_password "$generated_password"
				NEXUS_SEC_PROXY_NEXUS_USERNAME=admin
				NEXUS_SEC_PROXY_NEXUS_PASSWORD="$generated_password"
				NEXUS_CREDENTIALS_SOURCE=generated
				export NEXUS_SEC_PROXY_NEXUS_USERNAME
				export NEXUS_SEC_PROXY_NEXUS_PASSWORD

				if [ "$announced_generated_password" -eq 0 ]; then
					log "using generated Nexus admin password for catalog access"
					announced_generated_password=1
				fi
			fi
		fi

		now=$(date +%s)
		if [ $((now - started_at)) -ge "$CATALOG_TIMEOUT_SECS" ]; then
			print_service_debug nexus
			die "Nexus repository catalog is not reachable; set NEXUS_SEC_PROXY_NEXUS_USERNAME and NEXUS_SEC_PROXY_NEXUS_PASSWORD if this Nexus volume was already initialized"
		fi

		sleep 3
	done
}

print_access_summary() {
	printf '\n'
	printf 'Access:\n'
	printf '  Nexus: %s\n' "$NEXUS_BASE_URL"
	printf '  Proxy: %s\n' "$PROXY_BASE_URL"
	printf '  Proxy admin UI: %s/admin\n' "$PROXY_BASE_URL"
	printf '  Proxy admin bearer token: %s\n' "$NEXUS_SEC_PROXY_ADMIN_TOKEN"
	printf '  Proxy admin auth header: Authorization: Bearer %s\n' "$NEXUS_SEC_PROXY_ADMIN_TOKEN"

	case "$PROXY_ADMIN_TOKEN_SOURCE" in
		default)
			printf '  Proxy admin token source: built-in e2e default\n'
			;;
		e2e-configured)
			printf '  Proxy admin token source: NEXUS_SEC_PROXY_E2E_ADMIN_TOKEN\n'
			;;
		configured)
			printf '  Proxy admin token source: NEXUS_SEC_PROXY_ADMIN_TOKEN\n'
			;;
	esac

	if [ -n "$NEXUS_ADMIN_PASSWORD" ]; then
		printf '\n'
		printf 'Nexus admin credentials:\n'
		printf '  Username: %s\n' "$NEXUS_ADMIN_USERNAME"
		printf '  Password: %s\n' "$NEXUS_ADMIN_PASSWORD"
	elif [ "$NEXUS_CREDENTIALS_SOURCE" = "configured" ]; then
		printf '\n'
		printf 'Nexus catalog credentials:\n'
		printf '  Username: %s\n' "$NEXUS_SEC_PROXY_NEXUS_USERNAME"
		printf '  Password: from NEXUS_SEC_PROXY_NEXUS_PASSWORD\n'
	fi

	printf '\n'
	printf 'Useful commands:\n'
	printf '  docker compose -f %s ps\n' "$COMPOSE_FILE"
	printf '  docker compose -f %s logs -f nexus-sec-proxy\n' "$COMPOSE_FILE"
	printf '  docker compose -f %s down\n' "$COMPOSE_FILE"
}

wait_for_proxy_healthz() {
	started_at=$(date +%s)

	log "waiting for proxy health endpoint"

	while :; do
		if curl -fsS -o /dev/null "${PROXY_BASE_URL}/healthz" >/dev/null 2>&1; then
			log "proxy health endpoint is reachable"
			return 0
		fi

		now=$(date +%s)
		if [ $((now - started_at)) -ge "$PROXY_TIMEOUT_SECS" ]; then
			print_service_debug nexus-sec-proxy
			die "proxy health endpoint is not reachable after ${PROXY_TIMEOUT_SECS}s"
		fi

		sleep 2
	done
}

verify_trust_report_block() {
	TRUST_BLOCK_BODY_FILE=$(mktemp)
	TRUST_REPORT_FILE=$(mktemp)
	target_path="/repository/maven-central/org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.jar"

	log "verifying enforced block and Trust report"
	status=$(curl -sS \
		-o "$TRUST_BLOCK_BODY_FILE" \
		-w '%{http_code}' \
		"${PROXY_BASE_URL}${target_path}")
	if [ "$status" != "403" ]; then
		cat "$TRUST_BLOCK_BODY_FILE" >&2
		print_service_debug nexus-sec-proxy
		die "expected vulnerable package request to return 403, got ${status}"
	fi

	report_url=$(sed -n 's/^Full report: //p' "$TRUST_BLOCK_BODY_FILE" \
		| tr -d '\r' \
		| sed -n '1p')
	if [ -z "$report_url" ]; then
		cat "$TRUST_BLOCK_BODY_FILE" >&2
		die "blocked response did not include a Trust report URL"
	fi

	curl -fsS -o "$TRUST_REPORT_FILE" "$report_url"
	grep -Fq '<span>Trust</span>' "$TRUST_REPORT_FILE" \
		|| die "Trust report page does not contain the Trust header"
	grep -Fq 'log4j-core@2.14.1' "$TRUST_REPORT_FILE" \
		|| die "Trust report page does not contain the blocked target"
	log "Trust report is reachable at ${report_url}"
}

while [ "$#" -gt 0 ]; do
	case "$1" in
		--no-build)
			BUILD_IMAGES=0
			;;
		--no-prime-scanner-db)
			PRIME_SCANNER_DB=0
			;;
		--no-start-scanner-db-updater)
			START_SCANNER_DB_UPDATER=0
			;;
		-h|--help)
			usage
			exit 0
			;;
		*)
			usage >&2
			die "unknown option: $1"
			;;
	esac
	shift
done

require_command docker
require_command curl

cd "$REPO_ROOT"
load_dotenv_defaults
configure_proxy_admin_token

COMPOSE_FILE="${NEXUS_SEC_PROXY_E2E_COMPOSE_FILE:-$REPO_ROOT/e2e.compose.yaml}"
NEXUS_TIMEOUT_SECS="${NEXUS_SEC_PROXY_E2E_NEXUS_TIMEOUT_SECS:-600}"
CATALOG_TIMEOUT_SECS="${NEXUS_SEC_PROXY_E2E_CATALOG_TIMEOUT_SECS:-180}"
PROXY_TIMEOUT_SECS="${NEXUS_SEC_PROXY_E2E_PROXY_TIMEOUT_SECS:-180}"
NEXUS_OSS_PORT="${NEXUS_OSS_PORT:-8081}"
NEXUS_SEC_PROXY_PORT="${NEXUS_SEC_PROXY_PORT:-3000}"
NEXUS_BASE_URL="http://127.0.0.1:${NEXUS_OSS_PORT}"
PROXY_BASE_URL="http://127.0.0.1:${NEXUS_SEC_PROXY_PORT}"

validate_timeout NEXUS_SEC_PROXY_E2E_NEXUS_TIMEOUT_SECS "$NEXUS_TIMEOUT_SECS"
validate_timeout NEXUS_SEC_PROXY_E2E_CATALOG_TIMEOUT_SECS "$CATALOG_TIMEOUT_SECS"
validate_timeout NEXUS_SEC_PROXY_E2E_PROXY_TIMEOUT_SECS "$PROXY_TIMEOUT_SECS"

if [ ! -f "$COMPOSE_FILE" ]; then
	die "compose file not found: $COMPOSE_FILE"
fi

log "validating compose file"
compose config >/dev/null

if [ "$BUILD_IMAGES" -eq 1 ]; then
	log "building e2e images"
	compose build nexus-sec-proxy scanner-db-updater
fi

log "starting Nexus"
compose up -d nexus
wait_for_healthy nexus "$NEXUS_TIMEOUT_SECS"
refresh_nexus_base_url
wait_for_nexus_catalog_access

if [ "$PRIME_SCANNER_DB" -eq 1 ]; then
	log "priming scanner database volumes"
	compose run --rm --no-deps scanner-db-updater once
fi

if [ "$START_SCANNER_DB_UPDATER" -eq 1 ]; then
	log "starting scanner DB updater"
	compose up -d scanner-db-updater
fi

log "starting nexus-sec-proxy"
compose up -d nexus-sec-proxy
wait_for_healthy nexus-sec-proxy "$PROXY_TIMEOUT_SECS"
refresh_proxy_base_url
wait_for_proxy_healthz
verify_trust_report_block
capture_generated_nexus_admin_password

log "e2e environment is ready"
print_access_summary
