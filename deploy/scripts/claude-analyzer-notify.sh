#!/bin/bash
# CheckMK Notification Script for Claude Alert Analyzer
# Sends alert data as JSON to the claude-checkmk-analyzer webhook.
#
# CheckMK provides notification data via environment variables prefixed with NOTIFY_
# See: https://docs.checkmk.com/latest/en/notifications.html#environment
#
# Installation:
#   Copy this script to /omd/sites/<site>/local/share/check_mk/notifications/
#   chmod +x claude-analyzer-notify.sh
#
# CheckMK Notification Rule Parameters:
#   Parameter 1: Webhook URL (default: http://claude-checkmk-analyzer.monitoring:8080/webhook)
#   Parameter 2: Webhook secret (required, must match WEBHOOK_SECRET env var of the analyzer)

set -euo pipefail

WEBHOOK_URL="${NOTIFY_PARAMETER_1:-http://claude-checkmk-analyzer.monitoring:8080/webhook}"
WEBHOOK_SECRET="${NOTIFY_PARAMETER_2:-}"

if [ -z "$WEBHOOK_SECRET" ]; then
  echo "ERROR: WEBHOOK_SECRET not set (pass as notification parameter 2)"
  exit 2
fi

# Build JSON payload from CheckMK environment variables (using jq for safe escaping)
PAYLOAD=$(jq -n \
  --arg hostname "${NOTIFY_HOSTNAME:-}" \
  --arg host_address "${NOTIFY_HOSTADDRESS:-}" \
  --arg service_description "${NOTIFY_SERVICEDESC:-}" \
  --arg service_state "${NOTIFY_SERVICESTATE:-}" \
  --arg service_output "${NOTIFY_SERVICEOUTPUT:-}" \
  --arg host_state "${NOTIFY_HOSTSTATE:-}" \
  --arg notification_type "${NOTIFY_NOTIFICATIONTYPE:-}" \
  --arg perf_data "${NOTIFY_SERVICEPERFDATA:-}" \
  --arg long_plugin_output "${NOTIFY_LONGSERVICEOUTPUT:-}" \
  --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  '{
    hostname: $hostname,
    host_address: $host_address,
    service_description: $service_description,
    service_state: $service_state,
    service_output: $service_output,
    host_state: $host_state,
    notification_type: $notification_type,
    perf_data: $perf_data,
    long_plugin_output: $long_plugin_output,
    timestamp: $timestamp
  }')

# Send to analyzer webhook
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST "$WEBHOOK_URL" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $WEBHOOK_SECRET" \
  -d "$PAYLOAD" \
  --connect-timeout 5 \
  --max-time 10)

if [ "$HTTP_CODE" -ge 200 ] && [ "$HTTP_CODE" -lt 300 ]; then
  echo "OK: Notification sent (HTTP $HTTP_CODE)"
  exit 0
elif [ "$HTTP_CODE" -eq 503 ]; then
  echo "WARN: Queue full (HTTP 503), will retry"
  exit 1
else
  echo "ERROR: Webhook returned HTTP $HTTP_CODE"
  exit 2
fi
