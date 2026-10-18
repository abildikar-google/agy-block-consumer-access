#!/usr/bin/env bash
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# ==============================================================================
# Antigravity for Enterprise - Consumer Access Blocking Script
#
# Purpose:
#   Ensures enterprise developers authenticate through the Antigravity enterprise
#   login flow (governed by Google Cloud Terms of Service) and cannot fall into
#   the consumer login flow.
#
# Actions Performed:
#   1. GCP Authentication & Project Initialization:
#      Accepts Project ID (--project-id / -p) and Auth Principal (--principal / -u)
#      via CLI flags or interactive prompts, authenticates via 'gcloud auth login'
#      if needed, and configures the active gcloud account and project.
#   2. Network-Level Consumer Endpoint Block:
#      Blocks outbound access to the two consumer API hostnames:
#        - aicode.googleapis.com
#        - daily-cloudcode-pa.googleapis.com
#      Supports:
#        a) Google Cloud DNS Response Policy (VPC DNS sinkhole)
#        b) Google Cloud Next Generation Firewall (NGFW) Egress FQDN Deny Rules
#   3. Google Workspace Admin Console Guidance:
#      Displays step-by-step verification for disabling "Code Assist for
#      individuals" at admin.google.com.
#   4. End-to-End Verification & Reversible Rollback:
#      Verifies that consumer endpoints are unreachable while enterprise
#      endpoints remain accessible, and supports full rollback (--rollback).
# ==============================================================================

set -euo pipefail

# ==============================================================================
# Constants & Target Endpoints
# ==============================================================================
readonly CONSUMER_HOSTS=(
  "aicode.googleapis.com"
  "daily-cloudcode-pa.googleapis.com"
)

# Endpoints that MUST remain reachable for Enterprise Antigravity & Gemini API
readonly ENTERPRISE_VERIFY_HOSTS=(
  "businessaicode.googleapis.com"
  "cloudaicompanion.googleapis.com"
  "generativelanguage.googleapis.com"
)

# ==============================================================================
# Default Configuration Variables
# ==============================================================================
DRY_RUN="false"
ROLLBACK="false"
INTERACTIVE="true"

DEFAULT_PROJECT_ID="$(gcloud config get-value project 2>/dev/null || true)"
DEFAULT_AUTH_PRINCIPAL="$(gcloud auth list --filter="status:ACTIVE" --format="value(account)" 2>/dev/null | head -n 1 || true)"

# Modes: all, gcp-dns, gcp-firewall, verify
MODE="${MODE:-}"
PROJECT_ID="${PROJECT_ID:-}"
AUTH_PRINCIPAL="${AUTH_PRINCIPAL:-}"
VPC_NETWORKS="${VPC_NETWORKS:-}"
DNS_POLICY_NAME="${DNS_POLICY_NAME:-antigravity-consumer-block-rp}"
FIREWALL_POLICY_NAME="${FIREWALL_POLICY_NAME:-antigravity-consumer-block-fw}"
FIREWALL_RULE_PRIORITY="${FIREWALL_RULE_PRIORITY:-1000}"
GCLOUD_AUTH_DONE="false"

# Terminal formatting
if [[ -t 1 ]]; then
  readonly C_RESET="\033[0m"
  readonly C_BOLD="\033[1m"
  readonly C_GREEN="\033[32m"
  readonly C_YELLOW="\033[33m"
  readonly C_RED="\033[31m"
  readonly C_CYAN="\033[36m"
else
  readonly C_RESET=""
  readonly C_BOLD=""
  readonly C_GREEN=""
  readonly C_YELLOW=""
  readonly C_RED=""
  readonly C_CYAN=""
fi

# ==============================================================================
# Helper Functions
# ==============================================================================
log_info() {
  echo -e "${C_CYAN}[INFO]${C_RESET} $*"
}

log_success() {
  echo -e "${C_GREEN}[OK]${C_RESET} $*"
}

log_warn() {
  echo -e "${C_YELLOW}[WARN]${C_RESET} $*" >&2
}

log_error() {
  echo -e "${C_RED}[ERROR]${C_RESET} $*" >&2
}

log_section() {
  echo ""
  echo -e "${C_BOLD}==============================================================================${C_RESET}"
  echo -e "${C_BOLD}$*${C_RESET}"
  echo -e "${C_BOLD}==============================================================================${C_RESET}"
}

run_cmd() {
  if [[ "${DRY_RUN}" == "true" ]]; then
    echo -e "${C_YELLOW}[DRY-RUN]${C_RESET} Would execute: $*"
    return 0
  fi
  log_info "Executing: $*"
  "$@"
}

usage() {
  cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Automates network-level blocking of Antigravity consumer endpoints
(aicode.googleapis.com, daily-cloudcode-pa.googleapis.com) and verifies
endpoint reachability so enterprise developers stay on Google Cloud ToS.

Options:
  -m, --mode <MODE>                  Execution mode (required if non-interactive):
                                       gcp-dns      : Block via Cloud DNS Response Policy on VPC(s)
                                       gcp-firewall : Block via Cloud NGFW Egress FQDN Deny Rule on VPC(s)
                                       verify       : Verify consumer endpoints are blocked & enterprise works
                                       all          : Run gcp-dns, gcp-firewall, and verify
  -p, --project, --project-id <ID>   Google Cloud Project ID (default: active gcloud project)
  -u, --principal, --account <EMAIL> Google Cloud principal / user email to authenticate as
                                     (default: active gcloud account)
  -n, --networks <VPC1,VPC2>         Comma-separated VPC network names (default: default)
      --dns-policy <NAME>            Cloud DNS Response Policy name (default: ${DNS_POLICY_NAME})
      --fw-policy <NAME>             Global Network Firewall Policy name (default: ${FIREWALL_POLICY_NAME})
      --fw-priority <PRIORITY>       Firewall rule priority (default: ${FIREWALL_RULE_PRIORITY})
      --dry-run                      Preview all commands and changes without modifying any resources
      --rollback                     Reverse/remove the block rules for the selected mode
      --non-interactive              Do not prompt for interactive input
  -h, --help                         Show this help message and exit

Examples:
  # 1. Preview all GCP network blocking actions in Dry-Run mode:
  $(basename "$0") --mode all --project-id my-ent-project \\
    --principal admin@example.com --networks prod-vpc --dry-run

  # 2. Apply Cloud DNS sinkhole and Cloud Firewall Egress block on a VPC:
  $(basename "$0") --mode gcp-dns --project-id my-ent-project \\
    --principal admin@example.com --networks prod-vpc
  $(basename "$0") --mode gcp-firewall --project-id my-ent-project \\
    --principal admin@example.com --networks prod-vpc

  # 3. Verify that consumer endpoints are blocked and enterprise endpoints are unaffected:
  $(basename "$0") --mode verify --project-id my-ent-project --principal admin@example.com

  # 4. Rollback / remove the block rules:
  $(basename "$0") --mode all --project-id my-ent-project \\
    --principal admin@example.com --networks prod-vpc --rollback
EOF
}

# ==============================================================================
# Argument Parsing
# ==============================================================================
while [[ $# -gt 0 ]]; do
  case "$1" in
    -m|--mode)
      MODE="$2"
      shift 2
      ;;
    -p|--project|--project-id)
      PROJECT_ID="$2"
      shift 2
      ;;
    -u|--principal|--account|--username)
      AUTH_PRINCIPAL="$2"
      shift 2
      ;;
    -n|--networks)
      VPC_NETWORKS="$2"
      shift 2
      ;;
    --dns-policy)
      DNS_POLICY_NAME="$2"
      shift 2
      ;;
    --fw-policy)
      FIREWALL_POLICY_NAME="$2"
      shift 2
      ;;
    --fw-priority)
      FIREWALL_RULE_PRIORITY="$2"
      shift 2
      ;;
    --dry-run)
      DRY_RUN="true"
      shift
      ;;
    --rollback|--unblock)
      ROLLBACK="true"
      shift
      ;;
    --non-interactive)
      INTERACTIVE="false"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      log_error "Unknown argument: $1"
      usage
      exit 1
      ;;
  esac
done

# ==============================================================================
# Interactive Prompting (if needed)
# ==============================================================================
prompt_if_needed() {
  if [[ -z "${MODE}" ]]; then
    if [[ "${INTERACTIVE}" == "true" && -t 0 ]]; then
      echo "Select execution mode:"
      echo "  1) gcp-dns      - Block via Google Cloud DNS Response Policy (VPC Sinkhole)"
      echo "  2) gcp-firewall - Block via Google Cloud NGFW Egress FQDN Deny Rules"
      echo "  3) verify       - Verify consumer endpoints are blocked & enterprise works"
      echo "  4) all          - Execute gcp-dns, gcp-firewall, and verify"
      read -r -p "Enter choice [1-4, default: 3 (verify)]: " choice
      case "${choice:-3}" in
        1|gcp-dns) MODE="gcp-dns" ;;
        2|gcp-firewall) MODE="gcp-firewall" ;;
        3|verify) MODE="verify" ;;
        4|all) MODE="all" ;;
        *)
          log_error "Invalid selection: ${choice}"
          exit 1
          ;;
      esac
    else
      log_error "Mode (--mode) is required when running non-interactively."
      usage
      exit 1
    fi
  fi

  case "${MODE}" in
    gcp-dns|gcp-firewall|verify|all) ;;
    *)
      log_error "Invalid mode '${MODE}'. Valid modes: gcp-dns, gcp-firewall, verify, all."
      exit 1
      ;;
  esac

  if [[ -z "${PROJECT_ID}" ]]; then
    if [[ "${INTERACTIVE}" == "true" && -t 0 ]]; then
      read -r -p "Enter Google Cloud Project ID [${DEFAULT_PROJECT_ID}]: " input_proj || true
      PROJECT_ID="${input_proj:-${DEFAULT_PROJECT_ID}}"
    else
      PROJECT_ID="${DEFAULT_PROJECT_ID}"
    fi
  fi

  if [[ "${MODE}" =~ ^(gcp-dns|gcp-firewall|all)$ && -z "${PROJECT_ID}" ]]; then
    log_error "Google Cloud Project ID (--project-id) is required for mode '${MODE}'."
    exit 1
  fi

  if [[ -z "${AUTH_PRINCIPAL}" ]]; then
    if [[ "${INTERACTIVE}" == "true" && -t 0 ]]; then
      read -r -p "Enter GCP Principal / Account Email for authentication [${DEFAULT_AUTH_PRINCIPAL}]: " input_principal || true
      AUTH_PRINCIPAL="${input_principal:-${DEFAULT_AUTH_PRINCIPAL}}"
    else
      AUTH_PRINCIPAL="${DEFAULT_AUTH_PRINCIPAL}"
    fi
  fi

  if [[ -z "${VPC_NETWORKS}" ]]; then
    if [[ "${INTERACTIVE}" == "true" && -t 0 && "${MODE}" =~ ^(gcp-dns|gcp-firewall|all)$ ]]; then
      read -r -p "Enter target VPC network name(s) (comma-separated) [default]: " input_nets || true
      VPC_NETWORKS="${input_nets:-default}"
    else
      VPC_NETWORKS="default"
    fi
  fi
}

# ==============================================================================
# Pre-flight Authentication & Project Setup
# ==============================================================================
check_gcloud_prereqs() {
  if [[ "${GCLOUD_AUTH_DONE}" == "true" ]]; then
    return 0
  fi

  if ! command -v gcloud >/dev/null 2>&1; then
    log_error "Google Cloud CLI ('gcloud') is not installed or not in PATH."
    exit 1
  fi

  log_section "GCP Authentication & Project Configuration"

  if [[ -n "${AUTH_PRINCIPAL}" ]]; then
    local existing_cred=""
    existing_cred=$(gcloud auth list --filter="account:${AUTH_PRINCIPAL}" --format="value(account)" 2>/dev/null | head -n 1 || true)
    if [[ -n "${existing_cred}" ]]; then
      log_info "Found existing credentials for principal '${AUTH_PRINCIPAL}'. Setting as active account..."
      run_cmd gcloud config set account "${AUTH_PRINCIPAL}" --quiet
    else
      log_info "Principal '${AUTH_PRINCIPAL}' is not yet authenticated locally. Initiating 'gcloud auth login'..."
      run_cmd gcloud auth login "${AUTH_PRINCIPAL}" --brief
    fi
  else
    if [[ "${DRY_RUN}" != "true" ]]; then
      local active_account
      active_account=$(gcloud auth list --filter="status:ACTIVE" --format="value(account)" 2>/dev/null | head -n 1 || true)
      if [[ -z "${active_account}" ]]; then
        log_info "No active gcloud account found. Initiating 'gcloud auth login'..."
        run_cmd gcloud auth login --brief
        active_account=$(gcloud auth list --filter="status:ACTIVE" --format="value(account)" 2>/dev/null | head -n 1 || true)
      fi
      AUTH_PRINCIPAL="${active_account}"
    fi
  fi

  if [[ -n "${PROJECT_ID}" ]]; then
    log_info "Setting active Google Cloud project to '${PROJECT_ID}'..."
    run_cmd gcloud config set project "${PROJECT_ID}" --quiet
    if [[ "${DRY_RUN}" != "true" ]]; then
      local project_num=""
      project_num=$(gcloud projects describe "${PROJECT_ID}" --format="value(projectNumber)" 2>/dev/null || true)
      if [[ -z "${project_num}" ]]; then
        log_error "Project '${PROJECT_ID}' does not exist or is not accessible by '${AUTH_PRINCIPAL}'."
        exit 1
      fi
      log_success "Authenticated as '${AUTH_PRINCIPAL}' on project '${PROJECT_ID}' (Project Number: ${project_num})."
    fi
  fi

  GCLOUD_AUTH_DONE="true"
}

# Build full network self-links for Cloud DNS / Firewall associations
build_network_urls() {
  local project="$1"
  local networks_csv="$2"
  local urls=()
  IFS=',' read -r -a net_array <<< "${networks_csv}"
  for net in "${net_array[@]}"; do
    net=$(echo "${net}" | xargs)
    [[ -z "${net}" ]] && continue
    if [[ "${net}" == https://* || "${net}" == projects/* ]]; then
      urls+=("${net}")
    else
      urls+=("https://www.googleapis.com/compute/v1/projects/${project}/global/networks/${net}")
    fi
  done
  local IFS=','
  echo "${urls[*]}"
}

# ==============================================================================
# Action 1A: Google Cloud DNS Response Policy (VPC DNS Sinkhole)
# ==============================================================================
configure_gcp_dns() {
  check_gcloud_prereqs
  log_section "Network Control (Cloud DNS): Consumer Endpoint Sinkhole"

  local network_urls
  network_urls=$(build_network_urls "${PROJECT_ID}" "${VPC_NETWORKS}")

  if [[ "${ROLLBACK}" == "true" ]]; then
    log_info "Rolling back Cloud DNS Response Policy '${DNS_POLICY_NAME}' in project '${PROJECT_ID}'..."
    for idx in "${!CONSUMER_HOSTS[@]}"; do
      local host="${CONSUMER_HOSTS[$idx]}"
      local rule_name="block-${host//./-}"
      rule_name="${rule_name:0:63}"
      run_cmd gcloud dns response-policies rules delete "${rule_name}" \
        --response-policy="${DNS_POLICY_NAME}" \
        --project="${PROJECT_ID}" \
        --quiet \
        --no-user-output-enabled || true
    done
    run_cmd gcloud dns response-policies update "${DNS_POLICY_NAME}" \
      --networks="" \
      --project="${PROJECT_ID}" \
      --quiet \
      --no-user-output-enabled || true
    run_cmd gcloud dns response-policies delete "${DNS_POLICY_NAME}" \
      --project="${PROJECT_ID}" \
      --quiet \
      --no-user-output-enabled || true
    log_success "Cloud DNS Response Policy rollback complete."
    return 0
  fi

  log_info "Enabling Cloud DNS API (dns.googleapis.com) on project '${PROJECT_ID}'..."
  run_cmd gcloud services enable dns.googleapis.com --project="${PROJECT_ID}" --quiet

  local policy_exists="false"
  if [[ "${DRY_RUN}" != "true" ]]; then
    if gcloud dns response-policies describe "${DNS_POLICY_NAME}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
      policy_exists="true"
    fi
  fi

  if [[ "${policy_exists}" == "true" ]]; then
    log_info "Updating existing Cloud DNS Response Policy '${DNS_POLICY_NAME}' with networks: ${VPC_NETWORKS}"
    run_cmd gcloud dns response-policies update "${DNS_POLICY_NAME}" \
      --description="Blocks Antigravity consumer endpoints (aicode.googleapis.com, daily-cloudcode-pa.googleapis.com) to enforce Cloud ToS" \
      --networks="${network_urls}" \
      --project="${PROJECT_ID}" \
      --no-user-output-enabled
  else
    log_info "Creating Cloud DNS Response Policy '${DNS_POLICY_NAME}' attached to VPCs: ${VPC_NETWORKS}"
    run_cmd gcloud dns response-policies create "${DNS_POLICY_NAME}" \
      --description="Blocks Antigravity consumer endpoints (aicode.googleapis.com, daily-cloudcode-pa.googleapis.com) to enforce Cloud ToS" \
      --networks="${network_urls}" \
      --project="${PROJECT_ID}" \
      --no-user-output-enabled
  fi

  for host in "${CONSUMER_HOSTS[@]}"; do
    local rule_name="block-${host//./-}"
    rule_name="${rule_name:0:63}"
    local fqdn="${host}."
    local local_data_a="name=${fqdn},type=A,ttl=300,rrdatas=0.0.0.0"
    local local_data_aaaa="name=${fqdn},type=AAAA,ttl=300,rrdatas=::"

    local rule_exists="false"
    if [[ "${DRY_RUN}" != "true" ]]; then
      if gcloud dns response-policies rules describe "${rule_name}" \
        --response-policy="${DNS_POLICY_NAME}" \
        --project="${PROJECT_ID}" >/dev/null 2>&1; then
        rule_exists="true"
      fi
    fi

    if [[ "${rule_exists}" == "true" ]]; then
      log_info "Updating DNS sinkhole rule '${rule_name}' for ${fqdn} -> 0.0.0.0 (A) / :: (AAAA)"
      run_cmd gcloud dns response-policies rules update "${rule_name}" \
        --response-policy="${DNS_POLICY_NAME}" \
        --dns-name="${fqdn}" \
        --local-data="${local_data_a}" \
        --local-data="${local_data_aaaa}" \
        --project="${PROJECT_ID}" \
        --no-user-output-enabled
    else
      log_info "Creating DNS sinkhole rule '${rule_name}' for ${fqdn} -> 0.0.0.0 (A) / :: (AAAA)"
      run_cmd gcloud dns response-policies rules create "${rule_name}" \
        --response-policy="${DNS_POLICY_NAME}" \
        --dns-name="${fqdn}" \
        --local-data="${local_data_a}" \
        --local-data="${local_data_aaaa}" \
        --project="${PROJECT_ID}" \
        --no-user-output-enabled
    fi
  done

  log_success "Cloud DNS sinkhole configured for: ${CONSUMER_HOSTS[*]}"
}

# ==============================================================================
# Action 1B: Google Cloud Network Firewall Policy (Egress FQDN Deny)
# ==============================================================================
configure_gcp_firewall() {
  check_gcloud_prereqs
  log_section "Network Control (Cloud NGFW): Egress FQDN Deny Rule"

  local fqdn_list
  fqdn_list=$(IFS=','; echo "${CONSUMER_HOSTS[*]}")

  IFS=',' read -r -a net_array <<< "${VPC_NETWORKS}"

  if [[ "${ROLLBACK}" == "true" ]]; then
    log_info "Rolling back Global Network Firewall Policy '${FIREWALL_POLICY_NAME}' in project '${PROJECT_ID}'..."
    for net in "${net_array[@]}"; do
      net=$(echo "${net}" | xargs)
      [[ -z "${net}" ]] && continue
      local assoc_name="${FIREWALL_POLICY_NAME}-${net}"
      assoc_name="${assoc_name:0:63}"
      run_cmd gcloud compute network-firewall-policies associations delete \
        --firewall-policy="${FIREWALL_POLICY_NAME}" \
        --name="${assoc_name}" \
        --global-firewall-policy \
        --project="${PROJECT_ID}" \
        --quiet || true
    done

    run_cmd gcloud compute network-firewall-policies rules delete "${FIREWALL_RULE_PRIORITY}" \
      --firewall-policy="${FIREWALL_POLICY_NAME}" \
      --global-firewall-policy \
      --project="${PROJECT_ID}" \
      --quiet || true

    run_cmd gcloud compute network-firewall-policies delete "${FIREWALL_POLICY_NAME}" \
      --global \
      --project="${PROJECT_ID}" \
      --quiet || true

    log_success "Cloud Network Firewall Policy rollback complete."
    return 0
  fi

  log_info "Enabling Compute Engine API (compute.googleapis.com) on project '${PROJECT_ID}'..."
  run_cmd gcloud services enable compute.googleapis.com --project="${PROJECT_ID}" --quiet

  local fw_policy_exists="false"
  if [[ "${DRY_RUN}" != "true" ]]; then
    if gcloud compute network-firewall-policies describe "${FIREWALL_POLICY_NAME}" \
      --global --project="${PROJECT_ID}" >/dev/null 2>&1; then
      fw_policy_exists="true"
    fi
  fi

  if [[ "${fw_policy_exists}" == "false" ]]; then
    log_info "Creating Global Network Firewall Policy '${FIREWALL_POLICY_NAME}'..."
    run_cmd gcloud compute network-firewall-policies create "${FIREWALL_POLICY_NAME}" \
      --description="Blocks outbound traffic to Antigravity consumer API endpoints" \
      --global \
      --project="${PROJECT_ID}"
  else
    log_info "Global Network Firewall Policy '${FIREWALL_POLICY_NAME}' already exists."
  fi

  local rule_exists="false"
  if [[ "${DRY_RUN}" != "true" ]]; then
    if gcloud compute network-firewall-policies rules describe "${FIREWALL_RULE_PRIORITY}" \
      --firewall-policy="${FIREWALL_POLICY_NAME}" \
      --global-firewall-policy \
      --project="${PROJECT_ID}" >/dev/null 2>&1; then
      rule_exists="true"
    fi
  fi

  if [[ "${rule_exists}" == "true" ]]; then
    log_info "Updating Egress FQDN Deny rule (priority ${FIREWALL_RULE_PRIORITY}) for: ${fqdn_list}"
    run_cmd gcloud compute network-firewall-policies rules update "${FIREWALL_RULE_PRIORITY}" \
      --firewall-policy="${FIREWALL_POLICY_NAME}" \
      --global-firewall-policy \
      --action="deny" \
      --direction="EGRESS" \
      --dest-fqdns="${fqdn_list}" \
      --layer4-configs="tcp:443,udp:443" \
      --enable-logging \
      --description="Block Antigravity consumer login endpoints (${fqdn_list})" \
      --project="${PROJECT_ID}"
  else
    log_info "Creating Egress FQDN Deny rule (priority ${FIREWALL_RULE_PRIORITY}) for: ${fqdn_list}"
    run_cmd gcloud compute network-firewall-policies rules create "${FIREWALL_RULE_PRIORITY}" \
      --firewall-policy="${FIREWALL_POLICY_NAME}" \
      --global-firewall-policy \
      --action="deny" \
      --direction="EGRESS" \
      --dest-fqdns="${fqdn_list}" \
      --layer4-configs="tcp:443,udp:443" \
      --enable-logging \
      --description="Block Antigravity consumer login endpoints (${fqdn_list})" \
      --project="${PROJECT_ID}"
  fi

  for net in "${net_array[@]}"; do
    net=$(echo "${net}" | xargs)
    [[ -z "${net}" ]] && continue
    local assoc_name="${FIREWALL_POLICY_NAME}-${net}"
    assoc_name="${assoc_name:0:63}"
    log_info "Associating Firewall Policy '${FIREWALL_POLICY_NAME}' with VPC network '${net}'..."
    if [[ "${DRY_RUN}" == "true" ]]; then
      run_cmd gcloud compute network-firewall-policies associations create \
        --firewall-policy="${FIREWALL_POLICY_NAME}" \
        --network="${net}" \
        --name="${assoc_name}" \
        --global-firewall-policy \
        --project="${PROJECT_ID}"
    else
      if gcloud compute network-firewall-policies describe "${FIREWALL_POLICY_NAME}" \
        --global --project="${PROJECT_ID}" \
        --format="value(associations[].name)" 2>/dev/null | tr ';' '\n' | grep -qx "${assoc_name}"; then
        log_info "Association '${assoc_name}' already exists on network '${net}'."
      else
        run_cmd gcloud compute network-firewall-policies associations create \
          --firewall-policy="${FIREWALL_POLICY_NAME}" \
          --network="${net}" \
          --name="${assoc_name}" \
          --global-firewall-policy \
          --project="${PROJECT_ID}"
      fi
    fi
  done

  log_success "Cloud NGFW Egress FQDN Deny rule configured for: ${CONSUMER_HOSTS[*]}"
}

# ==============================================================================
# Action 2: Google Workspace Admin Console Control Guidance
# ==============================================================================
print_workspace_admin_guidance() {
  log_section "Google Workspace Admin Console Control (admin.google.com)"
  cat <<'EOF'
In addition to blocking the two consumer API hostnames at the network level,
disable "Code Assist for individuals" in the Google Workspace Admin Console:

  Reference: https://docs.cloud.google.com/gemini/docs/codeassist/control-individuals-access

  Required Admin Role:
    - Google Workspace Super Admin or Services Admin (with "Service Settings" privilege)

  Steps in https://admin.google.com:
    1. Sign in to https://admin.google.com with an administrator account.
    2. In the left navigation menu, click: Apps -> Additional Google Services -> Google Cloud Platform.
    3. Click on "Code Assist settings".
    4. Uncheck "Allow access to Code Assist for individuals" to block consumer/individual access.
    5. Click "Save".
EOF
}

# ==============================================================================
# Action 3: Verification ("How to verify it worked")
# ==============================================================================
verify_controls() {
  if [[ -n "${PROJECT_ID}" || -n "${AUTH_PRINCIPAL}" ]]; then
    check_gcloud_prereqs
  fi

  log_section "Verification: Consumer Endpoint Block & Enterprise Readiness"

  if [[ "${DRY_RUN}" == "true" ]]; then
    echo -e "${C_YELLOW}[DRY-RUN]${C_RESET} Would test DNS resolution and HTTPS connectivity to:"
    echo "  Blocked Consumer Endpoints (Expected: UNREACHABLE / 0.0.0.0):"
    for host in "${CONSUMER_HOSTS[@]}"; do
      echo "    - https://${host}"
    done
    echo "  Allowed Enterprise Endpoints (Expected: REACHABLE):"
    for host in "${ENTERPRISE_VERIFY_HOSTS[@]}"; do
      echo "    - https://${host}"
    done
    return 0
  fi

  local consumer_blocked_count=0
  echo -e "${C_BOLD}1. Checking Consumer Endpoints (Expected: BLOCKED / UNREACHABLE):${C_RESET}"
  for host in "${CONSUMER_HOSTS[@]}"; do
    local resolved_ip=""
    if command -v getent >/dev/null 2>&1; then
      resolved_ip=$(getent hosts "${host}" 2>/dev/null | awk '{print $1}' | head -n 1 || true)
    elif command -v dig >/dev/null 2>&1; then
      resolved_ip=$(dig +short "${host}" 2>/dev/null | tail -n 1 || true)
    fi

    # Test if sinkholed to 0.0.0.0 / 127.0.0.1 / :: or if curl fails to connect
    if [[ "${resolved_ip}" == "0.0.0.0" || "${resolved_ip}" == "127.0.0.1" || "${resolved_ip}" == "::" || "${resolved_ip}" == "::1" ]]; then
      log_success "${host} is sinkholed via DNS (${resolved_ip}) -> BLOCKED"
      consumer_blocked_count=$((consumer_blocked_count + 1))
    elif ! curl -sS -I --connect-timeout 5 --max-time 7 "https://${host}" >/dev/null 2>&1; then
      log_success "https://${host} is unreachable via HTTPS -> BLOCKED"
      consumer_blocked_count=$((consumer_blocked_count + 1))
    else
      log_warn "https://${host} is still REACHABLE from this machine (resolved IP: ${resolved_ip:-unknown})."
      log_warn "  -> Ensure this device is inside the protected VPC/network where Cloud DNS / Cloud NGFW rules apply."
    fi
  done

  echo ""
  echo -e "${C_BOLD}2. Checking Enterprise & Gemini API Endpoints (Expected: REACHABLE):${C_RESET}"
  for host in "${ENTERPRISE_VERIFY_HOSTS[@]}"; do
    if curl -sS -I --connect-timeout 5 --max-time 7 "https://${host}" >/dev/null 2>&1; then
      log_success "https://${host} is REACHABLE (Enterprise traffic unaffected)"
    else
      log_warn "https://${host} could not be reached. Check outbound internet/VPC access."
    fi
  done

  if [[ -n "${PROJECT_ID}" ]]; then
    echo ""
    echo -e "${C_BOLD}3. Checking GCP Network Policy Status on Project '${PROJECT_ID}':${C_RESET}"
    if gcloud dns response-policies describe "${DNS_POLICY_NAME}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
      local dns_rules
      dns_rules=$(gcloud dns response-policies rules list "${DNS_POLICY_NAME}" --project="${PROJECT_ID}" --format="value(ruleName,dnsName)" 2>/dev/null | tr '\n' ' ' || true)
      log_success "Cloud DNS Response Policy '${DNS_POLICY_NAME}' is ACTIVE (Rules: ${dns_rules:-none})."
    else
      log_info "Cloud DNS Response Policy '${DNS_POLICY_NAME}' not found on project '${PROJECT_ID}'."
    fi

    if gcloud compute network-firewall-policies describe "${FIREWALL_POLICY_NAME}" --global --project="${PROJECT_ID}" >/dev/null 2>&1; then
      local fw_assocs
      fw_assocs=$(gcloud compute network-firewall-policies describe "${FIREWALL_POLICY_NAME}" --global --project="${PROJECT_ID}" --format="value(associations[].name)" 2>/dev/null || true)
      log_success "Global Network Firewall Policy '${FIREWALL_POLICY_NAME}' is ACTIVE (Associations: ${fw_assocs:-none})."
    else
      log_info "Global Network Firewall Policy '${FIREWALL_POLICY_NAME}' not found on project '${PROJECT_ID}'."
    fi
  fi

  echo ""
  echo -e "${C_BOLD}4. Manual Spot-Check in Antigravity Client:${C_RESET}"
  echo "  [ ] Attempt the CONSUMER login flow in Antigravity -> model calls should fail/be unavailable."
  echo "  [ ] Confirm the ENTERPRISE login flow succeeds and everyday Antigravity functionality works."
}

# ==============================================================================
# Main Execution Flow
# ==============================================================================
main() {
  prompt_if_needed

  log_section "Antigravity for Enterprise - Consumer Access Guardrail"
  echo "  Mode:                 ${MODE}"
  echo "  Dry-Run:              ${DRY_RUN}"
  echo "  Rollback:             ${ROLLBACK}"
  echo "  GCP Project ID:       ${PROJECT_ID:-<not set>}"
  echo "  Auth Principal:       ${AUTH_PRINCIPAL:-<active gcloud account>}"
  echo "  Target VPC Networks:  ${VPC_NETWORKS}"
  echo "  Blocked Hostnames:    ${CONSUMER_HOSTS[*]}"

  case "${MODE}" in
    gcp-dns)
      configure_gcp_dns
      print_workspace_admin_guidance
      ;;
    gcp-firewall)
      configure_gcp_firewall
      print_workspace_admin_guidance
      ;;
    verify)
      verify_controls
      print_workspace_admin_guidance
      ;;
    all)
      configure_gcp_dns
      configure_gcp_firewall
      print_workspace_admin_guidance
      verify_controls
      ;;
  esac

  echo ""
  if [[ "${DRY_RUN}" == "true" ]]; then
    log_success "Dry-run completed successfully. Re-run without '--dry-run' to apply changes."
  else
    log_success "Execution completed successfully."
  fi
}

main "$@"
