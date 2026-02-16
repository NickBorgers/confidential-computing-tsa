#!/bin/bash
set -euo pipefail

PASS=0
FAIL=0

run_test() {
  local name="$1"
  shift
  echo "=== TEST: $name ==="
  if "$@"; then
    echo "PASS: $name"
    ((PASS++))
  else
    echo "FAIL: $name"
    ((FAIL++))
  fi
  echo ""
}

# Test 1: vTPM device present
test_vtpm_present() {
  [ -c /dev/tpm0 ]
}

# Test 2: SEV reported in kernel logs
test_sev_in_dmesg() {
  dmesg | grep -qi "SEV"
}

# Test 3: SEV-SNP memory encryption active
test_sev_snp_active() {
  dmesg | grep -qi "SEV-SNP"
}

# Test 4: Extract SNP report from vTPM NV index
test_snp_report_readable() {
  tpm2_nvread 0x01400001 -s 32 > /tmp/snp_report_sample.bin 2>/dev/null
  [ -s /tmp/snp_report_sample.bin ]
}

# Test 5: SNP report contains valid (non-zero) data
test_snp_report_nonzero() {
  local hex
  hex=$(xxd -p /tmp/snp_report_sample.bin | tr -d '\n')
  # Check that it's not all zeros
  [ "$hex" != "$(printf '%0*d' ${#hex} 0)" ]
}

# Test 6: Fetch VCEK certificate from Azure THIM endpoint
test_thim_vcek() {
  local response
  response=$(curl -s -H "Metadata: true" \
    "http://169.254.169.254/metadata/THIM/amd/certification" 2>/dev/null)
  # Response should contain vcekCert or certificate data
  echo "$response" | jq -e '.vcekCert' > /dev/null 2>&1 || \
  echo "$response" | jq -e '.certificateChain' > /dev/null 2>&1
}

# Test 7: Basic OS health check
test_os_health() {
  # Verify the system booted in confidential mode and basic services are running
  systemctl is-system-running --wait 2>/dev/null || true
  local state
  state=$(systemctl is-system-running 2>/dev/null || echo "unknown")
  [ "$state" = "running" ] || [ "$state" = "degraded" ]
}

echo "========================================="
echo "Confidential VM Attestation Tests"
echo "========================================="
echo ""

run_test "vTPM device present" test_vtpm_present
run_test "SEV reported in kernel logs" test_sev_in_dmesg
run_test "SEV-SNP memory encryption active" test_sev_snp_active
run_test "SNP report readable from vTPM" test_snp_report_readable
run_test "SNP report contains non-zero data" test_snp_report_nonzero
run_test "VCEK certificate from Azure THIM" test_thim_vcek
run_test "OS health check" test_os_health

echo "========================================="
echo "Results: $PASS passed, $FAIL failed"
echo "========================================="

if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
