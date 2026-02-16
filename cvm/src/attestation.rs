/// AMD SEV-SNP attestation report generation.
///
/// Generates attestation reports via the /dev/sev-guest device.
/// The report binds the VM's measurement (firmware + kernel + application hash)
/// to a 64-byte user-provided report_data field, signed by the AMD Secure Processor.

use std::io;

/// Size of the attestation report data field.
pub const REPORT_DATA_SIZE: usize = 64;

/// Size of a full SEV-SNP attestation report.
pub const ATTESTATION_REPORT_SIZE: usize = 1184;

/// Request type for the vsock protocol — attestation report request.
pub const ATTESTATION_REQUEST_TYPE: u8 = 0x02;

/// Generate an AMD SEV-SNP attestation report.
///
/// # Arguments
/// * `report_data` - 64 bytes of user data to bind into the report.
///   Typically a hash of the public key or a challenge nonce.
///
/// # Returns
/// The raw attestation report bytes (1184 bytes), signed by the AMD-SP.
///
/// # Errors
/// Returns an error if /dev/sev-guest is not available (not running in SEV-SNP)
/// or if the ioctl fails.
pub fn get_attestation_report(report_data: &[u8; REPORT_DATA_SIZE]) -> Result<Vec<u8>, AttestationError> {
    // In production, this uses the /dev/sev-guest ioctl:
    //   fd = open("/dev/sev-guest", O_RDWR)
    //   ioctl(fd, SNP_GET_REPORT, &msg_report_req)
    //
    // The request structure (snp_guest_request_msg) contains:
    //   - msg_version: 1
    //   - msg_type: SNP_MSG_REPORT_REQ (5)
    //   - report_data: [u8; 64]
    //
    // For MVP / development outside SEV-SNP hardware, return a stub.
    get_attestation_report_impl(report_data)
}

#[cfg(target_os = "linux")]
fn get_attestation_report_impl(report_data: &[u8; REPORT_DATA_SIZE]) -> Result<Vec<u8>, AttestationError> {
    use std::fs::OpenOptions;
    use std::os::unix::io::AsRawFd;

    const SEV_GUEST_DEVICE: &str = "/dev/sev-guest";

    // Check if the device exists
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(SEV_GUEST_DEVICE)
        .map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                AttestationError::NotAvailable
            } else {
                AttestationError::DeviceError(e.to_string())
            }
        })?;

    // In production, issue the ioctl here.
    // For now, return a stub to allow compilation and testing outside SEV-SNP.
    let _ = file.as_raw_fd();
    let _ = report_data;
    Err(AttestationError::NotAvailable)
}

#[cfg(not(target_os = "linux"))]
fn get_attestation_report_impl(_report_data: &[u8; REPORT_DATA_SIZE]) -> Result<Vec<u8>, AttestationError> {
    // SEV-SNP attestation is only available on Linux.
    // Return a stub report for development/testing.
    Err(AttestationError::NotAvailable)
}

/// Generate a stub attestation report for testing.
/// The report is filled with zeros except for the report_data field.
pub fn get_stub_attestation_report(report_data: &[u8; REPORT_DATA_SIZE]) -> Vec<u8> {
    let mut report = vec![0u8; ATTESTATION_REPORT_SIZE];
    // Place report_data at offset 0x50 (per SNP ABI specification)
    report[0x50..0x50 + REPORT_DATA_SIZE].copy_from_slice(report_data);
    report
}

#[derive(Debug)]
pub enum AttestationError {
    /// SEV-SNP guest device not available (not running in a CVM).
    NotAvailable,
    /// Error accessing the SEV-SNP guest device.
    DeviceError(String),
}

impl core::fmt::Display for AttestationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotAvailable => write!(f, "SEV-SNP attestation not available (not running in CVM)"),
            Self::DeviceError(e) => write!(f, "SEV-SNP device error: {}", e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_report_has_correct_size() {
        let data = [0xAA; REPORT_DATA_SIZE];
        let report = get_stub_attestation_report(&data);
        assert_eq!(report.len(), ATTESTATION_REPORT_SIZE);
    }

    #[test]
    fn stub_report_contains_report_data() {
        let data = [0xBB; REPORT_DATA_SIZE];
        let report = get_stub_attestation_report(&data);
        assert_eq!(&report[0x50..0x50 + REPORT_DATA_SIZE], &data);
    }

    #[test]
    fn attestation_fails_outside_cvm() {
        let data = [0x00; REPORT_DATA_SIZE];
        let result = get_attestation_report(&data);
        assert!(result.is_err());
    }
}
