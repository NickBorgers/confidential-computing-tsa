/// Time engine for the CVM core.
///
/// Provides:
/// - SecureTSC reader (AMD SEV-SNP hardware clock)
/// - NTS client for periodic cross-validation
/// - Monotonic enforcement (timestamps never go backward)
/// - GeneralizedTime formatter for TSTInfo

use std::sync::atomic::{AtomicU64, Ordering};

/// Last issued timestamp in milliseconds since Unix epoch.
/// Used to enforce monotonicity.
static LAST_TIMESTAMP_MS: AtomicU64 = AtomicU64::new(0);

/// Read the hardware TSC via RDTSC instruction.
///
/// On AMD SEV-SNP with SecureTSC enabled, this returns a value calibrated
/// by the AMD Secure Processor. The hypervisor cannot intercept or manipulate it.
///
/// Returns the raw TSC counter value.
#[cfg(target_arch = "x86_64")]
pub fn read_tsc() -> u64 {
    // SAFETY: RDTSC is always available on x86_64 and reads a monotonic counter.
    // On SEV-SNP with SecureTSC, this is hardware-protected.
    unsafe {
        core::arch::x86_64::_rdtsc()
    }
}

#[cfg(not(target_arch = "x86_64"))]
pub fn read_tsc() -> u64 {
    // Fallback for non-x86_64 development. Not used in production.
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

/// TSC calibration data from the AMD Secure Processor.
/// Set at VM boot from the SEV-SNP launch parameters.
pub struct TscCalibration {
    /// TSC frequency in Hz (set by AMD-SP at VM launch).
    pub tsc_freq_hz: u64,
    /// TSC value at calibration time.
    pub tsc_at_calibration: u64,
    /// Unix timestamp (milliseconds) at calibration time.
    pub unix_ms_at_calibration: u64,
}

impl TscCalibration {
    /// Convert a raw TSC value to Unix time in milliseconds.
    pub fn tsc_to_unix_ms(&self, tsc: u64) -> u64 {
        let elapsed_ticks = tsc.wrapping_sub(self.tsc_at_calibration);
        let elapsed_ms = elapsed_ticks / (self.tsc_freq_hz / 1000);
        self.unix_ms_at_calibration + elapsed_ms
    }
}

/// NTS validation state.
///
/// In production, this manages authenticated NTP sessions with 4 NTS servers.
/// For MVP, this is a stub that trusts the system clock.
pub struct NtsState {
    /// Whether NTS validation has been performed at least once.
    pub validated: bool,
    /// Maximum observed drift between SecureTSC and NTS (milliseconds).
    pub max_drift_ms: u64,
    /// Drift tolerance threshold (milliseconds).
    pub tolerance_ms: u64,
}

impl NtsState {
    pub fn new(tolerance_ms: u64) -> Self {
        Self {
            validated: false,
            max_drift_ms: 0,
            tolerance_ms,
        }
    }

    /// Check if the time source is currently valid.
    pub fn is_valid(&self) -> bool {
        self.validated && self.max_drift_ms <= self.tolerance_ms
    }
}

/// Get the current Unix timestamp in milliseconds, enforcing monotonicity.
///
/// In production, this reads SecureTSC and applies calibration.
/// For MVP (development outside SEV-SNP), falls back to system clock.
pub fn current_time_ms() -> u64 {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_millis() as u64;

    // Enforce monotonicity: never return a timestamp less than the last one issued.
    loop {
        let last = LAST_TIMESTAMP_MS.load(Ordering::Acquire);
        let ts = if now_ms > last { now_ms } else { last + 1 };
        match LAST_TIMESTAMP_MS.compare_exchange(last, ts, Ordering::Release, Ordering::Relaxed) {
            Ok(_) => return ts,
            Err(_) => continue, // Concurrent update; retry.
        }
    }
}

/// Format a Unix timestamp (milliseconds) as a GeneralizedTime string.
///
/// Output format: "YYYYMMDDHHMMSS.mmmZ" (exactly 19 bytes).
/// Example: "20260215120000.123Z"
pub fn format_generalized_time(unix_ms: u64) -> [u8; 19] {
    let secs = unix_ms / 1000;
    let millis = (unix_ms % 1000) as u32;

    // Convert seconds to calendar date/time.
    // Simple implementation — no leap second handling (UTC doesn't observe them in timestamps).
    let (year, month, day, hour, minute, second) = unix_secs_to_datetime(secs);

    let mut buf = [0u8; 19];
    write_decimal(&mut buf[0..4], year as u32, 4);
    write_decimal(&mut buf[4..6], month as u32, 2);
    write_decimal(&mut buf[6..8], day as u32, 2);
    write_decimal(&mut buf[8..10], hour as u32, 2);
    write_decimal(&mut buf[10..12], minute as u32, 2);
    write_decimal(&mut buf[12..14], second as u32, 2);
    buf[14] = b'.';
    write_decimal(&mut buf[15..18], millis, 3);
    buf[18] = b'Z';
    buf
}

/// Write a decimal number into a fixed-width ASCII buffer (zero-padded).
fn write_decimal(buf: &mut [u8], mut value: u32, width: usize) {
    for i in (0..width).rev() {
        buf[i] = b'0' + (value % 10) as u8;
        value /= 10;
    }
}

/// Convert Unix seconds to (year, month, day, hour, minute, second).
///
/// Handles dates from 1970 to 9999. No leap-second awareness (standard for GeneralizedTime).
fn unix_secs_to_datetime(secs: u64) -> (u16, u8, u8, u8, u8, u8) {
    let second = (secs % 60) as u8;
    let mins_total = secs / 60;
    let minute = (mins_total % 60) as u8;
    let hours_total = mins_total / 60;
    let hour = (hours_total % 24) as u8;
    let mut days = (hours_total / 24) as u32;

    // Calculate year and remaining days
    let mut year: u16 = 1970;
    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if days < days_in_year {
            break;
        }
        days -= days_in_year;
        year += 1;
    }

    // Calculate month and day
    let months_days: [u32; 12] = if is_leap_year(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut month: u8 = 1;
    for &md in &months_days {
        if days < md {
            break;
        }
        days -= md;
        month += 1;
    }

    let day = days as u8 + 1; // days are 1-based

    (year, month, day, hour, minute, second)
}

fn is_leap_year(year: u16) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_epoch() {
        let gt = format_generalized_time(0);
        assert_eq!(&gt, b"19700101000000.000Z");
    }

    #[test]
    fn format_known_date() {
        // 2026-02-15 12:00:00.000 UTC
        // Unix timestamp: 1771070400000 ms
        let unix_ms = 1_771_070_400_000;
        let gt = format_generalized_time(unix_ms);
        assert_eq!(&gt, b"20260215120000.000Z");
    }

    #[test]
    fn format_with_millis() {
        // 2026-02-15 12:00:00.123 UTC
        let unix_ms = 1_771_070_400_123;
        let gt = format_generalized_time(unix_ms);
        assert_eq!(&gt, b"20260215120000.123Z");
    }

    #[test]
    fn format_leap_year() {
        // 2024-02-29 00:00:00.000 UTC (leap year)
        let unix_ms = 1_709_164_800_000;
        let gt = format_generalized_time(unix_ms);
        assert_eq!(&gt, b"20240229000000.000Z");
    }

    #[test]
    fn format_end_of_year() {
        // 2025-12-31 23:59:59.999 UTC
        let unix_ms = 1_767_225_599_999;
        let gt = format_generalized_time(unix_ms);
        assert_eq!(&gt, b"20251231235959.999Z");
    }

    #[test]
    fn monotonic_enforcement() {
        // Reset atomic for test isolation
        LAST_TIMESTAMP_MS.store(0, Ordering::SeqCst);

        let t1 = current_time_ms();
        let t2 = current_time_ms();
        let t3 = current_time_ms();
        assert!(t2 >= t1);
        assert!(t3 >= t2);
    }

    #[test]
    fn tsc_calibration_conversion() {
        let cal = TscCalibration {
            tsc_freq_hz: 2_000_000_000, // 2 GHz
            tsc_at_calibration: 1_000_000_000,
            unix_ms_at_calibration: 1_771_070_400_000,
        };

        // 1 second later = 2 billion ticks later
        let tsc_later = 1_000_000_000 + 2_000_000_000;
        let ms = cal.tsc_to_unix_ms(tsc_later);
        assert_eq!(ms, 1_771_070_401_000);
    }

    #[test]
    fn unix_secs_to_datetime_epoch() {
        let (y, m, d, h, min, s) = unix_secs_to_datetime(0);
        assert_eq!((y, m, d, h, min, s), (1970, 1, 1, 0, 0, 0));
    }

    #[test]
    fn unix_secs_to_datetime_2026() {
        // 2026-02-15 12:00:00 UTC = 1771070400
        let (y, m, d, h, min, s) = unix_secs_to_datetime(1_771_070_400);
        assert_eq!((y, m, d, h, min, s), (2026, 2, 15, 12, 0, 0));
    }
}
