/// Wrapper configuration: certificates, policy, and CVM connection settings.
/// Wrapper configuration loaded at startup.
pub struct WrapperConfig {
    /// DER-encoded ECDSA P-384 TSA certificate.
    pub ecdsa_cert_der: Vec<u8>,
    /// DER-encoded CA chain certificates.
    pub ca_chain_der: Vec<Vec<u8>>,
    /// Issuer DN from the ECDSA certificate (DER-encoded).
    pub issuer_der: Vec<u8>,
    /// Serial number from the ECDSA certificate (DER-encoded INTEGER).
    pub serial_number_der: Vec<u8>,
    /// TSA policy OID (as DER-encoded OID value bytes, without tag/length).
    pub policy_oid: Vec<u8>,
    /// CVM vsock CID (or 0 for TCP development mode).
    pub cvm_cid: u32,
    /// CVM port.
    pub cvm_port: u32,
    /// HTTP listen address.
    pub listen_addr: String,
}

impl Default for WrapperConfig {
    fn default() -> Self {
        Self {
            ecdsa_cert_der: Vec::new(),
            ca_chain_der: Vec::new(),
            issuer_der: Vec::new(),
            serial_number_der: vec![0x02, 0x01, 0x01], // INTEGER 1
            policy_oid: vec![0x2B, 0x06, 0x01, 0x04, 0x01, 0x00, 0x01], // placeholder
            cvm_cid: 0,
            cvm_port: 5000,
            listen_addr: "0.0.0.0:3000".to_string(),
        }
    }
}

impl WrapperConfig {
    /// Load configuration from environment variables and certificate files.
    pub fn from_env() -> Result<Self, ConfigError> {
        let mut config = Self::default();

        if let Ok(addr) = std::env::var("TSA_LISTEN_ADDR") {
            config.listen_addr = addr;
        }

        if let Ok(port) = std::env::var("CVM_PORT") {
            config.cvm_port = port
                .parse()
                .map_err(|_| ConfigError::InvalidValue("CVM_PORT".into()))?;
        }

        if let Ok(cid) = std::env::var("CVM_CID") {
            config.cvm_cid = cid
                .parse()
                .map_err(|_| ConfigError::InvalidValue("CVM_CID".into()))?;
        }

        // Certificate paths
        if let Ok(cert_path) = std::env::var("TSA_CERT_PATH") {
            config.ecdsa_cert_der = load_der_file(&cert_path)?;
        }

        if let Ok(ca_path) = std::env::var("TSA_CA_CHAIN_PATH") {
            config.ca_chain_der = vec![load_der_file(&ca_path)?];
        }

        Ok(config)
    }
}

/// Load a DER-encoded file.
fn load_der_file(path: &str) -> Result<Vec<u8>, ConfigError> {
    std::fs::read(path).map_err(|e| ConfigError::FileNotFound(format!("{}: {}", path, e)))
}

#[derive(Debug)]
pub enum ConfigError {
    FileNotFound(String),
    InvalidValue(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FileNotFound(p) => write!(f, "file not found: {}", p),
            Self::InvalidValue(k) => write!(f, "invalid value for {}", k),
        }
    }
}
