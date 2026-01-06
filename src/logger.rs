use crate::dhcp::DhcpRequest;
use anyhow::Result;
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::Mutex;

pub struct RequestLogger {
    file: Mutex<std::fs::File>,
}

impl RequestLogger {
    pub fn new(path: &str) -> Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;

        Ok(Self {
            file: Mutex::new(file),
        })
    }

    pub fn log(&self, request: &DhcpRequest) -> Result<()> {
        let json = serde_json::to_string(request)?;
        let mut file = self.file.lock().unwrap();
        writeln!(file, "{}", json)?;
        file.flush()?;
        Ok(())
    }
}
