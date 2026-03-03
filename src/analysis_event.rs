use std::time::Duration;

use crate::analyzer::{
    AlStatusCodeUpdate, ECDeviceError, ECError, ESMErrorDetail, ErrorCorrelation, StateTransition,
    WkcErrorDetail,
};

#[derive(Debug, Clone)]
pub enum AnalysisEventKind {
    FrameError,
    Address,
    Wkc,
    Esm,
    State,
    Al,
}

#[derive(Debug, Clone)]
pub struct AnalysisEvent {
    pub frame: u64,
    pub timestamp: Duration,
    pub kind: AnalysisEventKind,
    pub summary: String,
    pub details: Vec<String>,
}

impl AnalysisEvent {
    pub fn title(&self) -> &'static str {
        match self.kind {
            AnalysisEventKind::FrameError => "FRAME",
            AnalysisEventKind::Address => "ADDR",
            AnalysisEventKind::Wkc => "WKC",
            AnalysisEventKind::Esm => "ESM",
            AnalysisEventKind::State => "STATE",
            AnalysisEventKind::Al => "AL",
        }
    }
}

pub fn from_state_transition(tr: &StateTransition) -> AnalysisEvent {
    AnalysisEvent {
        frame: tr.packet_number,
        timestamp: tr.timestamp,
        kind: AnalysisEventKind::State,
        summary: format!("[{}] {} -> {}", tr.subdevice_id, tr.from, tr.to),
        details: vec!["Device state transition detected".to_string()],
    }
}

pub fn from_al_status_update(
    frame: u64,
    timestamp: Duration,
    update: &AlStatusCodeUpdate,
) -> AnalysisEvent {
    AnalysisEvent {
        frame,
        timestamp,
        kind: AnalysisEventKind::Al,
        summary: format!(
            "[{}] AL Status Code updated to 0x{:04x}",
            update.subdevice_id, update.al_status_code
        ),
        details: vec!["AL status code became available after an ESM error".to_string()],
    }
}

pub fn from_ec_error(error: ECError, correlations: &[ErrorCorrelation]) -> Vec<AnalysisEvent> {
    match error {
        ECError::InvalidDatagram {
            packet_number,
            timestamp,
            error,
        } => {
            vec![AnalysisEvent {
                frame: packet_number,
                timestamp,
                kind: AnalysisEventKind::FrameError,
                summary: error.to_string(),
                details: vec!["Invalid EtherCAT datagram".to_string()],
            }]
        }
        ECError::DeviceError(errors) => errors
            .into_iter()
            .map(|e| from_device_error(e, correlations))
            .collect(),
    }
}

fn from_device_error(error: ECDeviceError, correlations: &[ErrorCorrelation]) -> AnalysisEvent {
    match error {
        ECDeviceError::InvalidAutoIncrementAddress {
            packet_number,
            timestamp,
            command,
            address,
        } => AnalysisEvent {
            frame: packet_number,
            timestamp,
            kind: AnalysisEventKind::Address,
            summary: format!(
                "{} auto-increment {:#06x} not found",
                command.as_str(),
                address
            ),
            details: vec![
                "Auto-increment address does not map to known subdevice".to_string(),
                "Potential causes: topology change, disconnected subdevice".to_string(),
            ],
        },
        ECDeviceError::InvalidConfiguredAddress {
            packet_number,
            timestamp,
            command,
            address,
        } => AnalysisEvent {
            frame: packet_number,
            timestamp,
            kind: AnalysisEventKind::Address,
            summary: format!("{} configured {:#06x} not found", command.as_str(), address),
            details: vec![
                "Configured address does not map to known subdevice".to_string(),
                "Potential causes: not configured yet, address conflict".to_string(),
            ],
        },
        ECDeviceError::InvalidWkc(wkc) => from_wkc_error(wkc),
        ECDeviceError::ESMError(esm) => from_esm_error(esm, correlations),
    }
}

fn from_wkc_error(wkc: WkcErrorDetail) -> AnalysisEvent {
    let sub = wkc
        .subdevice_id
        .map(|s| s.to_string())
        .unwrap_or_else(|| "-".to_string());
    AnalysisEvent {
        frame: wkc.packet_number,
        timestamp: wkc.timestamp,
        kind: AnalysisEventKind::Wkc,
        summary: format!(
            "[{}] {} reg:{:#06x} len:{} expected:{} actual:{}",
            sub,
            wkc.command.as_str(),
            wkc.register,
            wkc.length,
            wkc.expected,
            wkc.actual
        ),
        details: vec![format!(
            "WKC cause: {}",
            wkc_cause_short(wkc.expected, wkc.actual)
        )],
    }
}

fn from_esm_error(esm: ESMErrorDetail, correlations: &[ErrorCorrelation]) -> AnalysisEvent {
    let mut details = vec![format!("ESM detail: {}", esm_error_short(&esm.error))];

    if let Some(code) = esm.al_status_code {
        details.push(format!("AL Status Code: 0x{:04x}", code));
    } else {
        details.push("AL Status Code: pending".to_string());
    }

    if let Some(corr) = find_correlation(&esm, correlations) {
        details.push(format!(
            "Correlated WKC: frame #{} expected:{} actual:{} reg:{:#06x}",
            corr.packet_number, corr.expected, corr.actual, corr.register
        ));
    }

    AnalysisEvent {
        frame: esm.packet_number,
        timestamp: esm.timestamp,
        kind: AnalysisEventKind::Esm,
        summary: format!("[{}] {}", esm.subdevice_id, esm.command.as_str()),
        details,
    }
}

fn find_correlation<'a>(
    esm: &ESMErrorDetail,
    correlations: &'a [ErrorCorrelation],
) -> Option<&'a WkcErrorDetail> {
    correlations
        .iter()
        .find(|c| {
            c.esm_error.packet_number == esm.packet_number
                && c.esm_error.subdevice_id == esm.subdevice_id
        })
        .map(|c| &c.wkc_error)
}

fn wkc_cause_short(expected: u16, actual: u16) -> &'static str {
    if actual == 0 {
        "no response"
    } else if actual < expected {
        "partial response"
    } else {
        "unexpected extra response"
    }
}

fn esm_error_short(err: &ecdump::subdevice::ESMError) -> String {
    use ecdump::subdevice::ESMError;

    match err {
        ESMError::IllegalTransition { to } => format!("illegal transition to {:?}", to),
        ESMError::InvalidStateTransition { requested, current } => {
            format!("requested {:?}, current {:?}", requested, current)
        }
        ESMError::BackwardTransition {
            from,
            to,
            has_error,
        } => {
            if *has_error {
                format!("backward transition {} -> {} (error flag set)", from, to)
            } else {
                format!("backward transition {} -> {}", from, to)
            }
        }
        ESMError::TransitionFailed {
            requested,
            current,
            has_error,
        } => {
            if *has_error {
                format!(
                    "transition to {:?} failed, current {:?} (error flag set)",
                    requested, current
                )
            } else {
                format!(
                    "transition to {:?} failed, current {:?}",
                    requested, current
                )
            }
        }
    }
}
