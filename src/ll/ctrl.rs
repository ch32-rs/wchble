//! LL Control PDU opcodes / handlers (stub).

/// Subset of LL Control opcodes used during bring-up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum LlCtrlOpcode {
    ConnectionUpdateInd = 0x00,
    ChannelMapInd = 0x01,
    TerminateInd = 0x02,
    EncReq = 0x03,
    EncRsp = 0x04,
    StartEncReq = 0x05,
    StartEncRsp = 0x06,
    UnknownRsp = 0x07,
    FeatureReq = 0x08,
    FeatureRsp = 0x09,
    VersionInd = 0x0c,
    ConnectionParamReq = 0x0f,
    ConnectionParamRsp = 0x10,
}
