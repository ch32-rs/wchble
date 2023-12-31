use crate::raw;
use num_enum::{FromPrimitive, IntoPrimitive};

// pub type bStatus_t = u8;
// SUCCESS(0x00):指令按预期执行。
// INVALIDPARAMETER(0x02):无效的连接句柄或请求字段。
// MSG_BUFFER_NOT_AVAIL (0x04):HCI 缓冲区不可用。请稍后重试。
// bleNotConnected(0x14):设备未连接。
// blePending(0x17):
// 当返回到客户端功能时，服务器或 GATT 子过程正在进行中，有待处理的响应。
// 返回服务器功能时，来自客户端的确认待处理。
// bleTimeout(0x16):上一个事务超时。重新连接之前，无法发送 ATT 或 GATT 消息。
// bleMemAllocError(0x13):发生内存分配错误
// bleLinkEncrypted(0x19):链接已加密。不要在加密的链接上发送包含身份验证签
/*
#define FAILURE                         0x01   //!< Failure
#define INVALIDPARAMETER                0x02   //!< Invalid request field
#define INVALID_TASK                    0x03   //!< Task ID isn't setup properly
#define MSG_BUFFER_NOT_AVAIL            0x04   //!< No buffer is available.
#define INVALID_MSG_POINTER             0x05   //!< No message pointer.
#define INVALID_EVENT_ID                0x06   //!< Invalid event id.
#define INVALID_TIMEOUT                 0x07   //!< Invalid timeout.
#define NO_TIMER_AVAIL                  0x08   //!< No event is available.
#define NV_OPER_FAILED                  0x0A   //!< read a data item to NV failed.
#define INVALID_MEM_SIZE                0x0B   //!< The tokens take up too much space and don't fit into Advertisement data and Scan Response Data

#define bleInvalidTaskID                INVALID_TASK  //!< Task ID isn't setup properly
#define bleEecKeyRequestRejected        0x06   //!< key missing
#define bleNotReady                     0x10   //!< Not ready to perform task
#define bleAlreadyInRequestedMode       0x11   //!< Already performing that task
#define bleIncorrectMode                0x12   //!< Not setup properly to perform that task
#define bleMemAllocError                0x13   //!< Memory allocation error occurred
#define bleNotConnected                 0x14   //!< Can't perform function when not in a connection
#define bleNoResources                  0x15   //!< There are no resource available
#define blePending                      0x16   //!< Waiting
#define bleTimeout                      0x17   //!< Timed out performing function
#define bleInvalidRange                 0x18   //!< A parameter is out of range
#define bleLinkEncrypted                0x19   //!< The link is already encrypted
#define bleProcedureComplete            0x1A   //!< The Procedure is completed
#define bleInvalidMtuSize               0x1B   //!< SDU size is larger than peer MTU.
 */

#[repr(u8)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, PartialEq, Eq, Clone, Copy, FromPrimitive, IntoPrimitive)]
pub enum RawError {
    /// This is not really an error, but is added here anyway, just in case someone mistakenly converts NRF_SUCCESS into RawError.
    Success = 0x00,

    #[num_enum(default)]
    Unknown = 0xFF,

    /// Failure
    Failure = 0x01,
    /// Invalid request field
    InvalidParameter = 0x02,
    /// Task ID isn't setup properly
    InvalidTask = 0x03,
    /// No buffer is available
    MsgBufferNotAvail = 0x04,
    /// No message pointer
    InvalidMsgPointer = 0x05,
    // /// Invalid event id
    // InvalidEventId = 0x06,
    /// Invalid timeout
    InvalidTimeout = 0x07,
    /// No event is available
    NoTimerAvail = 0x08,
    /// Read a data item to NV failed
    NvOperFailed = 0x0A,
    /// The tokens take up too much space and don't fit into Advertisement data and Scan Response Data
    InvalidMemSize = 0x0B,

    // BLE errors
    /// Key missing
    EecKeyRequestRejected = 0x06,
    /// Not ready to perform task
    NotReady = 0x10,
    /// Already performing that task
    AlreadyInRequestedMode = 0x11,
    /// Not setup properly to perform that task
    IncorrectMode = 0x12,
    /// Memory allocation error occurred
    MemAllocError = 0x13,
    /// Can't perform function when not in a connection
    NotConnected = 0x14,
    /// There are no resource available
    NoResources = 0x15,
    /// Waiting
    Pending = 0x16,
    /// Timed out performing function
    Timeout = 0x17,
    /// A parameter is out of range
    InvalidRange = 0x18,
    /// The link is already encrypted
    LinkEncrypted = 0x19,
    /// The Procedure is completed
    ProcedureComplete = 0x1A,
    /// SDU size is larger than peer MTU
    InvalidMtuSize = 0x1B,
}

impl RawError {
    pub fn convert(ret: u8) -> Result<(), RawError> {
        if ret == 0x00 {
            Ok(())
        } else {
            Err(RawError::from(ret))
        }
    }
}
