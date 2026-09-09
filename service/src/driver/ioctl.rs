//! IOCTL codes and communication functions

use super::super::error::{Result, ServiceError};
use std::os::windows::io::AsRawHandle;
use windows::Win32::System::IO::DeviceIoControl;
use windows::Win32::Foundation::HANDLE;

// IOCTL Codes (must match driver definitions)
// CTL_CODE(FILE_DEVICE_NETWORK=0x12, function, METHOD_BUFFERED=0, FILE_ANY_ACCESS=0)
pub const IOCTL_ADD_RULE: u32 = 0x00122004;      // 0x801 << 2
pub const IOCTL_REMOVE_RULE: u32 = 0x00122008;   // 0x802 << 2
pub const IOCTL_UPDATE_RULE: u32 = 0x0012200C;   // 0x803 << 2
pub const IOCTL_CLEAR_RULES: u32 = 0x00122010;   // 0x804 << 2
pub const IOCTL_GET_EVENT: u32 = 0x00122014;     // 0x805 << 2
pub const IOCTL_GET_DNS_EVENT: u32 = 0x00122018; // 0x806 << 2
pub const IOCTL_SET_DEFAULT_POLICY: u32 = 0x0012201C; // 0x807 << 2
pub const IOCTL_SET_THROTTLE: u32 = 0x00122020;       // 0x808 << 2
pub const IOCTL_GET_DIAGS: u32 = 0x00122024;         // 0x809 << 2
pub const IOCTL_CLEAR_THROTTLE: u32 = 0x00122028;    // 0x80A << 2

/// Raw layout of the driver's CF_DIAGS (IOCTL_GET_DIAGS output).
/// Field order/types mirror driver/inc/types.h exactly (natural alignment,
/// repr(C)); per-slot meanings follow CF_DIAG_SLOT_* there
/// (V4: 0=ale-connect 1=recv-accept 2=dns 3=stream 4=flow-established
///  5=outbound-transport 12=inbound-transport; V6 = same indices +6 where
///  applicable: 6..11 and 13).
///
/// v2 tail: unreg_status/unreg_retries (callout teardown results of the
/// current driver session). With a v1 driver the IOCTL copies fewer bytes
/// than this struct; the leftover tail stays zero because the struct is
/// zero-initialized, and get_diags_ioctl additionally re-zeroes the tail
/// when version < 2.
///
/// v3 tail: throttle_active_entries/throttle_notify_removes (kernel throttle
/// table process-exit cleanup; re-zeroed when version < 3).
///
/// v4 tail: in-transport (download shaping) classify/permit/block counters
/// plus the two new callouts' register/unregister status arrays (slots 12/13
/// kept out of the historical 12-slot arrays so the v1..v3 prefix layout is
/// byte-identical; re-zeroed when version < 4).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DriverDiagsRaw {
    pub magic: u32,
    pub version: u32,
    pub size: u32,
    pub reserved: u32,
    pub reg_status: [u32; 12],
    pub callout_id: [u32; 12],
    pub classify_stream: [u64; 2],
    pub classify_flow_est: [u64; 2],
    pub assoc_ok: [u64; 2],
    pub assoc_fail: [u64; 2],
    pub flow_delete: [u64; 2],
    pub stream_bytes_counted: [u64; 2],
    pub unreg_status: [u32; 12],
    pub unreg_retries: [u32; 12],
    pub throttle_active_entries: u32,
    pub throttle_notify_removes: u32,
    pub in_transport_classify: [u64; 2],
    pub in_transport_permit: [u64; 2],
    pub in_transport_block: [u64; 2],
    /// 入站传输层两个 callout 的注册/注销状态（[0]=V4 槽 12、[1]=V6 槽 13）
    pub in_transport_reg_status: [u32; 2],
    pub in_transport_callout_id: [u32; 2],
    pub in_transport_unreg_status: [u32; 2],
    pub in_transport_unreg_retries: [u32; 2],
    /// v5 tail: kernel pacing (clone-hold-timed-inject) counters
    /// (re-zeroed when version < 5).
    pub pacing_held: u64,
    pub pacing_injected: u64,
    pub pacing_inject_fail: u64,
    pub pacing_queue_drop: u64,
    pub pacing_queue_depth_max: u64,
    pub pacing_timer_ticks: u64,
}

/// Input payload of IOCTL_SET_THROTTLE. Wire layout must match the driver's
/// THROTTLE_INPUT (three u32s, 12 bytes, natural alignment).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DriverThrottleInput {
    pub process_id: u32,
    pub rate_up_bps: u32,
    pub rate_down_bps: u32,
}

/// Send IOCTL command to driver
pub fn send_ioctl(
    file: &std::fs::File,
    ioctl_code: u32,
    input_data: &[u8],
) -> Result<()> {
    let handle = HANDLE(file.as_raw_handle() as *mut _);
    
    unsafe {
        let mut bytes_returned = 0u32;
        DeviceIoControl(
            handle,
            ioctl_code,
            Some(input_data.as_ptr() as *const _),
            input_data.len() as u32,
            None,
            0,
            Some(&mut bytes_returned),
            None,
        ).map_err(|e| ServiceError::Driver(format!("DeviceIoControl failed: {}", e)))?;
    }

    Ok(())
}

/// Get event from driver using IOCTL
pub fn get_event_ioctl(file: &std::fs::File, output_buffer: &mut [u8]) -> Result<usize> {
    let handle = HANDLE(file.as_raw_handle() as *mut _);
    
    unsafe {
        let mut bytes_returned = 0u32;
        match DeviceIoControl(
            handle,
            IOCTL_GET_EVENT,
            None,
            0,
            Some(output_buffer.as_mut_ptr() as *mut _),
            output_buffer.len() as u32,
            Some(&mut bytes_returned),
            None,
        ) {
            Ok(_) => Ok(bytes_returned as usize),
            Err(e) => {
                let error_code = e.code().0;
                // ERROR_NO_MORE_ITEMS = 259
                // STATUS_NO_MORE_ENTRIES converted to HRESULT = -2147024637 (0x8007103)
                if error_code == 259 || error_code == -2147024637 {
                    Err(ServiceError::Driver("No event available".to_string()))
                } else {
                    Err(ServiceError::Io(std::io::Error::from_raw_os_error(error_code)))
                }
            }
        }
    }
}
/// Fetch the driver's diagnostics snapshot (IOCTL_GET_DIAGS).
/// Errors if the driver predates this IOCTL (STATUS_INVALID_DEVICE_REQUEST).
pub fn get_diags_ioctl(file: &std::fs::File) -> Result<DriverDiagsRaw> {
    let handle = HANDLE(file.as_raw_handle() as *mut _);
    let mut out = DriverDiagsRaw {
        magic: 0,
        version: 0,
        size: 0,
        reserved: 0,
        reg_status: [0; 12],
        callout_id: [0; 12],
        classify_stream: [0; 2],
        classify_flow_est: [0; 2],
        assoc_ok: [0; 2],
        assoc_fail: [0; 2],
        flow_delete: [0; 2],
        stream_bytes_counted: [0; 2],
        unreg_status: [0; 12],
        unreg_retries: [0; 12],
        throttle_active_entries: 0,
        throttle_notify_removes: 0,
        in_transport_classify: [0; 2],
        in_transport_permit: [0; 2],
        in_transport_block: [0; 2],
        in_transport_reg_status: [0; 2],
        in_transport_callout_id: [0; 2],
        in_transport_unreg_status: [0; 2],
        in_transport_unreg_retries: [0; 2],
        pacing_held: 0,
        pacing_injected: 0,
        pacing_inject_fail: 0,
        pacing_queue_drop: 0,
        pacing_queue_depth_max: 0,
        pacing_timer_ticks: 0,
    };

    unsafe {
        let mut bytes_returned = 0u32;
        DeviceIoControl(
            handle,
            IOCTL_GET_DIAGS,
            None,
            0,
            Some(&mut out as *mut _ as *mut _),
            std::mem::size_of::<DriverDiagsRaw>() as u32,
            Some(&mut bytes_returned),
            None,
        )
        .map_err(|e| ServiceError::Driver(format!("get diags DeviceIoControl failed: {}", e)))?;
    }

    if out.magic != 0x3047_4944 {
        return Err(ServiceError::Driver(format!(
            "driver diags magic mismatch: 0x{:08X}",
            out.magic
        )));
    }
    // 降级保护：v1 驱动的 IOCTL 只回填 v1 布局，尾部字段理论上保持零初始
    // 化值，但显式清零以防御任何非零残留（如栈复用）。v2 同理对 v3 尾部、
    // v3 对 v4 尾部清零。
    if out.version < 2 {
        out.unreg_status = [0; 12];
        out.unreg_retries = [0; 12];
    }
    if out.version < 3 {
        out.throttle_active_entries = 0;
        out.throttle_notify_removes = 0;
    }
    if out.version < 4 {
        out.in_transport_classify = [0; 2];
        out.in_transport_permit = [0; 2];
        out.in_transport_block = [0; 2];
        out.in_transport_reg_status = [0; 2];
        out.in_transport_callout_id = [0; 2];
        out.in_transport_unreg_status = [0; 2];
        out.in_transport_unreg_retries = [0; 2];
    }
    if out.version < 5 {
        out.pacing_held = 0;
        out.pacing_injected = 0;
        out.pacing_inject_fail = 0;
        out.pacing_queue_drop = 0;
        out.pacing_queue_depth_max = 0;
        out.pacing_timer_ticks = 0;
    }
    Ok(out)
}

/// Get next DNS event from driver. Returns Ok(0) when no event is available.
pub fn get_dns_event_ioctl(file: &std::fs::File, output_buffer: &mut [u8]) -> Result<usize> {
    let handle = HANDLE(file.as_raw_handle() as *mut _);

    unsafe {
        let mut bytes_returned = 0u32;
        match DeviceIoControl(
            handle,
            IOCTL_GET_DNS_EVENT,
            None,
            0,
            Some(output_buffer.as_mut_ptr() as *mut _),
            output_buffer.len() as u32,
            Some(&mut bytes_returned),
            None,
        ) {
            Ok(_) => Ok(bytes_returned as usize),
            Err(e) => {
                let error_code = e.code().0;
                if error_code == 259 || error_code == -2147024637 {
                    Ok(0)
                } else {
                    Err(ServiceError::Io(std::io::Error::from_raw_os_error(error_code)))
                }
            }
        }
    }
}
