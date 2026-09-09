//! WFP Engine management
//! 
//! Handles opening and closing the WFP engine session.

use super::super::error::{Result, ServiceError};
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::*;
use windows::Win32::Foundation::*;
use windows::Win32::System::Rpc::RPC_C_AUTHN_DEFAULT;
use std::ptr;

pub struct WfpEngine {
    engine_handle: HANDLE,
}

// engine_handle is a raw HANDLE (*mut c_void) which is not Send/Sync by
// default. A WFP engine handle is safe to use from any thread (the WFP API
// is thread-safe), and within this crate the handle is only touched through
// &self methods; storing WfpEngine in Arc<Mutex<Option<Arc<_>>>> for the IPC
// handler requires Send + Sync, so assert them here.
unsafe impl Send for WfpEngine {}
unsafe impl Sync for WfpEngine {}

impl WfpEngine {
    /// Open a new WFP engine session
    pub fn new() -> Result<Self> {
        tracing::info!("Opening WFP engine");
        
        let mut engine_handle = HANDLE::default();
        
        unsafe {
            let result = FwpmEngineOpen0(
                None,                    // serverName (NULL for local)
                RPC_C_AUTHN_DEFAULT as u32,     // authnService
                None,                    // authIdentity (NULL for current user)
                None,                    // session (NULL for default)
                &mut engine_handle,
            );
            
            if result != 0 {
                return Err(ServiceError::Wfp(format!(
                    "Failed to open WFP engine: error code 0x{:08X}",
                    result
                )));
            }
        }
        
        tracing::info!("WFP engine opened successfully");
        
        Ok(WfpEngine { engine_handle })
    }
    
    /// Get the engine handle
    pub fn handle(&self) -> HANDLE {
        self.engine_handle
    }
    
    /// Register the provider
    pub fn register_provider(&self) -> Result<()> {
        tracing::info!("Registering WFP provider");
        
        let provider_name = windows::core::w!("Ceasefire Firewall");
        let provider_description = windows::core::w!("Local firewall with network monitoring");
        
        let provider = FWPM_PROVIDER0 {
            providerKey: super::CEASEFIRE_PROVIDER_GUID,
            displayData: FWPM_DISPLAY_DATA0 {
                name: windows::core::PWSTR(provider_name.as_ptr() as *mut u16),
                description: windows::core::PWSTR(provider_description.as_ptr() as *mut u16),
            },
            flags: 0,
            providerData: FWP_BYTE_BLOB::default(),
            serviceName: windows::core::PWSTR(ptr::null_mut()),
        };
        
        unsafe {
            let result = FwpmProviderAdd0(self.engine_handle, &provider, None);
            
            // ERROR_FWP_ALREADY_EXISTS (0x80320009) is OK - provider already registered
            if result != 0 && result != 0x80320009 {
                return Err(ServiceError::Wfp(format!(
                    "Failed to register provider: error code 0x{:08X}",
                    result
                )));
            }
        }
        
        tracing::info!("WFP provider registered successfully");
        Ok(())
    }
    
    /// Register the sublayer
    pub fn register_sublayer(&self) -> Result<()> {
        tracing::info!("Registering WFP sublayer");
        
        let sublayer_name = windows::core::w!("Ceasefire Sublayer");
        let sublayer_description = windows::core::w!("Sublayer for Ceasefire firewall filters");
        
        let sublayer = FWPM_SUBLAYER0 {
            subLayerKey: super::CEASEFIRE_SUBLAYER_GUID,
            displayData: FWPM_DISPLAY_DATA0 {
                name: windows::core::PWSTR(sublayer_name.as_ptr() as *mut u16),
                description: windows::core::PWSTR(sublayer_description.as_ptr() as *mut u16),
            },
            flags: 0,
            providerKey: &super::CEASEFIRE_PROVIDER_GUID as *const _ as *mut _,
            providerData: FWP_BYTE_BLOB::default(),
            weight: 0x8000, // Medium priority
        };
        
        unsafe {
            let result = FwpmSubLayerAdd0(self.engine_handle, &sublayer, None);
            
            // ERROR_FWP_ALREADY_EXISTS is OK
            if result != 0 && result != 0x80320009 {
                return Err(ServiceError::Wfp(format!(
                    "Failed to register sublayer: error code 0x{:08X}",
                    result
                )));
            }
        }
        
        tracing::info!("WFP sublayer registered successfully");
        Ok(())
    }
    
    /// Unregister provider and sublayer
    pub fn cleanup(&self) -> Result<()> {
        tracing::info!("Cleaning up WFP provider and sublayer");
        
        unsafe {
            // Delete sublayer (ignore errors)
            let _ = FwpmSubLayerDeleteByKey0(
                self.engine_handle,
                &super::CEASEFIRE_SUBLAYER_GUID,
            );
            
            // Delete provider (ignore errors)
            let _ = FwpmProviderDeleteByKey0(
                self.engine_handle,
                &super::CEASEFIRE_PROVIDER_GUID,
            );
        }
        
        tracing::info!("WFP cleanup completed");
        Ok(())
    }
}

impl Drop for WfpEngine {
    fn drop(&mut self) {
        if !self.engine_handle.is_invalid() {
            tracing::info!("Closing WFP engine");
            unsafe {
                let _ = FwpmEngineClose0(self.engine_handle);
            }
        }
    }
}
