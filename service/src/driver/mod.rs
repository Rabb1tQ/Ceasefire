//! Driver communication module

pub mod handle;
pub mod ioctl;
pub mod converter;

pub use handle::{diags_raw_to_model, log_driver_diags, DriverHandle};
pub use ioctl::{IOCTL_ADD_RULE, IOCTL_REMOVE_RULE, IOCTL_UPDATE_RULE, IOCTL_CLEAR_RULES};
pub use converter::rule_to_driver_input;
