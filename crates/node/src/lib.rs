//! The privmsg node as a library: messenger logic (`app`), encrypted profile
//! (`store`) and wire formats (`wire`). The `privmsg` binary is a command
//! line over it; the fuzz targets drive it directly.

pub mod app;
pub mod decoy;
pub mod store;
pub mod wire;
