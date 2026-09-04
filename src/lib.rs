//! Provider-neutral building blocks for LLM Multiaccount Proxy.

#![forbid(unsafe_code)]

pub mod admin;
pub mod auth;
pub mod config;
pub mod data_plane;
pub mod egress;
pub mod forward_proxy;
pub mod http_app;
pub mod migration;
pub mod providers;
pub mod routing;
pub mod secrets;
pub mod storage;
