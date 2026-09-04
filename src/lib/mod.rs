pub mod action_queue;
pub mod admin_auth;
pub mod app_api;
/// Phase-1 owner catalog (copy-install only; no package exec).
pub mod app_catalog;
pub mod totp;
/// Owner portal app mounts (`/apps/<slug>/`) registry and reverse proxy.
pub mod app_web;
pub mod crypto;
pub mod data_models;
pub mod dns_cache;
/// Wire-format fuzz entry points and mutational campaign (§8.2).
pub mod fuzz;
pub mod handlers;
pub mod http_server;
pub mod persistence;
pub mod scheduler;
pub mod thread_pool;
pub mod udp_listener;
pub mod wire;
pub mod writer;
