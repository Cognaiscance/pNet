//! Installer agent: catalog + desired apps + status. Notify only for catalog apps.
//! `bootstrap` installs pNet + this agent from a local binary directory.

pub mod bootstrap;
pub mod catalog;
pub mod fabric;
pub mod proto;
pub mod state;
pub mod sync;
pub mod web;
