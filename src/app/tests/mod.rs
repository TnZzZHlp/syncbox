use std::fs;

use tempfile::TempDir;

use crate::{
    identity, network,
    storage::DataPaths,
    types::{RuntimeState, RuntimeStatus, ShareId},
};

use super::*;

mod initial_sync;
mod isolation;
mod share_state;
mod status;
