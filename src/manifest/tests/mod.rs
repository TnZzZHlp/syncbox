use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;

use iroh::{EndpointId, SecretKey};
use tempfile::TempDir;

use crate::types::{ClockState, HlcTimestamp, ShareId};

use super::*;

mod model;
mod path;
mod scan;
