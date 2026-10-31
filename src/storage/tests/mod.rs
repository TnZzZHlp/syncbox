use std::{fs, io::Write as _};

use tempfile::TempDir;

use crate::types::ShareId;

use super::atomic::atomic_write_with;
use super::*;

mod atomic;
mod registry;
