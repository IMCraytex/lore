// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//! Seeding the local store from files already on disk.
//!
//! A clone downloads every fragment it needs. When the same content is already
//! present locally — an export, an older checkout, a copy from a colleague —
//! those fragments can be produced from disk instead of the network.
//!
//! This is safe because fragments are content-addressed: seeding a file yields
//! the address its bytes hash to and nothing else. A stale or unrelated file
//! contributes an address no revision asks for, so a clone simply never reads
//! it. Nothing is deleted, moved, or overwritten — the seed directory is only
//! ever read.

use std::path::Path;
use std::sync::Arc;

use lore_error_set::prelude::*;
use serde::Deserialize;
use serde::Serialize;

use crate::errors::InvalidArguments;
use crate::event;
use crate::event::EventError;
use crate::immutable;
use crate::interface::LoreError;
use crate::interface::LoreString;
use crate::lore::Context;
use crate::repository::RepositoryContext;
use crate::util;

#[error_set]
pub enum SeedError {
    InvalidArguments,
}

impl EventError for SeedError {
    fn translated(&self) -> LoreError {
        LoreError::Internal
    }

    fn inner(&self) -> String {
        self.to_string()
    }
}

/// Directories that never hold repository content and are skipped wholesale.
const SKIPPED: [&str; 5] = [".lore", ".urc", ".git", ".svn", "node_modules"];

/// Reported once per file that was read into the store.
#[repr(C)]
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoreRepositorySeedFileEventData {
    /// Path of the file that was seeded.
    pub path: LoreString,
    /// Size of the file in bytes.
    pub size: u64,
}

/// Reported once when seeding finishes.
#[repr(C)]
#[derive(Clone, PartialEq, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoreRepositorySeedEndEventData {
    /// Files read into the store.
    pub file_count: u64,
    /// Total bytes read from the seed directory.
    pub byte_count: u64,
    /// Files that could not be read, and were skipped.
    pub skipped_count: u64,
}

/// What a seeding run produced.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SeedResult {
    pub file_count: u64,
    pub byte_count: u64,
    pub skipped_count: u64,
}

/// Reads every file under `source` into the repository's immutable store.
///
/// The store is content-addressed, so a file whose content the repository
/// already holds costs nothing beyond the read, and a file it never needs is
/// simply never referenced. Unreadable files are counted and skipped rather
/// than failing the run: a seed directory is untrusted input, and one bad file
/// must not discard the work done for thousands of good ones.
pub async fn seed(
    repository: Arc<RepositoryContext>,
    source: impl AsRef<Path>,
) -> Result<SeedResult, SeedError> {
    let source = source.as_ref();
    let metadata = lore_io::IoDriver::global()
        .metadata(source)
        .await
        .map_err(|err| InvalidArguments {
            reason: format!("seed path does not exist or is not accessible: {err}"),
        })?;
    if !metadata.is_dir() {
        return Err(InvalidArguments {
            reason: "seed path is not a directory".into(),
        }
        .into());
    }

    let mut result = SeedResult::default();
    let mut pending = vec![source.to_path_buf()];

    // Iterative rather than recursive: a deep asset tree must not put the
    // traversal depth on the stack.
    while let Some(directory) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&directory) else {
            result.skipped_count += 1;
            continue;
        };

        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();

            let Ok(file_type) = entry.file_type() else {
                result.skipped_count += 1;
                continue;
            };

            if file_type.is_dir() {
                if !SKIPPED.contains(&name.as_str()) {
                    pending.push(path);
                }
                continue;
            }
            // Symlinks are followed by neither the walk nor the read: the
            // target is either inside the tree and seeded on its own, or
            // outside it and none of our business.
            if !file_type.is_file() {
                continue;
            }

            let Ok(file_metadata) = entry.metadata() else {
                result.skipped_count += 1;
                continue;
            };
            let size = util::fs::file_size(&file_metadata);
            if size == 0 {
                continue;
            }

            match immutable::write_from_file(
                repository.clone(),
                &path,
                Context::default(),
                Default::default(),
            )
            .await
            {
                Ok(_) => {
                    result.file_count += 1;
                    result.byte_count += size;
                    event::LoreEvent::RepositorySeedFile(LoreRepositorySeedFileEventData {
                        path: LoreString::from_path(&path),
                        size,
                    })
                    .send();
                }
                Err(_) => result.skipped_count += 1,
            }
        }
    }

    event::LoreEvent::RepositorySeedEnd(LoreRepositorySeedEndEventData {
        file_count: result.file_count,
        byte_count: result.byte_count,
        skipped_count: result.skipped_count,
    })
    .send();

    Ok(result)
}
