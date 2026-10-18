// SPDX-License-Identifier: Apache-2.0

//! A payload by reference read back for replay (`quantstratum-docs:
//! karyos/design/recording-group-replay.md` section 2).
//!
//! A message event whose payload is by reference names a recording and
//! the frames `[position, position + extent)`. [`read_message`] reads
//! them through the recording's [`ReplaySource`] and reassembles the
//! message: each frame's payload after its header (32 bytes, or 96 with
//! the trace extension), from the first fragment to the last. A range the
//! recording no longer holds, a padding or aborted block or a lost range
//! inside it, fragments out of order, or a length other than recorded
//! leaves the payload unavailable at replay time (section 7).

use std::path::Path;

use karyos_sys::frame::{EXTENSION_LENGTH, FRAME_ALIGNMENT, HEADER_LENGTH, Word0};

use crate::disk::Disk;
use crate::segment::Geometry;
use crate::segment::replay::{Rate, ReplaySource, Step};

#[cfg(test)]
mod tests;

/// Where a recording's frames are read from.
#[derive(Debug, Clone, Copy)]
pub struct Recording<'a> {
    /// The Archive directory that holds it.
    pub dir: &'a Path,
    /// Its id.
    pub recording_id: u64,
    /// Its segment geometry.
    pub geometry: Geometry,
}

/// The frames of one message, as recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frames {
    /// The first frame's position.
    pub position: u64,
    /// The frames' extent, from the first frame to the last one's end.
    pub extent: u32,
    /// The message's payload length.
    pub length: u32,
}

/// Reads the message of `frames` from `recording` on `disk` into `out`;
/// returns its length. `None` when replay cannot give it: see the module.
///
/// It allocates the source's buffer and opens the recording's files: a
/// payload by reference is the one read a replayed event may allocate for
/// (section 11).
pub fn read_message<D: Disk>(
    disk: D,
    recording: &Recording<'_>,
    frames: Frames,
    out: &mut [u8],
) -> Option<usize> {
    let to = frames.position.checked_add(u64::from(frames.extent))?;
    let length = usize::try_from(frames.length).ok()?;
    let out = out.get_mut(..length)?;
    // The source needs room for the largest frame, at most the whole
    // payload behind the longest header, never the whole extent.
    let alignment = usize::try_from(FRAME_ALIGNMENT).ok()?;
    let buffer = length
        .checked_add(usize::try_from(HEADER_LENGTH + EXTENSION_LENGTH).ok()?)?
        .checked_next_multiple_of(alignment)?;
    let mut source = ReplaySource::open(
        disk,
        recording.dir,
        recording.recording_id,
        recording.geometry,
        frames.position,
        to,
        Rate::Full,
        buffer,
    )
    .ok()?;
    let mut filled = 0usize;
    let mut started = false;
    let mut ended = false;
    loop {
        match source.poll(0).ok()? {
            Step::Frames { bytes, .. } => {
                let mut offset = 0usize;
                while offset < bytes.len() {
                    if ended {
                        return None;
                    }
                    let word = bytes.get(offset..offset.checked_add(8)?)?;
                    let word0 = Word0::unpack(u64::from_le_bytes(word.try_into().ok()?)).ok()?;
                    let flags = word0.flags();
                    // The first fragment begins the message; no later one does.
                    if flags.begin() == started {
                        return None;
                    }
                    started = true;
                    let frame_length = usize::try_from(word0.frame_length()).ok()?;
                    let header = usize::try_from(flags.header_length()).ok()?;
                    let payload = bytes
                        .get(offset.checked_add(header)?..offset.checked_add(frame_length)?)?;
                    let to = filled.checked_add(payload.len())?;
                    out.get_mut(filled..to)?.copy_from_slice(payload);
                    filled = to;
                    ended = flags.end();
                    offset =
                        offset.checked_add(frame_length.checked_next_multiple_of(alignment)?)?;
                }
            }
            Step::End { .. } => break,
            Step::Fill { .. } | Step::Gap { .. } | Step::Wait { .. } => return None,
        }
    }
    (ended && filled == length).then_some(filled)
}
