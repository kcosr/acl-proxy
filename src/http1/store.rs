use std::fmt;

use allocator_api2::boxed::Box as FallibleBox;
use zeroize::Zeroize;

pub(crate) const PARSER_STORE_BYTES: usize = 64 * 1024;

pub(crate) struct ParserStore {
    bytes: FallibleBox<[u8]>,
    start: usize,
    end: usize,
    head_scan_cursor: usize,
    head_scan_pending_cr: bool,
    head_scan_crlf_pairs: u8,
    #[cfg(test)]
    head_scan_inspected: usize,
    #[cfg(test)]
    zeroized_bytes: usize,
    #[cfg(test)]
    moved_bytes: usize,
}

impl ParserStore {
    pub(crate) fn try_new() -> Result<Self, ParserStoreAllocationError> {
        let mut bytes = FallibleBox::<[u8]>::try_new_uninit_slice(PARSER_STORE_BYTES)
            .map_err(|_| ParserStoreAllocationError)?;
        for byte in bytes.iter_mut() {
            byte.write(0);
        }
        // Every element was initialized to zero above.
        let bytes = unsafe { bytes.assume_init() };
        Ok(Self {
            bytes,
            start: 0,
            end: 0,
            head_scan_cursor: 0,
            head_scan_pending_cr: false,
            head_scan_crlf_pairs: 0,
            #[cfg(test)]
            head_scan_inspected: 0,
            #[cfg(test)]
            zeroized_bytes: 0,
            #[cfg(test)]
            moved_bytes: 0,
        })
    }

    pub(crate) fn capacity(&self) -> usize {
        self.bytes.len()
    }

    pub(crate) fn initialized_len(&self) -> usize {
        self.end - self.start
    }

    pub(crate) fn initialized(&self) -> &[u8] {
        &self.bytes[self.start..self.end]
    }

    pub(crate) fn writable(&mut self) -> &mut [u8] {
        if self.end == self.bytes.len() && self.start != 0 {
            self.compact();
        }
        &mut self.bytes[self.end..]
    }

    pub(crate) fn commit_written(&mut self, count: usize) -> Result<(), ParserStoreError> {
        self.end = self
            .end
            .checked_add(count)
            .filter(|end| *end <= self.bytes.len())
            .ok_or(ParserStoreError::CapacityExceeded)?;
        Ok(())
    }

    pub(crate) fn append(&mut self, input: &[u8]) -> Result<(), ParserStoreError> {
        if input.len() > self.bytes.len() - self.end && self.start != 0 {
            self.compact();
        }
        let end = self
            .end
            .checked_add(input.len())
            .ok_or(ParserStoreError::CapacityExceeded)?;
        if end > self.bytes.len() {
            return Err(ParserStoreError::CapacityExceeded);
        }
        self.bytes[self.end..end].copy_from_slice(input);
        self.end = end;
        Ok(())
    }

    pub(crate) fn consume_prefix(&mut self, count: usize) -> Result<(), ParserStoreError> {
        if count > self.initialized_len() {
            return Err(ParserStoreError::InvalidReclamation);
        }
        let consumed_end = self.start + count;
        self.bytes[self.start..consumed_end].zeroize();
        #[cfg(test)]
        {
            self.zeroized_bytes += count;
        }
        self.start = consumed_end;
        if self.start == self.end {
            self.start = 0;
            self.end = 0;
        }
        self.reset_head_scan();
        Ok(())
    }

    pub(crate) fn wipe(&mut self) {
        self.bytes.zeroize();
        #[cfg(test)]
        {
            self.zeroized_bytes += self.bytes.len();
        }
        self.start = 0;
        self.end = 0;
        self.reset_head_scan();
    }

    pub(super) fn scan_head_end(&mut self) -> Result<Option<usize>, HeadScanError> {
        while self.head_scan_cursor < self.initialized_len() {
            let byte = self.bytes[self.start + self.head_scan_cursor];
            self.head_scan_cursor += 1;
            #[cfg(test)]
            {
                self.head_scan_inspected += 1;
            }

            if self.head_scan_pending_cr {
                if byte != b'\n' {
                    return Err(HeadScanError::NonCanonicalLineEnding);
                }
                self.head_scan_pending_cr = false;
                self.head_scan_crlf_pairs += 1;
                if self.head_scan_crlf_pairs == 2 {
                    return Ok(Some(self.head_scan_cursor));
                }
            } else {
                match byte {
                    b'\r' => self.head_scan_pending_cr = true,
                    b'\n' => return Err(HeadScanError::NonCanonicalLineEnding),
                    _ => self.head_scan_crlf_pairs = 0,
                }
            }
        }
        Ok(None)
    }

    fn reset_head_scan(&mut self) {
        self.head_scan_cursor = 0;
        self.head_scan_pending_cr = false;
        self.head_scan_crlf_pairs = 0;
    }

    fn compact(&mut self) {
        if self.start == 0 {
            return;
        }
        let retained = self.initialized_len();
        self.bytes.copy_within(self.start..self.end, 0);
        self.bytes[retained..self.end].zeroize();
        #[cfg(test)]
        {
            self.moved_bytes += retained;
            self.zeroized_bytes += self.end - retained;
        }
        self.start = 0;
        self.end = retained;
    }

    #[cfg(test)]
    pub(crate) fn complete_storage(&self) -> &[u8] {
        &self.bytes
    }

    #[cfg(test)]
    pub(crate) fn inspected_head_bytes_for_test(&self) -> usize {
        self.head_scan_inspected
    }

    #[cfg(test)]
    pub(crate) fn zeroized_bytes_for_test(&self) -> usize {
        self.zeroized_bytes
    }

    #[cfg(test)]
    pub(crate) fn moved_bytes_for_test(&self) -> usize {
        self.moved_bytes
    }

    #[cfg(test)]
    pub(crate) fn inactive_storage_is_zeroed_for_test(&self) -> bool {
        self.bytes[..self.start].iter().all(|byte| *byte == 0)
            && self.bytes[self.end..].iter().all(|byte| *byte == 0)
    }
}

impl Drop for ParserStore {
    fn drop(&mut self) {
        self.wipe();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ParserStoreAllocationError;

impl fmt::Display for ParserStoreAllocationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "could not allocate the fixed HTTP/1 parser store"
        )
    }
}

impl std::error::Error for ParserStoreAllocationError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ParserStoreError {
    CapacityExceeded,
    InvalidReclamation,
}

impl fmt::Display for ParserStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CapacityExceeded => formatter.write_str("HTTP/1 parser store capacity exceeded"),
            Self::InvalidReclamation => {
                formatter.write_str("HTTP/1 parser store reclamation exceeded initialized bytes")
            }
        }
    }
}

impl std::error::Error for ParserStoreError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum HeadScanError {
    NonCanonicalLineEnding,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_store_allocation_capacity_and_complete_wipe_are_exact() {
        let mut store = ParserStore::try_new().unwrap();
        assert_eq!(store.capacity(), PARSER_STORE_BYTES);
        store.writable().fill(0xa5);
        store.commit_written(PARSER_STORE_BYTES).unwrap();

        store.wipe();

        assert_eq!(store.initialized_len(), 0);
        assert!(store.complete_storage().iter().all(|byte| *byte == 0));
    }

    #[test]
    fn parser_store_reclamation_wipes_every_nonretained_byte() {
        let mut store = ParserStore::try_new().unwrap();
        store.append(b"secret-headbody").unwrap();

        store.consume_prefix(b"secret-head".len()).unwrap();

        assert_eq!(store.initialized(), b"body");
        assert!(store.inactive_storage_is_zeroed_for_test());
        assert_eq!(store.zeroized_bytes_for_test(), b"secret-head".len());
        assert_eq!(store.moved_bytes_for_test(), 0);
    }

    #[test]
    fn parser_store_rejects_capacity_and_reclamation_overflow() {
        let mut store = ParserStore::try_new().unwrap();
        assert_eq!(
            store.commit_written(PARSER_STORE_BYTES + 1),
            Err(ParserStoreError::CapacityExceeded)
        );
        assert_eq!(
            store.consume_prefix(1),
            Err(ParserStoreError::InvalidReclamation)
        );
    }

    #[test]
    fn bytewise_reclamation_zeroization_work_is_linear() {
        let mut store = ParserStore::try_new().unwrap();
        for _ in 0..4096 {
            store.append(b"x").unwrap();
            store.consume_prefix(1).unwrap();
        }
        assert_eq!(store.zeroized_bytes_for_test(), 4096);

        store.append(b"sensitive").unwrap();
        let before_wipe = store.zeroized_bytes_for_test();
        store.wipe();
        assert_eq!(
            store.zeroized_bytes_for_test() - before_wipe,
            PARSER_STORE_BYTES
        );
        assert!(store.complete_storage().iter().all(|byte| *byte == 0));
    }
}
