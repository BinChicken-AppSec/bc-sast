use crate::inflate::{inflate, InflateError};

const EOCD_SIGNATURE: u32 = 0x0605_4B50;
const CENTRAL_SIGNATURE: u32 = 0x0201_4B50;
const LOCAL_SIGNATURE: u32 = 0x0403_4B50;

const EOCD_FIXED_LEN: usize = 22;
const CENTRAL_FIXED_LEN: usize = 46;
const LOCAL_FIXED_LEN: usize = 30;

const MAX_COMMENT: usize = u16::MAX as usize;

const METHOD_STORED: u16 = 0;
const METHOD_DEFLATE: u16 = 8;

const ZIP64_SENTINEL: u32 = 0xFFFF_FFFF;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    pub max_entries: usize,
    pub max_entry_bytes: usize,
    pub max_name_len: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_entries: 4096,
            max_entry_bytes: 16 * 1024 * 1024,
            max_name_len: 512,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZipError {
    NotAnArchive,
    Malformed(&'static str),
    TooManyEntries { limit: usize },
    NameTooLong { limit: usize },
    Zip64Unsupported,
    MultiDisk,
    Encrypted { name: String },
    UnsupportedMethod { name: String, method: u16 },
    NoSuchEntry { name: String },
    Corrupt { name: String, cause: InflateError },
    ChecksumMismatch { name: String },
}

impl std::fmt::Display for ZipError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAnArchive => write!(
                f,
                "no end-of-central-directory record; this is not a ZIP archive"
            ),
            Self::Malformed(what) => write!(f, "malformed archive: {what}"),
            Self::TooManyEntries { limit } => {
                write!(f, "the archive declares more than {limit} entries")
            }
            Self::NameTooLong { limit } => {
                write!(f, "an entry name is longer than {limit} bytes")
            }
            Self::Zip64Unsupported => write!(
                f,
                "this archive needs ZIP64, which is not supported; \
                 an Office document does not use it"
            ),
            Self::MultiDisk => write!(f, "the archive spans several disks"),
            Self::Encrypted { name } => write!(f, "{name:?} is encrypted"),
            Self::UnsupportedMethod { name, method } => write!(
                f,
                "{name:?} uses compression method {method}; only stored (0) \
                 and deflate (8) are supported"
            ),
            Self::NoSuchEntry { name } => write!(f, "the archive has no entry named {name:?}"),
            Self::Corrupt { name, cause } => write!(f, "{name:?} did not decompress: {cause}"),
            Self::ChecksumMismatch { name } => {
                write!(f, "{name:?} decompressed but failed its CRC-32 check")
            }
        }
    }
}

impl std::error::Error for ZipError {}

fn u16_at(data: &[u8], at: usize) -> Result<u16, ZipError> {
    let b = data
        .get(at..at + 2)
        .ok_or(ZipError::Malformed("a field ran past the end of the data"))?;
    Ok(u16::from(b[0]) | (u16::from(b[1]) << 8))
}

fn u32_at(data: &[u8], at: usize) -> Result<u32, ZipError> {
    let b = data
        .get(at..at + 4)
        .ok_or(ZipError::Malformed("a field ran past the end of the data"))?;
    Ok(
        u32::from(b[0])
            | (u32::from(b[1]) << 8)
            | (u32::from(b[2]) << 16)
            | (u32::from(b[3]) << 24),
    )
}

#[derive(Debug, Clone)]
pub struct Entry {
    pub name: String,
    method: u16,
    flags: u16,
    crc32: u32,
    compressed_size: usize,
    local_header_offset: usize,
}

fn find_eocd(data: &[u8]) -> Result<usize, ZipError> {
    if data.len() < EOCD_FIXED_LEN {
        return Err(ZipError::NotAnArchive);
    }
    let highest = data.len() - EOCD_FIXED_LEN;
    let lowest = highest.saturating_sub(MAX_COMMENT);
    for at in (lowest..=highest).rev() {
        if u32_at(data, at)? == EOCD_SIGNATURE {
            let comment_len = usize::from(u16_at(data, at + 20)?);
            if at + EOCD_FIXED_LEN + comment_len == data.len() {
                return Ok(at);
            }
        }
    }
    Err(ZipError::NotAnArchive)
}

pub fn entries(data: &[u8], limits: &Limits) -> Result<Vec<Entry>, ZipError> {
    let eocd = find_eocd(data)?;

    if u16_at(data, eocd + 4)? != 0 || u16_at(data, eocd + 6)? != 0 {
        return Err(ZipError::MultiDisk);
    }
    let declared = usize::from(u16_at(data, eocd + 10)?);
    if declared > limits.max_entries {
        return Err(ZipError::TooManyEntries {
            limit: limits.max_entries,
        });
    }
    let cd_size = u32_at(data, eocd + 12)?;
    let cd_offset = u32_at(data, eocd + 16)?;
    if cd_size == ZIP64_SENTINEL || cd_offset == ZIP64_SENTINEL {
        return Err(ZipError::Zip64Unsupported);
    }
    let cd_start = cd_offset as usize;
    let cd_end = cd_start
        .checked_add(cd_size as usize)
        .ok_or(ZipError::Malformed("the central directory overflows"))?;
    if cd_end > data.len() {
        return Err(ZipError::Malformed(
            "the central directory extends past the end of the data",
        ));
    }

    let mut out = Vec::new();
    let mut at = cd_start;
    while at < cd_end {
        if u32_at(data, at)? != CENTRAL_SIGNATURE {
            return Err(ZipError::Malformed(
                "a central-directory entry has no signature",
            ));
        }
        if out.len() >= limits.max_entries {
            return Err(ZipError::TooManyEntries {
                limit: limits.max_entries,
            });
        }
        let flags = u16_at(data, at + 8)?;
        let method = u16_at(data, at + 10)?;
        let crc32 = u32_at(data, at + 16)?;
        let compressed_size = u32_at(data, at + 20)?;
        let uncompressed_size = u32_at(data, at + 24)?;
        let name_len = usize::from(u16_at(data, at + 28)?);
        let extra_len = usize::from(u16_at(data, at + 30)?);
        let comment_len = usize::from(u16_at(data, at + 32)?);
        let local_header_offset = u32_at(data, at + 42)?;

        if compressed_size == ZIP64_SENTINEL
            || uncompressed_size == ZIP64_SENTINEL
            || local_header_offset == ZIP64_SENTINEL
        {
            return Err(ZipError::Zip64Unsupported);
        }
        if name_len > limits.max_name_len {
            return Err(ZipError::NameTooLong {
                limit: limits.max_name_len,
            });
        }
        let name_at = at + CENTRAL_FIXED_LEN;
        let raw_name = data
            .get(name_at..name_at + name_len)
            .ok_or(ZipError::Malformed("an entry name runs past the end"))?;
        let name = String::from_utf8_lossy(raw_name).into_owned();

        out.push(Entry {
            name,
            method,
            flags,
            crc32,
            compressed_size: compressed_size as usize,
            local_header_offset: local_header_offset as usize,
        });

        at = at
            .checked_add(CENTRAL_FIXED_LEN + name_len + extra_len + comment_len)
            .ok_or(ZipError::Malformed("a central-directory entry overflows"))?;
    }
    Ok(out)
}

pub fn entry_names(data: &[u8], limits: &Limits) -> Result<Vec<String>, ZipError> {
    Ok(entries(data, limits)?.into_iter().map(|e| e.name).collect())
}

pub fn read_entry(data: &[u8], name: &str, limits: &Limits) -> Result<Vec<u8>, ZipError> {
    let entries = entries(data, limits)?;
    let entry = entries
        .iter()
        .find(|e| e.name == name)
        .ok_or_else(|| ZipError::NoSuchEntry {
            name: name.to_string(),
        })?;
    read(data, entry, limits)
}

pub fn read(data: &[u8], entry: &Entry, limits: &Limits) -> Result<Vec<u8>, ZipError> {
    if entry.flags & 1 != 0 {
        return Err(ZipError::Encrypted {
            name: entry.name.clone(),
        });
    }
    let local = entry.local_header_offset;
    if u32_at(data, local)? != LOCAL_SIGNATURE {
        return Err(ZipError::Malformed("a local file header has no signature"));
    }
    let local_name_len = usize::from(u16_at(data, local + 26)?);
    let local_extra_len = usize::from(u16_at(data, local + 28)?);
    let data_start = local
        .checked_add(LOCAL_FIXED_LEN + local_name_len + local_extra_len)
        .ok_or(ZipError::Malformed("a local file header overflows"))?;
    let data_end = data_start
        .checked_add(entry.compressed_size)
        .ok_or(ZipError::Malformed("an entry's data overflows"))?;
    let raw = data
        .get(data_start..data_end)
        .ok_or(ZipError::Malformed("an entry's data runs past the end"))?;

    let out = match entry.method {
        METHOD_STORED => {
            if raw.len() > limits.max_entry_bytes {
                return Err(ZipError::Corrupt {
                    name: entry.name.clone(),
                    cause: InflateError::OutputTooLarge {
                        limit: limits.max_entry_bytes,
                    },
                });
            }
            raw.to_vec()
        }
        METHOD_DEFLATE => {
            inflate(raw, limits.max_entry_bytes).map_err(|cause| ZipError::Corrupt {
                name: entry.name.clone(),
                cause,
            })?
        }
        method => {
            return Err(ZipError::UnsupportedMethod {
                name: entry.name.clone(),
                method,
            })
        }
    };

    if crc32(&out) != entry.crc32 {
        return Err(ZipError::ChecksumMismatch {
            name: entry.name.clone(),
        });
    }
    Ok(out)
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = if crc & 1 != 0 { 0xEDB8_8320 } else { 0 };
            crc = (crc >> 1) ^ mask;
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Built {
        name: Vec<u8>,
        payload: Vec<u8>,
        method: u16,
        flags: u16,
        crc: Option<u32>,
        declared_size: Option<u32>,
        disk: u16,
        total_entries: u16,
        cd_offset: Option<u32>,
        cd_size: Option<u32>,
        local_signature: u32,
        central_signature: u32,
        comment: Vec<u8>,
    }

    impl Default for Built {
        fn default() -> Self {
            Self {
                name: b"word/document.xml".to_vec(),
                payload: b"<w:document/>".to_vec(),
                method: METHOD_STORED,
                flags: 0,
                crc: None,
                declared_size: None,
                disk: 0,
                total_entries: 1,
                cd_offset: None,
                cd_size: None,
                local_signature: LOCAL_SIGNATURE,
                central_signature: CENTRAL_SIGNATURE,
                comment: Vec::new(),
            }
        }
    }

    impl Built {
        fn bytes(&self) -> Vec<u8> {
            let crc = self.crc.unwrap_or_else(|| crc32(&self.payload));
            let size = self.declared_size.unwrap_or(self.payload.len() as u32);
            let mut local = Vec::new();
            local.extend_from_slice(&self.local_signature.to_le_bytes());
            local.extend_from_slice(&20u16.to_le_bytes());
            local.extend_from_slice(&self.flags.to_le_bytes());
            local.extend_from_slice(&self.method.to_le_bytes());
            local.extend_from_slice(&0u16.to_le_bytes());
            local.extend_from_slice(&0u16.to_le_bytes());
            local.extend_from_slice(&crc.to_le_bytes());
            local.extend_from_slice(&size.to_le_bytes());
            local.extend_from_slice(&size.to_le_bytes());
            local.extend_from_slice(&(self.name.len() as u16).to_le_bytes());
            local.extend_from_slice(&0u16.to_le_bytes());
            local.extend_from_slice(&self.name);
            let mut data = local;
            data.extend_from_slice(&self.payload);

            let mut central = Vec::new();
            central.extend_from_slice(&self.central_signature.to_le_bytes());
            central.extend_from_slice(&20u16.to_le_bytes());
            central.extend_from_slice(&20u16.to_le_bytes());
            central.extend_from_slice(&self.flags.to_le_bytes());
            central.extend_from_slice(&self.method.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&crc.to_le_bytes());
            central.extend_from_slice(&size.to_le_bytes());
            central.extend_from_slice(&size.to_le_bytes());
            central.extend_from_slice(&(self.name.len() as u16).to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u32.to_le_bytes());
            central.extend_from_slice(&0u32.to_le_bytes());
            central.extend_from_slice(&self.name);

            let mut out = data.clone();
            let cd_at = self.cd_offset.unwrap_or(data.len() as u32);
            let cd_len = self.cd_size.unwrap_or(central.len() as u32);
            out.extend_from_slice(&central);
            out.extend_from_slice(&EOCD_SIGNATURE.to_le_bytes());
            out.extend_from_slice(&self.disk.to_le_bytes());
            out.extend_from_slice(&self.disk.to_le_bytes());
            out.extend_from_slice(&self.total_entries.to_le_bytes());
            out.extend_from_slice(&self.total_entries.to_le_bytes());
            out.extend_from_slice(&cd_len.to_le_bytes());
            out.extend_from_slice(&cd_at.to_le_bytes());
            out.extend_from_slice(&(self.comment.len() as u16).to_le_bytes());
            out.extend_from_slice(&self.comment);
            out
        }
    }

    fn read(built: &Built) -> Result<Vec<u8>, ZipError> {
        read_entry(&built.bytes(), "word/document.xml", &Limits::default())
    }

    #[test]
    fn a_hand_built_archive_reads_back_what_was_put_in_it() {
        assert_eq!(read(&Built::default()).expect("valid"), b"<w:document/>");
    }

    #[test]
    fn anything_shorter_than_an_eocd_record_is_not_an_archive() {
        for len in [0usize, 1, 21] {
            assert_eq!(
                entry_names(&vec![0u8; len], &Limits::default()),
                Err(ZipError::NotAnArchive)
            );
        }
    }

    #[test]
    fn an_eocd_signature_inside_the_data_is_not_mistaken_for_the_record() {
        let mut payload = EOCD_SIGNATURE.to_le_bytes().to_vec();
        payload.extend_from_slice(&[0u8; 18]);
        let built = Built {
            payload,
            ..Built::default()
        };
        assert!(read(&built).is_ok());
    }

    #[test]
    fn an_eocd_signature_planted_in_the_comment_is_rejected() {
        let mut comment = EOCD_SIGNATURE.to_le_bytes().to_vec();
        comment.extend_from_slice(&[0u8; 30]);
        let built = Built {
            comment,
            ..Built::default()
        };
        assert_eq!(read(&built).expect("valid"), b"<w:document/>");
    }

    #[test]
    fn the_entry_cap_is_enforced_while_walking_not_only_as_declared() {
        let whole = Built::default().bytes();
        let eocd_at = whole.len() - EOCD_FIXED_LEN;
        let cd_size = u32_at(&whole, eocd_at + 12).expect("a size") as usize;
        let cd_at = u32_at(&whole, eocd_at + 16).expect("an offset") as usize;
        let central = &whole[cd_at..cd_at + cd_size];

        let mut forged = whole[..cd_at].to_vec();
        forged.extend_from_slice(central);
        forged.extend_from_slice(central);
        forged.extend_from_slice(&EOCD_SIGNATURE.to_le_bytes());
        forged.extend_from_slice(&0u16.to_le_bytes());
        forged.extend_from_slice(&0u16.to_le_bytes());
        forged.extend_from_slice(&1u16.to_le_bytes());
        forged.extend_from_slice(&1u16.to_le_bytes());
        forged.extend_from_slice(&((cd_size * 2) as u32).to_le_bytes());
        forged.extend_from_slice(&(cd_at as u32).to_le_bytes());
        forged.extend_from_slice(&0u16.to_le_bytes());

        let limits = Limits {
            max_entries: 1,
            ..Limits::default()
        };
        assert_eq!(
            entry_names(&forged, &limits),
            Err(ZipError::TooManyEntries { limit: 1 })
        );
        assert_eq!(
            entry_names(&forged, &Limits::default())
                .expect("valid")
                .len(),
            2
        );
    }

    #[test]
    fn a_multi_disk_archive_is_refused() {
        let built = Built {
            disk: 1,
            ..Built::default()
        };
        assert_eq!(read(&built), Err(ZipError::MultiDisk));
    }

    #[test]
    fn a_zip64_sentinel_in_the_eocd_is_refused() {
        let built = Built {
            cd_offset: Some(ZIP64_SENTINEL),
            ..Built::default()
        };
        assert_eq!(read(&built), Err(ZipError::Zip64Unsupported));
        let built = Built {
            cd_size: Some(ZIP64_SENTINEL),
            ..Built::default()
        };
        assert_eq!(read(&built), Err(ZipError::Zip64Unsupported));
    }

    #[test]
    fn a_zip64_sentinel_in_an_entry_is_refused() {
        let built = Built {
            declared_size: Some(ZIP64_SENTINEL),
            ..Built::default()
        };
        assert_eq!(read(&built), Err(ZipError::Zip64Unsupported));
    }

    #[test]
    fn a_central_directory_past_the_end_of_the_data_is_refused() {
        let built = Built {
            cd_size: Some(100_000),
            ..Built::default()
        };
        assert!(
            matches!(read(&built), Err(ZipError::Malformed(_))),
            "{:?}",
            read(&built)
        );
    }

    #[test]
    fn a_central_directory_entry_without_its_signature_is_refused() {
        let built = Built {
            central_signature: 0xDEAD_BEEF,
            ..Built::default()
        };
        assert_eq!(
            read(&built),
            Err(ZipError::Malformed(
                "a central-directory entry has no signature"
            ))
        );
    }

    #[test]
    fn a_local_header_without_its_signature_is_refused() {
        let built = Built {
            local_signature: 0xDEAD_BEEF,
            ..Built::default()
        };
        assert_eq!(
            read(&built),
            Err(ZipError::Malformed("a local file header has no signature"))
        );
    }

    #[test]
    fn an_archive_claiming_too_many_entries_is_refused() {
        let built = Built {
            total_entries: 9000,
            ..Built::default()
        };
        assert_eq!(
            entry_names(&built.bytes(), &Limits::default()),
            Err(ZipError::TooManyEntries { limit: 4096 })
        );
        let limits = Limits {
            max_entries: 0,
            ..Limits::default()
        };
        assert_eq!(
            entry_names(&Built::default().bytes(), &limits),
            Err(ZipError::TooManyEntries { limit: 0 })
        );
    }

    #[test]
    fn an_over_long_entry_name_is_refused() {
        let limits = Limits {
            max_name_len: 4,
            ..Limits::default()
        };
        assert_eq!(
            entry_names(&Built::default().bytes(), &limits),
            Err(ZipError::NameTooLong { limit: 4 })
        );
    }

    #[test]
    fn an_encrypted_entry_is_refused_before_anything_is_decoded() {
        let built = Built {
            flags: 1,
            ..Built::default()
        };
        assert_eq!(
            read(&built),
            Err(ZipError::Encrypted {
                name: "word/document.xml".into()
            })
        );
    }

    #[test]
    fn an_unsupported_compression_method_is_named() {
        let built = Built {
            method: 12,
            ..Built::default()
        };
        assert_eq!(
            read(&built),
            Err(ZipError::UnsupportedMethod {
                name: "word/document.xml".into(),
                method: 12
            })
        );
    }

    #[test]
    fn a_stored_entry_past_the_byte_bound_is_refused() {
        let limits = Limits {
            max_entry_bytes: 4,
            ..Limits::default()
        };
        let err = read_entry(&Built::default().bytes(), "word/document.xml", &limits)
            .expect_err("past the bound");
        assert!(
            matches!(
                err,
                ZipError::Corrupt {
                    cause: InflateError::OutputTooLarge { limit: 4 },
                    ..
                }
            ),
            "{err:?}"
        );
    }

    #[test]
    fn a_mismatched_checksum_is_reported() {
        let built = Built {
            crc: Some(0),
            ..Built::default()
        };
        assert_eq!(
            read(&built),
            Err(ZipError::ChecksumMismatch {
                name: "word/document.xml".into()
            })
        );
    }

    #[test]
    fn crc32_matches_published_vectors() {
        assert_eq!(crc32(b""), 0x0000_0000);
        assert_eq!(crc32(b"a"), 0xE8B7_BE43);
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(
            crc32(b"The quick brown fox jumps over the lazy dog"),
            0x414F_A339
        );
    }

    #[test]
    fn a_name_that_is_not_utf8_is_carried_rather_than_sinking_the_archive() {
        let built = Built {
            name: vec![0xFF, 0xFE, b'x'],
            ..Built::default()
        };
        let names = entry_names(&built.bytes(), &Limits::default()).expect("still readable");
        assert_eq!(names.len(), 1);
        assert!(names[0].contains('\u{FFFD}'), "{names:?}");
    }

    #[test]
    fn every_error_renders_and_is_a_std_error() {
        let all = [
            ZipError::NotAnArchive,
            ZipError::Malformed("something"),
            ZipError::TooManyEntries { limit: 1 },
            ZipError::NameTooLong { limit: 2 },
            ZipError::Zip64Unsupported,
            ZipError::MultiDisk,
            ZipError::Encrypted { name: "a".into() },
            ZipError::UnsupportedMethod {
                name: "a".into(),
                method: 9,
            },
            ZipError::NoSuchEntry { name: "a".into() },
            ZipError::Corrupt {
                name: "a".into(),
                cause: InflateError::Truncated,
            },
            ZipError::ChecksumMismatch { name: "a".into() },
        ];
        for e in all {
            assert!(!e.to_string().is_empty(), "{e:?} rendered empty");
            let _: &dyn std::error::Error = &e;
        }
    }

    #[test]
    fn the_default_bounds_are_stated_rather_than_implied() {
        let d = Limits::default();
        assert_eq!(d.max_entries, 4096);
        assert_eq!(d.max_entry_bytes, 16 * 1024 * 1024);
        assert_eq!(d.max_name_len, 512);
    }
}
