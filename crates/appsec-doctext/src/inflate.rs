const MAX_BITS: usize = 15;

const LENGTH_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LENGTH_EXTRA: [u32; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DIST_EXTRA: [u32; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];
const CODE_LENGTH_ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InflateError {
    Truncated,
    ReservedBlockType,
    StoredLengthMismatch,
    OverSubscribedTable,
    InvalidCode,
    InvalidSymbol(u16),
    DistanceTooFar { distance: usize, available: usize },
    OutputTooLarge { limit: usize },
}

impl std::fmt::Display for InflateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => write!(f, "the compressed stream ended mid-symbol"),
            Self::ReservedBlockType => write!(f, "block type 3 is reserved and has no meaning"),
            Self::StoredLengthMismatch => {
                write!(f, "a stored block's length did not match its complement")
            }
            Self::OverSubscribedTable => {
                write!(f, "a Huffman table declared more codes than can exist")
            }
            Self::InvalidCode => write!(f, "the bits matched no Huffman code"),
            Self::InvalidSymbol(s) => write!(f, "symbol {s} is outside its alphabet"),
            Self::DistanceTooFar {
                distance,
                available,
            } => write!(
                f,
                "a match referred {distance} bytes back with only {available} decoded"
            ),
            Self::OutputTooLarge { limit } => {
                write!(f, "decompressed output passed the {limit} byte limit")
            }
        }
    }
}

impl std::error::Error for InflateError {}

struct BitReader<'a> {
    data: &'a [u8],
    pos: usize,
    buf: u32,
    count: u32,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            buf: 0,
            count: 0,
        }
    }

    fn bit(&mut self) -> Result<u32, InflateError> {
        if self.count == 0 {
            let byte = *self.data.get(self.pos).ok_or(InflateError::Truncated)?;
            self.pos += 1;
            self.buf = u32::from(byte);
            self.count = 8;
        }
        let b = self.buf & 1;
        self.buf >>= 1;
        self.count -= 1;
        Ok(b)
    }

    fn bits(&mut self, need: u32) -> Result<u32, InflateError> {
        let mut out = 0u32;
        for i in 0..need {
            out |= self.bit()? << i;
        }
        Ok(out)
    }

    fn align(&mut self) {
        self.buf = 0;
        self.count = 0;
    }

    fn bytes(&mut self, n: usize) -> Result<&'a [u8], InflateError> {
        let end = self.pos.checked_add(n).ok_or(InflateError::Truncated)?;
        let out = self
            .data
            .get(self.pos..end)
            .ok_or(InflateError::Truncated)?;
        self.pos = end;
        Ok(out)
    }
}

struct Huffman {
    counts: [u16; MAX_BITS + 1],
    symbols: Vec<u16>,
}

impl Huffman {
    fn new(lengths: &[u8]) -> Result<Self, InflateError> {
        let mut counts = [0u16; MAX_BITS + 1];
        for &len in lengths {
            let len = usize::from(len);
            if len > MAX_BITS {
                return Err(InflateError::OverSubscribedTable);
            }
            counts[len] += 1;
        }
        let used = lengths.len() - usize::from(counts[0]);
        if used == 0 {
            return Ok(Self {
                counts,
                symbols: Vec::new(),
            });
        }
        let mut left: i64 = 1;
        for count in counts.iter().skip(1) {
            left <<= 1;
            left -= i64::from(*count);
            if left < 0 {
                return Err(InflateError::OverSubscribedTable);
            }
        }
        let mut offsets = [0u16; MAX_BITS + 2];
        for len in 1..=MAX_BITS {
            offsets[len + 1] = offsets[len] + counts[len];
        }
        let mut symbols = vec![0u16; used];
        for (symbol, &len) in lengths.iter().enumerate() {
            if len != 0 {
                let at = usize::from(offsets[usize::from(len)]);
                symbols[at] = symbol as u16;
                offsets[usize::from(len)] += 1;
            }
        }
        Ok(Self { counts, symbols })
    }

    fn decode(&self, br: &mut BitReader<'_>) -> Result<u16, InflateError> {
        let mut code: i64 = 0;
        let mut first: i64 = 0;
        let mut index: i64 = 0;
        for len in 1..=MAX_BITS {
            code |= i64::from(br.bit()?);
            let count = i64::from(self.counts[len]);
            if code - first < count {
                let at = (index + (code - first)) as usize;
                return self
                    .symbols
                    .get(at)
                    .copied()
                    .ok_or(InflateError::InvalidCode);
            }
            index += count;
            first = (first + count) << 1;
            code <<= 1;
        }
        Err(InflateError::InvalidCode)
    }
}

fn fixed_tables() -> Result<(Huffman, Huffman), InflateError> {
    let mut literal = [0u8; 288];
    for (symbol, len) in literal.iter_mut().enumerate() {
        *len = match symbol {
            0..=143 => 8,
            144..=255 => 9,
            256..=279 => 7,
            _ => 8,
        };
    }
    let distance = [5u8; 32];
    Ok((Huffman::new(&literal)?, Huffman::new(&distance)?))
}

pub fn inflate(input: &[u8], max_output: usize) -> Result<Vec<u8>, InflateError> {
    let mut br = BitReader::new(input);
    let mut out: Vec<u8> = Vec::new();
    loop {
        let last = br.bit()? == 1;
        match br.bits(2)? {
            0 => stored_block(&mut br, &mut out, max_output)?,
            1 => {
                let (literal, distance) = fixed_tables()?;
                compressed_block(&mut br, &mut out, max_output, &literal, &distance)?;
            }
            2 => {
                let (literal, distance) = dynamic_tables(&mut br)?;
                compressed_block(&mut br, &mut out, max_output, &literal, &distance)?;
            }
            _ => return Err(InflateError::ReservedBlockType),
        }
        if last {
            return Ok(out);
        }
    }
}

fn push(out: &mut Vec<u8>, byte: u8, max_output: usize) -> Result<(), InflateError> {
    if out.len() >= max_output {
        return Err(InflateError::OutputTooLarge { limit: max_output });
    }
    out.push(byte);
    Ok(())
}

fn stored_block(
    br: &mut BitReader<'_>,
    out: &mut Vec<u8>,
    max_output: usize,
) -> Result<(), InflateError> {
    br.align();
    let header = br.bytes(4)?;
    let len = u16::from(header[0]) | (u16::from(header[1]) << 8);
    let nlen = u16::from(header[2]) | (u16::from(header[3]) << 8);
    if len != !nlen {
        return Err(InflateError::StoredLengthMismatch);
    }
    let len = usize::from(len);
    if out.len().saturating_add(len) > max_output {
        return Err(InflateError::OutputTooLarge { limit: max_output });
    }
    out.extend_from_slice(br.bytes(len)?);
    Ok(())
}

fn dynamic_tables(br: &mut BitReader<'_>) -> Result<(Huffman, Huffman), InflateError> {
    let literal_count = br.bits(5)? as usize + 257;
    let distance_count = br.bits(5)? as usize + 1;
    let code_length_count = br.bits(4)? as usize + 4;

    let mut code_lengths = [0u8; 19];
    for &slot in CODE_LENGTH_ORDER.iter().take(code_length_count) {
        code_lengths[slot] = br.bits(3)? as u8;
    }
    let code_length_table = Huffman::new(&code_lengths)?;

    let total = literal_count + distance_count;
    let mut lengths = vec![0u8; total];
    let mut at = 0usize;
    while at < total {
        match length_op(code_length_table.decode(br)?)? {
            LengthOp::Literal(len) => {
                lengths[at] = len;
                at += 1;
            }
            LengthOp::RepeatPrevious => {
                if at == 0 {
                    return Err(InflateError::InvalidSymbol(16));
                }
                let previous = lengths[at - 1];
                let repeat = 3 + br.bits(2)? as usize;
                if at + repeat > total {
                    return Err(InflateError::InvalidSymbol(16));
                }
                for _ in 0..repeat {
                    lengths[at] = previous;
                    at += 1;
                }
            }
            LengthOp::RepeatZero {
                symbol,
                base,
                extra,
            } => {
                let repeat = base + br.bits(extra)? as usize;
                if at + repeat > total {
                    return Err(InflateError::InvalidSymbol(symbol));
                }
                at += repeat;
            }
        }
    }
    let (literal, distance) = lengths.split_at(literal_count);
    Ok((Huffman::new(literal)?, Huffman::new(distance)?))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LengthOp {
    Literal(u8),
    RepeatPrevious,
    RepeatZero {
        symbol: u16,
        base: usize,
        extra: u32,
    },
}

fn length_op(symbol: u16) -> Result<LengthOp, InflateError> {
    match symbol {
        0..=15 => Ok(LengthOp::Literal(symbol as u8)),
        16 => Ok(LengthOp::RepeatPrevious),
        17 => Ok(LengthOp::RepeatZero {
            symbol: 17,
            base: 3,
            extra: 3,
        }),
        18 => Ok(LengthOp::RepeatZero {
            symbol: 18,
            base: 11,
            extra: 7,
        }),
        other => Err(InflateError::InvalidSymbol(other)),
    }
}

fn compressed_block(
    br: &mut BitReader<'_>,
    out: &mut Vec<u8>,
    max_output: usize,
    literal: &Huffman,
    distance: &Huffman,
) -> Result<(), InflateError> {
    loop {
        let symbol = literal.decode(br)?;
        match symbol {
            0..=255 => push(out, symbol as u8, max_output)?,
            256 => return Ok(()),
            257..=285 => {
                let index = usize::from(symbol) - 257;
                let length =
                    usize::from(LENGTH_BASE[index]) + br.bits(LENGTH_EXTRA[index])? as usize;
                let dist_symbol = usize::from(distance.decode(br)?);
                if dist_symbol >= DIST_BASE.len() {
                    return Err(InflateError::InvalidSymbol(dist_symbol as u16));
                }
                let dist = usize::from(DIST_BASE[dist_symbol])
                    + br.bits(DIST_EXTRA[dist_symbol])? as usize;
                if dist > out.len() {
                    return Err(InflateError::DistanceTooFar {
                        distance: dist,
                        available: out.len(),
                    });
                }
                let start = out.len() - dist;
                for i in 0..length {
                    let byte = out[start + i];
                    push(out, byte, max_output)?;
                }
            }
            other => return Err(InflateError::InvalidSymbol(other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct BitWriter {
        bytes: Vec<u8>,
        acc: u32,
        bits: u32,
    }

    impl BitWriter {
        fn new() -> Self {
            Self {
                bytes: Vec::new(),
                acc: 0,
                bits: 0,
            }
        }

        fn value(&mut self, value: u32, count: u32) {
            for i in 0..count {
                self.bit((value >> i) & 1);
            }
        }

        fn code(&mut self, code: u32, count: u32) {
            for i in (0..count).rev() {
                self.bit((code >> i) & 1);
            }
        }

        fn bit(&mut self, b: u32) {
            self.acc |= b << self.bits;
            self.bits += 1;
            if self.bits == 8 {
                self.bytes.push(self.acc as u8);
                self.acc = 0;
                self.bits = 0;
            }
        }

        fn finish(mut self) -> Vec<u8> {
            if self.bits > 0 {
                self.bytes.push(self.acc as u8);
            }
            self.bytes
        }
    }

    #[test]
    fn an_over_subscribed_table_is_refused() {
        assert_eq!(
            Huffman::new(&[1, 1, 1]).map(|_| ()),
            Err(InflateError::OverSubscribedTable)
        );
        assert_eq!(
            Huffman::new(&[16]).map(|_| ()),
            Err(InflateError::OverSubscribedTable)
        );
    }

    #[test]
    fn an_empty_table_is_legal_but_decodes_nothing() {
        let empty = Huffman::new(&[0, 0, 0]).expect("an empty table is legal");
        let mut br = BitReader::new(&[0xFF, 0xFF, 0xFF]);
        assert_eq!(empty.decode(&mut br), Err(InflateError::InvalidCode));
        let mut short = BitReader::new(&[0xFF]);
        assert_eq!(empty.decode(&mut short), Err(InflateError::Truncated));
    }

    #[test]
    fn a_literal_symbol_with_no_meaning_is_refused() {
        let mut w = BitWriter::new();
        w.value(1, 1);
        w.value(1, 2);
        w.code(0b1100_0000 + 6, 8);
        assert_eq!(
            inflate(&w.finish(), 4096),
            Err(InflateError::InvalidSymbol(286))
        );
    }

    #[test]
    fn a_distance_symbol_with_no_meaning_is_refused() {
        let mut w = BitWriter::new();
        w.value(1, 1);
        w.value(1, 2);
        w.code(0b0011_0000, 8);
        w.code(0b0011_0000 + 97, 8);
        w.code(0b0000_0001, 7);
        w.code(30, 5);
        let err = inflate(&w.finish(), 4096).expect_err("refused");
        assert_eq!(err, InflateError::InvalidSymbol(30));
    }

    #[test]
    fn a_distance_before_the_start_of_the_output_is_refused() {
        let mut w = BitWriter::new();
        w.value(1, 1);
        w.value(1, 2);
        w.code(0b0000_0001, 7);
        w.code(0, 5);
        assert_eq!(
            inflate(&w.finish(), 4096),
            Err(InflateError::DistanceTooFar {
                distance: 1,
                available: 0
            })
        );
    }

    #[test]
    fn the_bit_writer_handles_an_exact_byte_boundary() {
        let mut w = BitWriter::new();
        w.value(0b1010_1010, 8);
        assert_eq!(w.finish(), vec![0b1010_1010], "a whole byte, no padding");
        let mut w = BitWriter::new();
        w.value(1, 1);
        assert_eq!(w.finish(), vec![1], "a partial byte is padded out");
    }

    #[test]
    fn a_code_length_symbol_outside_the_alphabet_is_refused() {
        assert_eq!(length_op(0), Ok(LengthOp::Literal(0)));
        assert_eq!(length_op(15), Ok(LengthOp::Literal(15)));
        assert_eq!(length_op(16), Ok(LengthOp::RepeatPrevious));
        assert_eq!(
            length_op(17),
            Ok(LengthOp::RepeatZero {
                symbol: 17,
                base: 3,
                extra: 3
            })
        );
        assert_eq!(
            length_op(18),
            Ok(LengthOp::RepeatZero {
                symbol: 18,
                base: 11,
                extra: 7
            })
        );
        for symbol in [19u16, 20, 287, u16::MAX] {
            assert_eq!(
                length_op(symbol),
                Err(InflateError::InvalidSymbol(symbol)),
                "{symbol}"
            );
        }
    }

    #[test]
    fn reading_zero_bits_consumes_nothing() {
        let mut br = BitReader::new(&[0b0000_0001]);
        assert_eq!(br.bits(0), Ok(0));
        assert_eq!(br.bit(), Ok(1));
    }

    #[test]
    fn a_code_length_repeat_with_nothing_to_repeat_is_refused() {
        let mut w = BitWriter::new();
        w.value(1, 1);
        w.value(2, 2);
        w.value(0, 5);
        w.value(0, 5);
        w.value(0, 4);
        w.value(1, 3);
        w.value(0, 3);
        w.value(0, 3);
        w.value(0, 3);
        w.code(0, 1);
        assert_eq!(
            inflate(&w.finish(), 4096),
            Err(InflateError::InvalidSymbol(16))
        );
    }
}
