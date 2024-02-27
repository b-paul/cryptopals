// already used 3 nightly features :sunglasses:
#![feature(exclusive_range_pattern)]
#![feature(iterator_try_collect)]
#![feature(option_get_or_insert_default)]

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HexDecodeError {
    InvalidByte(u8),
}

pub fn from_hex(bytes: &[u8]) -> Result<Vec<u8>, HexDecodeError> {
    let mut cur_byte = 0;
    let mut output = Vec::new();

    for (i, b) in bytes.iter().copied().enumerate() {
        cur_byte <<= 4;
        cur_byte |= match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => return Err(HexDecodeError::InvalidByte(b)),
        };
        if i % 2 == 1 {
            output.push(cur_byte);
            cur_byte = 0;
        }
    }

    if bytes.len() % 2 == 1 {
        output.push(cur_byte);
    }

    Ok(output)
}

pub fn to_base64(bytes: &[u8]) -> Vec<u8> {
    bytes
        .chunks(3)
        .flat_map(|bytes| {
            let mut sextuples: Vec<Option<u8>> = vec![None; 4];
            for (i, b) in bytes.into_iter().enumerate() {
                // each byte will write to two sextets since 6 < 8
                // write the upper 6/4/2 bits to the first sextet
                *sextuples[i].get_or_insert_default() |= (b >> 2 * i + 2) & 0x3F;
                // write the lower 2/4/6 bits to the second sextet
                *sextuples[i + 1].get_or_insert_default() |= (b & 0xFF >> 6 - 2 * i) << 4 - 2 * i;
            }
            sextuples.into_iter().map(|x| match x {
                Some(b) => match b {
                    0..26 => b + b'A',
                    26..52 => b - 26 + b'a',
                    52..62 => b - 52 + b'0',
                    62 => b'+',
                    63 => b'/',
                    _ => panic!("Illegal base64 sextet {b}"),
                },
                None => b'=',
            })
        })
        .collect()
}

fn main() {
    println!("Main doesn't do anything yet :)");
}

#[test]
fn from_hex_test() {
    assert_eq!(from_hex("414141".as_bytes()), Ok(vec![b'A', b'A', b'A']));
    assert_eq!(from_hex("4F".as_bytes()), Ok(vec![b'O']));
    assert_eq!(from_hex("4f".as_bytes()), Ok(vec![b'O']));
    assert_eq!(
        from_hex("abcdefg".as_bytes()),
        Err(HexDecodeError::InvalidByte(b'g'))
    );
}

#[test]
fn to_base64_test() {
    assert_eq!(
        to_base64("Many hands make light work.".as_bytes()),
        "TWFueSBoYW5kcyBtYWtlIGxpZ2h0IHdvcmsu".as_bytes()
    );
}

#[test]
fn challenge_1_set_1() {
    let input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let output = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
    assert_eq!(
        &to_base64(&from_hex(input.as_bytes()).unwrap()),
        output.as_bytes()
    );
}
