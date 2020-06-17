use thiserror::Error;
#[derive(Error, Debug, PartialEq, Eq)]
pub enum DecodeRLE90Error {
    #[error("insufficient data in input buffer")]
    InsufficientData,

    #[error("insufficient space in output buffer")]
    InsufficientSpace,

    #[error("encountered invalid input sequence at `{0}`")]
    InvalidEscapeSequence(usize),
}

pub fn decode_rle90(in_buf: &[u8], out_buf: &mut [u8]) -> Result<usize, DecodeRLE90Error> {
    let mut in_idx = 0;
    let mut out_idx = 0;
    let mut last_byte = 0;
    loop {
        // If we have consumed the entire input, return the length of the decoded output.
        if in_idx == in_buf.len() {
            return Ok(out_idx);
        }

        if in_buf[in_idx] != 0x90u8 {
            // Case 0 - literal bytes
            last_byte = in_buf[in_idx];

            // Check for sufficient output space.
            if out_idx == out_buf.len() {
                return Err(DecodeRLE90Error::InsufficientSpace);
            }

            out_buf[out_idx] = last_byte;
            in_idx += 1;
            out_idx += 1;
        } else {
            in_idx += 1;

            // Check for sufficient input length when handling escape codes.
            if in_idx == in_buf.len() {
                return Err(DecodeRLE90Error::InsufficientData);
            }

            if in_buf[in_idx] != 0 {
                // Case 1 - repeat last byte
                let rep_count = in_buf[in_idx]-1;

                if rep_count == 0 {
                    // Repeat length of 0 is invalid.
                    return Err(DecodeRLE90Error::InvalidEscapeSequence(in_idx-1));   
                }

                for _ in 0..rep_count {
                    // Check for sufficient output space.
                    if out_idx == out_buf.len() {
                        return Err(DecodeRLE90Error::InsufficientSpace);
                    }

                    out_buf[out_idx] = last_byte;
                    out_idx += 1;
                }

                in_idx += 1;             
            } else {
                // Case 2 - escaped 0x90 byte
                last_byte = 0x90u8;

                // Check for sufficient output space.
                if out_idx == out_buf.len() {
                    return Err(DecodeRLE90Error::InsufficientSpace);
                }

                out_buf[out_idx] = last_byte;
                in_idx += 1;
                out_idx += 1;
            }
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vector1() {
        let b1 = [0xFF, 0x90, 0x04];
        let mut buffer = [0; 10];
        let res = decode_rle90(&b1, &mut buffer);
        assert_eq!(res, Ok(4));
        assert_eq!(buffer[0..4], [0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn test_vector2() {
        let b1 = [0x2B, 0x90, 0x00, 0x90, 0x05];
        let mut buffer = [0; 10];
        let res = decode_rle90(&b1, &mut buffer);
        assert_eq!(res, Ok(6));
        assert_eq!(buffer[0..6], [0x2B, 0x90, 0x90, 0x90, 0x90, 0x90]);
    }

    #[test]
    fn test_insufficient_data_err() {
        let b1 = [0x2B, 0x90];
        let mut buffer = [0; 10];
        let res = decode_rle90(&b1, &mut buffer);
        assert_eq!(res, Err(DecodeRLE90Error::InsufficientData));
    }

    #[test]
    fn test_insufficient_space_err1() {
        let b1 = [0x2B, 0x90, 0xFF];
        let mut buffer = [0; 10];
        let res = decode_rle90(&b1, &mut buffer);
        assert_eq!(res, Err(DecodeRLE90Error::InsufficientSpace));
    }

    #[test]
    fn test_insufficient_space_err2() {
        let b1 = [0x2B, 0x2B, 0x2B];
        let mut buffer = [0; 2];
        let res = decode_rle90(&b1, &mut buffer);
        assert_eq!(res, Err(DecodeRLE90Error::InsufficientSpace));
    }

    #[test]
    fn test_invalid_escape_err() {
        let b1 = [0x2B, 0x90, 0x01];
        let mut buffer = [0; 10];
        let res = decode_rle90(&b1, &mut buffer);
        assert_eq!(res, Err(DecodeRLE90Error::InvalidEscapeSequence(1)));
    }

}
