use bytes::{Buf, BytesMut};

#[derive(Debug, PartialEq)]
pub enum TelnetFrame {
    // Interpret as Command (IAC) telnet command
    IAC(Vec<u8>),

    // Control Sequence Introducer (ANSI Escape sequence)
    CSI(Vec<u8>),

    // Data frame contains raw bytes
    Data(Vec<u8>),

    // No frame available, but more data may be coming
    Next,
}

impl TelnetFrame {
    pub fn parse_iac(buffer: &mut BytesMut) -> Option<Self> {
        // Check the 2nd and 3rd byte
        match (buffer.get(0), buffer.get(1), buffer.get(2)) {
            // IAC + IAC
            (Some(0xFF), Some(&0xFF), _) => {
                buffer.advance(2);
                Some(Self::Data(vec![0xFF]))
            }

            // IAC + SB + ... + SE
            (Some(0xFF), Some(&0xFA), _) => {
                // Needle is equivalent to IAC + SE
                let needle = &[0xFF, 0xF0];

                // Find it in the "haystack"
                match buffer.windows(2).position(|p| p == needle) {
                    Some(i) => {
                        // We found the subsequence, so split after it (including the needle)
                        let iac = buffer.split_to(i + 2).to_vec();

                        return Some(Self::IAC(iac));
                    }
                    None => None,
                }
            }

            // IAC + WILL/WONT/DO/DONT + OPTION
            (Some(0xFF), Some(_), Some(_)) => {
                let iac = buffer.split_to(3);
                Some(Self::IAC(iac.to_vec()))
            }

            _ => None,
        }
    }

    pub fn parse_csi(buffer: &mut BytesMut) -> Option<Self> {
        // Check if the buffer starts with an escape sequence of 'ESC' + '['
        if !buffer.starts_with(&[0x1B, b'[']) {
            return None;
        }

        // Check for a CSI 'final' byte
        buffer
            .iter()
            .skip(2)
            .position(|&b| (0x40..=0x7E).contains(&b))
            .map(|i| {
                // If we found the CSI final byte, return everything up to and
                // including it
                let csi = buffer.split_to(i + 3);
                Self::CSI(csi.to_vec())
            })
    }

    pub fn parse_data(buffer: &mut BytesMut) -> Option<Self> {
        match buffer.iter().position(|b| b == &0xFF || b == &0x1B) {
            // First byte is IAC or CSI start byte, so we have no data to return
            Some(0) => None,

            // Found a start byte, return everything before it
            Some(i) => {
                let raw_bytes = buffer.split_to(i);
                Some(Self::Data(raw_bytes.to_vec()))
            }

            // No start byte found, return the entire buffer
            None => {
                if buffer.is_empty() {
                    return None;
                }

                let raw_bytes = buffer.to_vec();
                buffer.clear();

                Some(Self::Data(raw_bytes))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    #[test]
    fn test_parse_iac() {
        // Test IAC + SB + ... + SE
        let mut buffer = BytesMut::from(&[0xFF, 0xFA, 0x01, 0x02, 0xF0, 0xFF][..]);
        let result = TelnetFrame::parse_iac(&mut buffer);
        assert!(matches!(result, Some(TelnetFrame::IAC(_))));
        if let Some(TelnetFrame::IAC(iac)) = result {
            assert_eq!(iac, vec![0xFF, 0xFA, 0x01, 0x02, 0xF0]);
        }
        assert_eq!(buffer, BytesMut::from(&[0xFF][..]));

        // Test IAC + WILL/WONT/DO/DONT + OPTION
        let mut buffer = BytesMut::from(&[0xFF, 0xFB, 0x03][..]);
        let result = TelnetFrame::parse_iac(&mut buffer);
        assert!(matches!(result, Some(TelnetFrame::IAC(_))));
        if let Some(TelnetFrame::IAC(iac)) = result {
            assert_eq!(iac, vec![0xFF, 0xFB, 0x03]);
        }
        assert_eq!(buffer, BytesMut::new());

        // Test Non IAC
        let mut buffer = BytesMut::from(&[0x01, 0x02, 0x03][..]);
        let result = TelnetFrame::parse_iac(&mut buffer);
        assert_eq!(result, None);
        assert_eq!(buffer, BytesMut::from(&[0x01, 0x02, 0x03][..]));

        // Test Incomplete IAC + SB
        let mut buffer = BytesMut::from(&[0xFF, 0xFA, 0x01, 0x02][..]);
        let result = TelnetFrame::parse_iac(&mut buffer);
        assert_eq!(result, None);
        assert_eq!(buffer, BytesMut::from(&[0xFF, 0xFA, 0x01, 0x02][..]));

        // Test Incomplete IAC + WILL/WONT/DO/DONT
        let mut buffer = BytesMut::from(&[0xFF, 0xFB][..]);
        let result = TelnetFrame::parse_iac(&mut buffer);
        assert_eq!(result, None);
        assert_eq!(buffer, BytesMut::from(&[0xFF, 0xFB][..]));

        // Test double IAC
        let mut buffer = BytesMut::from(&[0xFF, 0xFF, 0x01, 0x02][..]);
        let result = TelnetFrame::parse_iac(&mut buffer);
        assert_eq!(result, TelnetFrame::Data(vec![0xFF]).into());
        assert_eq!(buffer, BytesMut::from(&[0x01, 0x02][..]));
    }

    #[test]
    fn test_parse_data() {
        let mut buffer = BytesMut::from(&[0x01, 0x02, 0xFF, 0x03, 0x04][..]);
        let result = TelnetFrame::parse_data(&mut buffer);
        assert!(matches!(result, Some(TelnetFrame::Data(_))));
        if let Some(TelnetFrame::Data(raw_bytes)) = result {
            assert_eq!(raw_bytes, vec![0x01, 0x02]);
        }
        assert_eq!(buffer, BytesMut::from(&[0xFF, 0x03, 0x04][..]));

        let mut buffer = BytesMut::from(&[0x01, 0x02, 0x1B, 0x03, 0x04][..]);
        let result = TelnetFrame::parse_data(&mut buffer);
        assert!(matches!(result, Some(TelnetFrame::Data(_))));
        if let Some(TelnetFrame::Data(raw_bytes)) = result {
            assert_eq!(raw_bytes, vec![0x01, 0x02]);
        }
        assert_eq!(buffer, BytesMut::from(&[0x1B, 0x03, 0x04][..]));

        let mut buffer = BytesMut::from(&[0x01, 0x02, 0x03, 0x04][..]);
        let result = TelnetFrame::parse_data(&mut buffer);
        assert!(matches!(result, Some(TelnetFrame::Data(_))));
        if let Some(TelnetFrame::Data(raw_bytes)) = result {
            assert_eq!(raw_bytes, vec![0x01, 0x02, 0x03, 0x04]);
        }
        assert_eq!(buffer, BytesMut::new());
    }

    #[test]
    fn test_parse_csi() {
        let mut buffer = BytesMut::from(&[0x1B, b'[', 0x31, 0x3B, 0x32, 0x48][..]);
        let result = TelnetFrame::parse_csi(&mut buffer);
        assert!(matches!(result, Some(TelnetFrame::CSI(_))));
        if let Some(TelnetFrame::CSI(csi)) = result {
            assert_eq!(csi, vec![0x1B, b'[', 0x31, 0x3B, 0x32, 0x48]);
        }

        let mut buffer = BytesMut::from(&[0x1B, b'[', 0x31, 0x3B, 0x32][..]);
        let result = TelnetFrame::parse_csi(&mut buffer);
        assert_eq!(result, None);

        let mut buffer = BytesMut::from(&[0x01, 0x02, 0x03][..]);
        let result = TelnetFrame::parse_csi(&mut buffer);
        assert_eq!(result, None);
    }
}
