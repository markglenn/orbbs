use anyhow::Result;
use bytes::BytesMut;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use super::{
    frame::TelnetFrame,
    negotiation::{TelnetAction, TelnetOption},
};

pub struct Connection {
    stream: TcpStream,
    buffer: BytesMut,
}

impl Connection {
    pub fn new(stream: TcpStream) -> Self {
        Self {
            stream,
            buffer: BytesMut::with_capacity(4096),
        }
    }

    pub async fn request_terminal_type(&mut self) -> Result<()> {
        self.stream.write_all(&[0xFF, 253, 24]).await?;
        self.stream
            .write_all(&[0xFF, 250, 24, 1, 0xFF, 240])
            .await?;

        Ok(())
    }

    pub async fn send_negotiation(
        &mut self,
        action: TelnetAction,
        option: TelnetOption,
    ) -> Result<()> {
        let action = num::ToPrimitive::to_u8(&action).unwrap();
        let option = num::ToPrimitive::to_u8(&option).unwrap();

        self.stream.write_all(&[0xFF, action, option]).await?;

        Ok(())
    }

    pub async fn next_frame(&mut self) -> Option<TelnetFrame> {
        match TelnetFrame::parse_iac(&mut self.buffer)
            .or_else(|| TelnetFrame::parse_csi(&mut self.buffer))
            .or_else(|| TelnetFrame::parse_data(&mut self.buffer))
        {
            // Some sort of frame exists, return it
            Some(frame) => Some(frame),

            None => {
                // If we didn't find a frame, try to read more data from the socket
                match self.stream.read_buf(&mut self.buffer).await {
                    // Reading 0 bytes means the socket has been closed by the client
                    Ok(0) => None,

                    // Reading some bytes means we should try to parse again
                    Ok(_) => Some(TelnetFrame::Next),

                    // Reading failed, so we assume the socket has been closed
                    Err(_) => None,
                }
            }
        }
    }

    pub async fn send(&mut self, data: &[u8]) -> Result<()> {
        self.stream.write_all(data).await?;

        Ok(())
    }
}
