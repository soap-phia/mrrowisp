use bytes::{ Buf, BufMut, Bytes, BytesMut };
use thiserror::Error;

pub const MAXMSG: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    Connect = 0x01,
    Data = 0x02,
    Continue = 0x03,
    Close = 0x04,
    Info = 0x05,
    TwispResize = 0xf0,
}

impl TryFrom<u8> for PacketType {
    type Error = ProtocolError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            0x01 => PacketType::Connect,
            0x02 => PacketType::Data,
            0x03 => PacketType::Continue,
            0x04 => PacketType::Close,
            0x05 => PacketType::Info,
            0xf0 => PacketType::TwispResize,
            _ => {
                return Err(ProtocolError::UnknownPacket(value));
            }
        })
    }
}

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("packet too short")]
    TooShort,
    #[error("packet too large")]
    TooLarge,
    #[error("unknown packet type {0:02x}")] UnknownPacket(u8),
    #[error("invalid payload: {0}")] Invalid(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamType {
    Tcp = 0x01,
    Udp = 0x02,
    Twisp = 0x03,
}

impl TryFrom<u8> for StreamType {
    type Error = ProtocolError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            0x01 => StreamType::Tcp,
            0x02 => StreamType::Udp,
            0x03 => StreamType::Twisp,
            _ => {
                return Err(ProtocolError::Invalid("stream type"));
            }
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Packet {
    Connect {
        stream_id: u32,
        stream_type: StreamType,
        port: u16,
        host: String,
    },
    Data {
        stream_id: u32,
        payload: Bytes,
    },
    Continue {
        stream_id: u32,
        remaining: u32,
    },
    Close {
        stream_id: u32,
        reason: u8,
    },
    Info {
        stream_id: u32,
        major: u8,
        minor: u8,
        extensions: Bytes,
    },
    TwispResize {
        stream_id: u32,
        rows: u16,
        cols: u16,
    },
}

impl Packet {
    pub fn encode(&self, out: &mut BytesMut) {
        self.encode_into(out)
    }

    pub fn encode_into<B: BufMut>(&self, out: &mut B) {
        match self {
            Packet::Connect { stream_id, stream_type, port, host } => {
                out.put_u8(PacketType::Connect as u8);
                out.put_u32_le(*stream_id);
                out.put_u8(*stream_type as u8);
                out.put_u16_le(*port);
                out.put_slice(host.as_bytes());
            }
            Packet::Data { stream_id, payload } => {
                out.put_u8(PacketType::Data as u8);
                out.put_u32_le(*stream_id);
                out.put_slice(payload);
            }
            Packet::Continue { stream_id, remaining } => {
                out.put_u8(PacketType::Continue as u8);
                out.put_u32_le(*stream_id);
                out.put_u32_le(*remaining);
            }
            Packet::Close { stream_id, reason } => {
                out.put_u8(PacketType::Close as u8);
                out.put_u32_le(*stream_id);
                out.put_u8(*reason);
            }
            Packet::Info { stream_id, major, minor, extensions } => {
                out.put_u8(PacketType::Info as u8);
                out.put_u32_le(*stream_id);
                out.put_u8(*major);
                out.put_u8(*minor);
                out.put_slice(extensions);
            }
            Packet::TwispResize { stream_id, rows, cols } => {
                out.put_u8(PacketType::TwispResize as u8);
                out.put_u32_le(*stream_id);
                out.put_u16_le(*rows);
                out.put_u16_le(*cols);
            }
        }
    }

    pub fn decode_from(data: &[u8]) -> Result<Option<Packet>, ProtocolError> {
        if data.len() < 5 {
            return Ok(None);
        }
        if data.len() > MAXMSG {
            return Err(ProtocolError::TooLarge);
        }
        let mut reader = &data[..];
        let kind = PacketType::try_from(reader.get_u8())?;
        let stream_id = reader.get_u32_le();

        let parsed = match kind {
            PacketType::Connect => {
                if reader.len() < 3 {
                    return Err(ProtocolError::TooShort);
                }
                let stream_type = StreamType::try_from(reader.get_u8())?;
                let port = reader.get_u16_le();
                let host = String::from_utf8(reader.to_vec()).map_err(|_|
                    ProtocolError::Invalid("hostname utf-8")
                )?;
                Packet::Connect {
                    stream_id,
                    stream_type,
                    port,
                    host,
                }
            }
            PacketType::Data => {
                let payload = reader.copy_to_bytes(reader.len());
                Packet::Data { stream_id, payload }
            }
            PacketType::Continue => {
                if reader.len() < 4 {
                    return Err(ProtocolError::TooShort);
                }
                let remaining = reader.get_u32_le();
                Packet::Continue {
                    stream_id,
                    remaining,
                }
            }
            PacketType::Close => {
                if reader.len() < 1 {
                    return Err(ProtocolError::TooShort);
                }
                let reason = reader.get_u8();
                Packet::Close { stream_id, reason }
            }
            PacketType::Info => {
                if reader.len() < 2 {
                    return Err(ProtocolError::TooShort);
                }
                let major = reader.get_u8();
                let minor = reader.get_u8();
                let extensions = reader.copy_to_bytes(reader.len());
                Packet::Info {
                    stream_id,
                    major,
                    minor,
                    extensions,
                }
            }
            PacketType::TwispResize => {
                if reader.len() < 4 {
                    return Err(ProtocolError::TooShort);
                }
                let rows = reader.get_u16_le();
                let cols = reader.get_u16_le();
                Packet::TwispResize {
                    stream_id,
                    rows,
                    cols,
                }
            }
        };

        Ok(Some(parsed))
    }
}

pub fn encode_extensions(extensions: &[Extension]) -> Bytes {
    let mut out = BytesMut::new();
    for ext in extensions {
        out.put_u8(ext.id());
        out.put_u32_le(ext.payload.len() as u32);
        out.extend_from_slice(&ext.payload);
    }
    out.freeze()
}

#[derive(Debug, Clone)]
pub struct Extension {
    pub id: u8,
    pub payload: Bytes,
}

impl Extension {
    pub fn new(id: u8, payload: impl Into<Bytes>) -> Self {
        Self {
            id,
            payload: payload.into(),
        }
    }
    pub fn id(&self) -> u8 {
        self.id
    }
}
