use bytes::{Buf, BufMut, Bytes, BytesMut, IntoBuf};
use cast::u16;
use pepbut::wire::encode_err;
use std::io::{self, Cursor};
use tokio_codec::{Decoder, Encoder};

/// Implements [`Encoder`] and [`Decoder`].
///
/// TCP messages start with a 2-byte length marker, so we get to handle those differently.
#[derive(Debug)]
#[cfg_attr(feature = "cargo-clippy", allow(stutter))]
pub enum DnsCodec {
    Tcp { len: Option<u16> },
    Udp,
}

impl DnsCodec {
    pub fn tcp() -> DnsCodec {
        DnsCodec::Tcp { len: None }
    }

    pub fn udp() -> DnsCodec {
        DnsCodec::Udp
    }
}

impl Decoder for DnsCodec {
    type Item = Bytes;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> io::Result<Option<Bytes>> {
        Ok(match self {
            DnsCodec::Tcp {
                len: ref mut self_len,
            } => {
                let len = match self_len {
                    Some(len) => *len,
                    None => {
                        if src.len() >= 2 {
                            src.split_to(2).into_buf().get_u16_be()
                        } else {
                            return Ok(None);
                        }
                    }
                };
                if src.len() >= (len as usize) {
                    *self_len = None;
                    Some(src.split_to(len as usize).freeze())
                } else {
                    *self_len = Some(len);
                    None
                }
            }
            DnsCodec::Udp => {
                if src.is_empty() {
                    None
                } else {
                    Some(src.take().freeze())
                }
            }
        })
    }
}

impl Encoder for DnsCodec {
    type Item = Bytes;
    type Error = io::Error;

    fn encode(&mut self, item: Bytes, dst: &mut BytesMut) -> io::Result<()> {
        if let DnsCodec::Tcp { .. } = self {
            if let Ok(len) = u16(item.len()) {
                dst.reserve(2);
                dst.put_u16_be(len);
            } else {
                dst.reserve(8);
                dst.put(encode_err(Cursor::new(item).get_u16_be(), 2));
                return Ok(());
            }
        }
        dst.reserve(item.len());
        dst.put(&item);
        Ok(())
    }
}
