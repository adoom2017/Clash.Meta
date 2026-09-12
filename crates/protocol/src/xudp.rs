//! Single-session XUDP over VLESS command 3. Wire layout is documented in
//! docs/vless-protocol.md; this implementation does not pool unrelated flows.
use crate::{BoxStream, Datagram, Target, vless};
use anyhow::{Result, ensure};
use async_trait::async_trait;
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::Mutex;

const SESSION_ID: u16 = 0;
const NEW: u8 = 1;
const KEEP: u8 = 2;
const END: u8 = 3;
const KEEPALIVE: u8 = 4;
const DATA: u8 = 1;
const ERROR: u8 = 2;
const UDP: u8 = 2;
const MAX_METADATA: usize = 512;
const MAX_PAYLOAD: usize = 65507;

struct Writer {
    stream: WriteHalf<BoxStream>,
    first: bool,
    usable: bool,
}

struct Reader {
    stream: ReadHalf<BoxStream>,
    usable: bool,
}

pub struct Session {
    target: Target,
    reader: Mutex<Reader>,
    writer: Mutex<Writer>,
}

impl Session {
    pub fn new(stream: BoxStream, target: Target) -> Self {
        let (reader, writer) = tokio::io::split(stream);
        Self {
            target,
            reader: Mutex::new(Reader {
                stream: reader,
                usable: true,
            }),
            writer: Mutex::new(Writer {
                stream: writer,
                first: true,
                usable: true,
            }),
        }
    }
}

fn packet(target: &Target, payload: &[u8], first: bool) -> Result<Vec<u8>> {
    ensure!(payload.len() <= MAX_PAYLOAD, "XUDP payload exceeds limit");
    let mut frame = vec![0, 0];
    frame.extend_from_slice(&SESSION_ID.to_be_bytes());
    frame.extend_from_slice(&[if first { NEW } else { KEEP }, DATA, UDP]);
    vless::encode_address(target, &mut frame)?;
    let size = (frame.len() - 2) as u16;
    frame[..2].copy_from_slice(&size.to_be_bytes());
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(payload);
    Ok(frame)
}

fn metadata(bytes: &[u8], default: &Target) -> Result<(Target, bool)> {
    ensure!(
        (4..=MAX_METADATA).contains(&bytes.len()),
        "invalid XUDP metadata length"
    );
    let id = u16::from_be_bytes([bytes[0], bytes[1]]);
    let status = bytes[2];
    let flags = bytes[3];
    ensure!(flags & !(DATA | ERROR) == 0, "invalid XUDP options");
    ensure!(flags & ERROR == 0, "XUDP peer rejected session");
    ensure!(
        status == KEEPALIVE || id == SESSION_ID,
        "unexpected XUDP session ID"
    );
    match status {
        END => {
            return Err(
                io::Error::new(io::ErrorKind::ConnectionAborted, "XUDP session ended").into(),
            );
        }
        KEEP | KEEPALIVE => {}
        _ => anyhow::bail!("unexpected XUDP frame status"),
    }
    let target = if bytes.len() == 4 {
        default.clone()
    } else {
        ensure!(status == KEEP && bytes[4] == UDP, "invalid XUDP network");
        let (target, consumed) = vless::decode_address(&bytes[5..])?;
        ensure!(consumed + 5 == bytes.len(), "trailing XUDP metadata");
        target
    };
    ensure!(
        status != KEEPALIVE || flags == 0,
        "XUDP keepalive cannot carry data"
    );
    Ok((target, flags & DATA != 0))
}

#[async_trait]
impl Datagram for Session {
    async fn send(&self, target: &Target, payload: &[u8]) -> Result<()> {
        ensure!(target == &self.target, "XUDP session target changed");
        let mut writer = self.writer.lock().await;
        ensure!(writer.usable, "XUDP writer interrupted or closed");
        let frame = packet(target, payload, writer.first)?;
        // An interrupted frame cannot be retried on this byte stream. Mark it
        // unusable before the first await, including when the future is dropped.
        writer.usable = false;
        writer.stream.write_all(&frame).await?;
        writer.stream.flush().await?;
        writer.first = false;
        writer.usable = true;
        Ok(())
    }

    async fn recv(&self) -> Result<(Target, Vec<u8>)> {
        let mut reader = self.reader.lock().await;
        ensure!(reader.usable, "XUDP reader interrupted or closed");
        reader.usable = false;
        for _ in 0..256 {
            let length = reader.stream.read_u16().await? as usize;
            ensure!(
                (4..=MAX_METADATA).contains(&length),
                "invalid XUDP metadata length"
            );
            let mut header = vec![0; length];
            reader.stream.read_exact(&mut header).await?;
            let (target, data) = metadata(&header, &self.target)?;
            if !data {
                continue;
            }
            let length = reader.stream.read_u16().await? as usize;
            ensure!(length <= MAX_PAYLOAD, "XUDP payload exceeds limit");
            let mut payload = vec![0; length];
            reader.stream.read_exact(&mut payload).await?;
            reader.usable = true;
            return Ok((target, payload));
        }
        anyhow::bail!("too many XUDP control frames without data")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn golden_new_and_keep_packets() {
        let target = Target::new("1.2.3.4", 53).unwrap();
        assert_eq!(
            packet(&target, &[0xab, 0xcd], true).unwrap(),
            [0, 12, 0, 0, 1, 1, 2, 0, 53, 1, 1, 2, 3, 4, 0, 2, 0xab, 0xcd]
        );
        let next = packet(&target, &[], false).unwrap();
        assert_eq!(next[4], KEEP);
        assert_eq!(&next[14..], &[0, 0]);
        assert!(packet(&target, &vec![0; MAX_PAYLOAD + 1], true).is_err());
    }

    #[tokio::test]
    async fn fragmented_response_addresses_keepalives_and_empty_datagrams() {
        let target = Target::new("example.com", 53).unwrap();
        let reply = Target::new("2001:db8::1", 53).unwrap();
        let (local, mut peer) = tokio::io::duplex(1);
        let session = Session::new(Box::new(local), target.clone());
        let mut frame = vec![0, 4, 0, 0, KEEPALIVE, 0];
        let mut response = packet(&reply, b"abc", false).unwrap();
        frame.append(&mut response);
        frame.extend_from_slice(&[0, 4, 0, 0, KEEP, DATA, 0, 0]);
        let task = tokio::spawn(async move {
            peer.write_all(&frame).await.unwrap();
        });
        assert_eq!(session.recv().await.unwrap(), (reply, b"abc".to_vec()));
        assert_eq!(session.recv().await.unwrap(), (target, vec![]));
        task.await.unwrap();
        assert!(session.recv().await.is_err());
    }

    #[test]
    fn rejects_invalid_headers() {
        let target = Target::new("example.com", 53).unwrap();
        for header in [
            vec![],
            vec![0, 0, KEEP],
            vec![0, 1, KEEP, DATA],
            vec![0, 0, NEW, DATA],
            vec![0, 0, END, 0],
            vec![0, 0, KEEP, ERROR],
            vec![0, 0, KEEP, 4],
            vec![0, 0, KEEP, DATA, 1],
            vec![0, 0, KEEPALIVE, DATA],
        ] {
            assert!(metadata(&header, &target).is_err(), "{header:?}");
        }
    }

    #[tokio::test]
    async fn interrupted_read_cannot_desynchronize_next_packet() {
        let (local, mut peer) = tokio::io::duplex(16);
        let session = Session::new(Box::new(local), Target::new("example.com", 53).unwrap());
        peer.write_all(&[0]).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(10), session.recv())
                .await
                .is_err()
        );
        let error = session.recv().await.unwrap_err();
        assert!(error.to_string().contains("interrupted"));
    }
}
