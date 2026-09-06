use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::net::UnixListener;
use tokio::sync::RwLock;
use mizn_common::ipc::{IpcCommand, IPC_COMMAND_MAX_FRAME_SIZE};

const SOCKET_GROUP_ENV: &str = "MIZN_SOCKET_GROUP";
const DEFAULT_SOCKET_GROUP: &str = "mizn";

fn configure_socket(path: &str) -> Result<(), std::io::Error> {
    use std::ffi::CString;
    use std::os::unix::fs::{chown, PermissionsExt};

    let group_name = std::env::var(SOCKET_GROUP_ENV)
        .unwrap_or_else(|_| DEFAULT_SOCKET_GROUP.to_string());
    let group_name_c = CString::new(group_name.clone()).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid socket group name")
    })?;

    let group_entry = unsafe { libc::getgrnam(group_name_c.as_ptr()) };
    if group_entry.is_null() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("socket group '{group_name}' does not exist"),
        ));
    }
    let gid = unsafe { (*group_entry).gr_gid };

    // The daemon is privileged, but only members of the dedicated group may
    // read telemetry or submit control commands.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    chown(path, None, Some(gid))?;
    Ok(())
}

pub fn start_telemetry_socket() -> Result<Arc<RwLock<Vec<tokio::net::UnixStream>>>, std::io::Error> {
    let socket_path = "/run/miznd.sock";
    let _ = std::fs::remove_file(socket_path);
    let listener = UnixListener::bind(socket_path)?;
    configure_socket(socket_path)?;

    let connections = Arc::new(RwLock::new(Vec::<tokio::net::UnixStream>::with_capacity(16)));
    let conns = connections.clone();
    
    tokio::spawn(async move {
        while let Ok((s, _)) = listener.accept().await {
            conns.write().await.push(s);
        }
    });

    Ok(connections)
}

pub fn start_command_socket() -> Result<tokio::sync::mpsc::UnboundedReceiver<u32>, std::io::Error> {
    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::unbounded_channel::<u32>();
    let cmd_socket_path = "/run/miznd_cmd.sock";
    let _ = std::fs::remove_file(cmd_socket_path);
    let cmd_listener = UnixListener::bind(cmd_socket_path)?;
    configure_socket(cmd_socket_path)?;
    
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = cmd_listener.accept().await {
            let tx = cmd_tx.clone();
            tokio::spawn(async move {
                loop {
                    match read_command(&mut stream).await {
                        Ok(Some(IpcCommand::BlockIp(ip))) => {
                            let _ = tx.send(ip);
                        }
                        Ok(None) => break,
                        Err(error) => {
                            eprintln!("[miznd] rejecting command connection: {error}");
                            break;
                        }
                    }
                }
            });
        }
    });

    Ok(cmd_rx)
}

async fn read_command<R>(stream: &mut R) -> Result<Option<IpcCommand>, String>
where
    R: AsyncRead + Unpin,
{
    let mut length_buf = [0u8; 4];
    match stream.read_exact(&mut length_buf).await {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(format!("failed to read command frame length: {error}")),
    }

    let frame_len = u32::from_be_bytes(length_buf) as usize;
    if frame_len == 0 || frame_len > IPC_COMMAND_MAX_FRAME_SIZE {
        return Err(format!("invalid command frame length: {frame_len}"));
    }

    let mut frame = vec![0u8; frame_len];
    stream
        .read_exact(&mut frame)
        .await
        .map_err(|error| format!("failed to read command frame: {error}"))?;

    let archived = rkyv::check_archived_root::<IpcCommand>(&frame)
        .map_err(|error| format!("invalid serialized command: {error}"))?;
    rkyv::Deserialize::deserialize(archived, &mut rkyv::Infallible)
        .map(Some)
        .map_err(|error| format!("failed to deserialize command: {error:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rkyv::ser::Serializer;
    use tokio::io::{duplex, AsyncWriteExt};

    fn serialize_command(command: &IpcCommand) -> Vec<u8> {
        let mut buffer = [0u8; 128];
        let mut scratch = [0u8; 128];
        let mut serializer = rkyv::ser::serializers::CompositeSerializer::new(
            rkyv::ser::serializers::BufferSerializer::new(&mut buffer),
            rkyv::ser::serializers::BufferScratch::new(&mut scratch),
            rkyv::Infallible,
        );
        serializer.serialize_value(command).unwrap();
        let len = serializer.pos();
        drop(serializer);
        buffer[..len].to_vec()
    }

    fn frame(command: &IpcCommand) -> Vec<u8> {
        let payload = serialize_command(command);
        let mut result = (payload.len() as u32).to_be_bytes().to_vec();
        result.extend_from_slice(&payload);
        result
    }

    #[tokio::test]
    async fn reads_fragmented_command_frame() {
        let (mut writer, mut reader) = duplex(128);
        let bytes = frame(&IpcCommand::BlockIp(0x7f000001));
        let split = 2;
        writer.write_all(&bytes[..split]).await.unwrap();
        writer.write_all(&bytes[split..]).await.unwrap();

        assert!(matches!(
            read_command(&mut reader).await.unwrap(),
            Some(IpcCommand::BlockIp(0x7f000001))
        ));
    }

    #[tokio::test]
    async fn reads_multiple_coalesced_command_frames() {
        let (mut writer, mut reader) = duplex(256);
        let mut bytes = frame(&IpcCommand::BlockIp(1));
        bytes.extend_from_slice(&frame(&IpcCommand::BlockIp(2)));
        writer.write_all(&bytes).await.unwrap();

        assert!(matches!(read_command(&mut reader).await.unwrap(), Some(IpcCommand::BlockIp(1))));
        assert!(matches!(read_command(&mut reader).await.unwrap(), Some(IpcCommand::BlockIp(2))));
    }

    #[tokio::test]
    async fn rejects_invalid_command_frame_without_panicking() {
        let (mut writer, mut reader) = duplex(128);
        writer.write_all(&4u32.to_be_bytes()).await.unwrap();
        writer.write_all(&[1, 2, 3, 4]).await.unwrap();

        assert!(read_command(&mut reader).await.is_err());
    }

    #[tokio::test]
    async fn rejects_oversized_command_frame_before_allocating() {
        let (mut writer, mut reader) = duplex(128);
        let oversized = (IPC_COMMAND_MAX_FRAME_SIZE as u32 + 1).to_be_bytes();
        writer.write_all(&oversized).await.unwrap();

        assert!(read_command(&mut reader).await.is_err());
    }
}
