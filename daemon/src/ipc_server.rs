use std::sync::Arc;
use tokio::io::{AsyncReadExt};
use tokio::net::UnixListener;
use tokio::sync::RwLock;
use mizn_common::ipc::IpcCommand;

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
        let mut buf = [0u8; 1024];
        while let Ok((mut stream, _)) = cmd_listener.accept().await {
            let tx = cmd_tx.clone();
            tokio::spawn(async move {
                while let Ok(n) = stream.read(&mut buf).await {
                    if n == 0 { break; }
                    let arch = unsafe { rkyv::archived_root::<IpcCommand>(&buf[..n]) };
                    let cmd: IpcCommand = rkyv::Deserialize::deserialize(arch, &mut rkyv::Infallible).unwrap();
                    let IpcCommand::BlockIp(ip) = cmd;
                    let _ = tx.send(ip);
                }
            });
        }
    });

    Ok(cmd_rx)
}
