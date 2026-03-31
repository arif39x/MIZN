use std::sync::Arc;
use tokio::io::{AsyncReadExt};
use tokio::net::UnixListener;
use tokio::sync::RwLock;
use mizn_common::ipc::IpcCommand;

pub fn start_telemetry_socket() -> Result<Arc<RwLock<Vec<tokio::net::UnixStream>>>, std::io::Error> {
    let socket_path = "/run/miznd.sock";
    let _ = std::fs::remove_file(socket_path);
    let listener = UnixListener::bind(socket_path)?;
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
