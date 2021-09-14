use futures::future::{self, Either, FutureExt};
use log::info;
use std::io;
use tokio::signal::unix::{signal, SignalKind};

pub async fn create_signal_monitor() -> io::Result<()> {
    // Future resolving to two signal streams. Can fail if setting up signal monitoring fails
    // 表示 SIGTERM 信号。
    //
    // 在 Unix 系统上，发送此信号以关闭进程。默认情况下，进程被这个信号终止。
    let mut sigterm = signal(SignalKind::terminate())?;
    // 表示 SIGINT 信号。
    //
    // 在 Unix 系统上，这个信号被发送来中断程序。默认情况下，进程被这个信号终止。
    let mut sigint = signal(SignalKind::interrupt())?;
    // sigterm.recv().boxed() 不停地接受下一个信号, 使用 boxed 是为了固定住 pin
    let signal_name = match future::select(sigterm.recv().boxed(), sigint.recv().boxed()).await {
        Either::Left(..) => "SIGTERM",
        Either::Right(..) => "SIGINT",
    };

    info!("received {}, exiting", signal_name);

    Ok(())
}
