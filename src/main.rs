// Copyright 2016-2017 Chang Lan
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
#[macro_use]
extern crate log;
#[macro_use]
extern crate serde;

use std::borrow::Borrow;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::Ordering;

use env_logger;
use futures::future::{self, Either};
use futures::FutureExt;
use libc;
use tokio::{self, runtime::Builder};

use crate::common::monitor;

mod cli;
mod common;
mod device;
mod network;
mod packet;
mod utils;
mod error;
mod protocol;

extern "C" fn handle_signal(_: libc::c_int) {
    network::INTERRUPTED.store(true, Ordering::Relaxed);
}

fn main() {
    env_logger::init();

    if !utils::is_root() {
        panic!("Please run as root");
    }
    #[cfg(feature = "multi-threaded")]
    let mut builder = Builder::new_multi_thread();
    builder.worker_threads((num_cpus::get() * 2 + 1));

    #[cfg(not(feature = "multi-threaded"))]
    let mut builder = Builder::new_current_thread();

    let runtime = builder.enable_all().build().expect("create tokio Runtime");

    runtime.block_on(async move {
        let abort_signal = monitor::create_signal_monitor();
        let server: Pin<Box<dyn Future<Output  = ()>>> = match cli::get_args().unwrap() {
            cli::Args::Client(client) =>Box::pin( network::connect(
                client.remote_addr.clone(),
                client.port,
                client.default_route,
                client.remote_addr.clone(),
            )),
            cli::Args::Server(server) => Box::pin(network::serve(server.port, server.key.clone(), server.dns)),
        };

        tokio::pin!(abort_signal);

        match future::select(server, abort_signal).await {
            Either::Left(((), ..)) => panic!("VPN server exited unexpectly"),
            Either::Right(_) => (),
        }
    });

    println!("SIGINT/SIGTERM captured. Exit.");
}
