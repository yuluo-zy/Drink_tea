// Copyright 2016-2020 Chang Lan
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

use std::{cmp, fmt, fs, io};
use std::convert::TryInto;
use std::fs::File;
use std::io::{BufRead, BufReader, Cursor, Error as IoError, Read, Write};
use std::net::{Ipv4Addr, UdpSocket};
use std::os::unix::io::{AsRawFd, RawFd};
use std::str::FromStr;

use libc::*;

use crate::error::Error;

const MTU: &'static str = "1380";
#[cfg(all(target_os = "linux", not(target_env = "musl")))]
const TUNSETIFF: c_ulong = 0x400454ca;

#[repr(C)]
union IfReqData {
    flags: libc::c_short,
    value: libc::c_int,
    addr: (libc::c_short, Ipv4Addr),
    _dummy: [u8; 24],
}

#[repr(C)]
struct IfReq {
    ifr_name: [u8; libc::IF_NAMESIZE],
    data: IfReqData,
}

impl IfReq {
    fn new(name: &str) -> Self {
        assert!(name.len() < libc::IF_NAMESIZE);
        let mut ifr_name = [0; libc::IF_NAMESIZE];
        ifr_name[..name.len()].clone_from_slice(name.as_bytes());
        Self { ifr_name, data: IfReqData { _dummy: [0; 24] } }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq)]
pub enum Type {
    /// Tun interface: This interface transports IP packets.
    #[serde(rename = "tun")]
    Tun,
    /// Tap interface: This interface transports Ethernet frames.
    #[serde(rename = "tap")]
    Tap,
}

impl fmt::Display for Type {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match *self {
            Type::Tun => write!(formatter, "tun"),
            Type::Tap => write!(formatter, "tap"),
        }
    }
}

impl FromStr for Type {
    type Err = &'static str;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Ok(match &text.to_lowercase() as &str {
            "tun" => Self::Tun,
            "tap" => Self::Tap,
            _ => return Err("Unknown device type"),
        })
    }
}

#[derive(Clone)]
pub struct MsgBuffer {
    space_before: usize,
    buffer: [u8; 65535],
    start: usize,
    end: usize,
}

impl MsgBuffer {
    pub fn new(space_before: usize) -> Self {
        Self { buffer: [0; 65535], space_before, start: space_before, end: space_before }
    }

    pub fn get_start(&self) -> usize {
        self.start
    }

    pub fn set_start(&mut self, start: usize) {
        self.start = start
    }

    pub fn prepend_byte(&mut self, byte: u8) {
        self.start -= 1;
        self.buffer[self.start] = byte
    }

    pub fn take_prefix(&mut self) -> u8 {
        let byte = self.buffer[self.start];
        self.start += 1;
        byte
    }

    pub fn buffer(&mut self) -> &mut [u8] {
        &mut self.buffer[self.start..]
    }

    pub fn message(&self) -> &[u8] {
        &self.buffer[self.start..self.end]
    }

    pub fn take(&mut self) -> Option<&[u8]> {
        if self.start != self.end {
            let end = self.end;
            self.end = self.start;
            Some(&self.buffer[self.start..end])
        } else {
            None
        }
    }

    pub fn message_mut(&mut self) -> &mut [u8] {
        &mut self.buffer[self.start..self.end]
    }

    pub fn set_length(&mut self, length: usize) {
        self.end = self.start + length
    }

    pub fn clone_from(&mut self, other: &[u8]) {
        self.set_length(other.len());
        self.message_mut().clone_from_slice(other);
    }

    pub fn len(&self) -> usize {
        self.end - self.start
    }

    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }

    pub fn clear(&mut self) {
        self.set_start(self.space_before);
        self.set_length(0)
    }
}

pub trait Device: AsRawFd {
    fn get_type(&self) -> Type;

    /// Returns the interface name of this device.
    fn ifname(&self) -> &str;

    fn read(&mut self, buffer: &mut MsgBuffer) -> Result<(), Error>;

    fn write(&mut self, buffer: &mut MsgBuffer) -> Result<(), Error>;

    fn get_ip(&self) -> Result<Ipv4Addr, Error>;
}

pub struct TunTapDevice {
    fd: File,
    ifname: String,
    type_: Type,
}

impl TunTapDevice {
    #[allow(clippy::useless_conversion)]
    pub fn new(ifname: &str, type_: Type, path: Option<&str>) -> io::Result<Self> {
        let path = path.unwrap_or_else(|| Self::default_path(type_));
        let fd = fs::OpenOptions::new().read(true).write(true).open(path)?;
        let flags = match type_ {
            Type::Tun => libc::IFF_TUN | libc::IFF_NO_PI,
            Type::Tap => libc::IFF_TAP | libc::IFF_NO_PI,
        };
        let mut ifreq = IfReq::new(ifname);
        ifreq.data.flags = flags as libc::c_short;
        let res = unsafe { libc::ioctl(fd.as_raw_fd(), TUNSETIFF.try_into().unwrap(), &mut ifreq) };
        match res {
            0 => {
                let mut ifname = String::with_capacity(32);
                let mut cursor = Cursor::new(ifreq.ifr_name);
                cursor.read_to_string(&mut ifname)?;
                ifname = ifname.trim_end_matches('\0').to_owned();
                Ok(Self { fd, ifname, type_ })
            }
            _ => Err(IoError::last_os_error()),
        }
    }

    /// Returns the default device path for a given type
    #[inline]
    pub fn default_path(type_: Type) -> &'static str {
        match type_ {
            Type::Tun | Type::Tap => "/dev/net/tun",
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[inline]
    fn correct_data_after_read(&mut self, _buffer: &mut MsgBuffer) {}

    #[cfg(any(
    target_os = "bitrig",
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "ios",
    target_os = "macos",
    target_os = "netbsd",
    target_os = "openbsd"
    ))]
    #[inline]
    fn correct_data_after_read(&mut self, buffer: &mut MsgBuffer) {
        if self.type_ == Type::Tun {
            // BSD-based systems add a 4-byte header containing the Ethertype for TUN
            buffer.set_start(buffer.get_start() + 4);
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[inline]
    fn correct_data_before_write(&mut self, _buffer: &mut MsgBuffer) {}

    #[cfg(any(
    target_os = "bitrig",
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "ios",
    target_os = "macos",
    target_os = "netbsd",
    target_os = "openbsd"
    ))]
    #[inline]
    fn correct_data_before_write(&mut self, buffer: &mut MsgBuffer) {
        if self.type_ == Type::Tun {
            // BSD-based systems add a 4-byte header containing the Ethertype for TUN
            buffer.set_start(buffer.get_start() - 4);
            match buffer.message()[4] >> 4 {
                // IP version
                4 => buffer.message_mut()[0..4].copy_from_slice(&[0x00, 0x00, 0x08, 0x00]),
                6 => buffer.message_mut()[0..4].copy_from_slice(&[0x00, 0x00, 0x86, 0xdd]),
                _ => unreachable!(),
            }
        }
    }

    pub fn get_overhead(&self) -> usize {
        40 /* for outer IPv6 header, can't be sure to only have IPv4 peers */
            + 8 /* for outer UDP header */
            + 1 /* message type header */
            + match self.type_ {
            Type::Tap => 14, /* inner ethernet header */
            Type::Tun => 0
        }
    }

    pub fn set_mtu(&self, value: Option<usize>) -> io::Result<()> {
        let value = match value {
            Some(value) => value,
            None => {
                let default_device = get_default_device()?;
                get_device_mtu(&default_device)? - self.get_overhead()
            }
        };
        info!("Setting MTU {} on device {}", value, self.ifname);
        set_device_mtu(&self.ifname, value)
    }

    pub fn configure(&self, addr: Ipv4Addr, netmask: Ipv4Addr) -> io::Result<()> {
        set_device_addr(&self.ifname, addr)?;
        set_device_netmask(&self.ifname, netmask)?;
        set_device_enabled(&self.ifname, true)
    }

    pub fn get_rp_filter(&self) -> io::Result<u8> {
        Ok(cmp::max(get_rp_filter("all")?, get_rp_filter(&self.ifname)?))
    }

    pub fn fix_rp_filter(&self) -> io::Result<()> {
        if get_rp_filter("all")? > 1 {
            info!("Setting net.ipv4.conf.all.rp_filter=1");
            set_rp_filter("all", 1)?
        }
        if get_rp_filter(&self.ifname)? != 1 {
            info!("Setting net.ipv4.conf.{}.rp_filter=1", self.ifname);
            set_rp_filter(&self.ifname, 1)?
        }
        Ok(())
    }
}

impl Device for TunTapDevice {
    fn get_type(&self) -> Type {
        self.type_
    }

    fn ifname(&self) -> &str {
        &self.ifname
    }

    fn read(&mut self, buffer: &mut MsgBuffer) -> Result<(), Error> {
        buffer.clear();
        let read = self.fd.read(buffer.buffer()).map_err(|e| Error::DeviceIo("Read error", e))?;
        buffer.set_length(read);
        self.correct_data_after_read(buffer);
        Ok(())
    }

    fn write(&mut self, buffer: &mut MsgBuffer) -> Result<(), Error> {
        self.correct_data_before_write(buffer);
        match self.fd.write_all(buffer.message()) {
            Ok(_) => self.fd.flush().map_err(|e| Error::DeviceIo("Flush error", e)),
            Err(e) => Err(Error::DeviceIo("Write error", e)),
        }
    }

    fn get_ip(&self) -> Result<Ipv4Addr, Error> {
        get_device_addr(&self.ifname).map_err(|e| Error::DeviceIo("Error getting IP address", e))
    }
}

impl AsRawFd for TunTapDevice {
    #[inline]
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

#[cfg(any(
target_os = "linux",
))]
fn get_default_device() -> io::Result<String> {
    let fd = BufReader::new(File::open("/proc/net/route")?);
    let mut best = None;
    for line in fd.lines() {
        let line = line?;
        let parts = line.split('\t').collect::<Vec<_>>();
        if parts[1] == "00000000" {
            best = Some(parts[0].to_string());
            break;
        }
        if parts[2] != "00000000" {
            best = Some(parts[0].to_string())
        }
    }
    if let Some(ifname) = best {
        Ok(ifname)
    } else {
        Err(io::Error::new(io::ErrorKind::NotFound, "No default interface found".to_string()))
    }
}

#[allow(clippy::useless_conversion)]
fn get_device_mtu(ifname: &str) -> io::Result<usize> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    let mut ifreq = IfReq::new(ifname);
    let res = unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCGIFMTU.try_into().unwrap(), &mut ifreq) };
    match res {
        0 => Ok(unsafe { ifreq.data.value as usize }),
        _ => Err(IoError::last_os_error()),
    }
}

#[allow(clippy::useless_conversion)]
fn set_device_mtu(ifname: &str, mtu: usize) -> io::Result<()> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    let mut ifreq = IfReq::new(ifname);
    ifreq.data.value = mtu as libc::c_int;
    let res = unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCSIFMTU.try_into().unwrap(), &mut ifreq) };
    match res {
        0 => Ok(()),
        _ => Err(IoError::last_os_error()),
    }
}

#[allow(clippy::useless_conversion)]
fn get_device_addr(ifname: &str) -> io::Result<Ipv4Addr> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    let mut ifreq = IfReq::new(ifname);
    let res = unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCGIFADDR.try_into().unwrap(), &mut ifreq) };
    match res {
        0 => {
            let af = unsafe { ifreq.data.addr.0 };
            if af as libc::c_int != libc::AF_INET {
                return Err(io::Error::new(io::ErrorKind::AddrNotAvailable, "Invalid address family".to_owned()));
            }
            let ip = unsafe { ifreq.data.addr.1 };
            Ok(ip)
        }
        _ => Err(IoError::last_os_error()),
    }
}

#[allow(clippy::useless_conversion)]
fn set_device_addr(ifname: &str, addr: Ipv4Addr) -> io::Result<()> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    let mut ifreq = IfReq::new(ifname);
    ifreq.data.addr = (libc::AF_INET as libc::c_short, addr);
    let res = unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCSIFADDR.try_into().unwrap(), &mut ifreq) };
    match res {
        0 => Ok(()),
        _ => Err(IoError::last_os_error()),
    }
}

#[allow(dead_code)]
#[allow(clippy::useless_conversion)]
fn get_device_netmask(ifname: &str) -> io::Result<Ipv4Addr> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    let mut ifreq = IfReq::new(ifname);
    let res = unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCGIFNETMASK.try_into().unwrap(), &mut ifreq) };
    match res {
        0 => {
            let af = unsafe { ifreq.data.addr.0 };
            if af as libc::c_int != libc::AF_INET {
                return Err(io::Error::new(io::ErrorKind::AddrNotAvailable, "Invalid address family".to_owned()));
            }
            let ip = unsafe { ifreq.data.addr.1 };
            Ok(ip)
        }
        _ => Err(IoError::last_os_error()),
    }
}

#[allow(clippy::useless_conversion)]
fn set_device_netmask(ifname: &str, addr: Ipv4Addr) -> io::Result<()> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    let mut ifreq = IfReq::new(ifname);
    ifreq.data.addr = (libc::AF_INET as libc::c_short, addr);
    let res = unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCSIFNETMASK.try_into().unwrap(), &mut ifreq) };
    match res {
        0 => Ok(()),
        _ => Err(IoError::last_os_error()),
    }
}

#[allow(clippy::useless_conversion)]
fn set_device_enabled(ifname: &str, up: bool) -> io::Result<()> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    let mut ifreq = IfReq::new(ifname);
    if unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCGIFFLAGS.try_into().unwrap(), &mut ifreq) } != 0 {
        return Err(IoError::last_os_error());
    }
    if up {
        unsafe { ifreq.data.value |= libc::IFF_UP | libc::IFF_RUNNING }
    } else {
        unsafe { ifreq.data.value &= !libc::IFF_UP }
    }
    let res = unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCSIFFLAGS.try_into().unwrap(), &mut ifreq) };
    match res {
        0 => Ok(()),
        _ => Err(IoError::last_os_error()),
    }
}

#[cfg(any(
target_os = "linux",
))]
fn get_rp_filter(device: &str) -> io::Result<u8> {
    let mut fd = File::open(format!("/proc/sys/net/ipv4/conf/{}/rp_filter", device))?;
    let mut contents = String::with_capacity(10);
    fd.read_to_string(&mut contents)?;
    u8::from_str(contents.trim()).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid rp_filter value"))
}

#[cfg(any(
target_os = "linux",
))]
fn set_rp_filter(device: &str, val: u8) -> io::Result<()> {
    let mut fd = File::create(format!("/proc/sys/net/ipv4/conf/{}/rp_filter", device))?;
    writeln!(fd, "{}", val)
}


#[cfg(test)]
mod tests {
    use std::process;

    use crate::device::*;
    use crate::utils;

    #[test]
    fn create_tun_test() {
        assert!(utils::is_root());

        let tun = Tun::create(10).unwrap();
        let name = tun.name();

        let output = process::Command::new("ifconfig")
            .arg(name)
            .output()
            .expect("failed to create tun device");
        assert!(output.status.success());

        tun.up(1);
    }
}
