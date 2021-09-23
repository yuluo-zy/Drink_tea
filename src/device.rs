use libc::*;
use std::io::{Read, Write};
use std::os::unix::io::{AsRawFd, RawFd};
use std::{fs, io, process};

const MTU: &'static str = "1380";

#[cfg(target_os = "linux")]
use std::path;

#[cfg(target_os = "linux")]
const IFNAMSIZ: usize = 16;
#[cfg(target_os = "linux")]
const IFF_TUN: c_short = 0x0001;
#[cfg(target_os = "linux")]
const IFF_NO_PI: c_short = 0x1000;
#[cfg(all(target_os = "linux", target_env = "musl"))]
const TUNSETIFF: c_int = 0x400454ca;
#[cfg(all(target_os = "linux", not(target_env = "musl")))]
const TUNSETIFF: c_ulong = 0x400454ca;


#[cfg(target_os = "linux")]
#[repr(C)]
pub struct IoctlFlagsData {
    pub ifr_name: [u8; IFNAMSIZ],
    pub ifr_flags: c_short,
}

#[cfg(target_os = "linux")]
impl IoctlFlagsData {
    fn ioctl_default(name: u8) -> Self {
        IoctlFlagsData {
            ifr_name: {
                let mut buffer = [0u8; IFNAMSIZ];
                let full_name = format!("tun{}", name);
                buffer[..full_name.len()].clone_from_slice(full_name.as_bytes());
                buffer
            },
            ifr_flags: IFF_TUN | IFF_NO_PI,
        }
    }
}

#[cfg(target_os = "macos")]
use std::mem;
#[cfg(target_os = "macos")]
use std::os::unix::io::FromRawFd;

#[cfg(target_os = "macos")]
const AF_SYS_CONTROL: u16 = 2;
#[cfg(target_os = "macos")]
const AF_SYSTEM: u8 = 32;
#[cfg(target_os = "macos")]
const PF_SYSTEM: c_int = AF_SYSTEM as c_int;
#[cfg(target_os = "macos")]
const SYSPROTO_CONTROL: c_int = 2;
#[cfg(target_os = "macos")]
const UTUN_OPT_IFNAME: c_int = 2;
#[cfg(target_os = "macos")]
const CTLIOCGINFO: c_ulong = 0xc0644e03;
#[cfg(target_os = "macos")]
const UTUN_CONTROL_NAME: &'static str = "com.apple.net.utun_control";

#[cfg(target_os = "macos")]
#[repr(C)]
pub struct CtlInfo {
    pub ctl_id: u32,
    pub ctl_name: [u8; 96],
}

#[cfg(target_os = "macos")]
impl Default for CtlInfo {
    fn default() -> Self {
        CtlInfo {
            ctl_id: 0,
            ctl_name: {
                let mut buffer = [0u8; 96];
                buffer[..UTUN_CONTROL_NAME.len()].clone_from_slice(UTUN_CONTROL_NAME.as_bytes());
                buffer
            },
        }
    }
}

#[cfg(target_os = "macos")]
#[repr(C)]
pub struct SockaddrCtl {
    pub sc_len: u8,
    pub sc_family: u8,
    pub ss_sysaddr: u16,
    pub sc_id: u32,
    pub sc_unit: u32,
    pub sc_reserved: [u32; 5],
}

#[cfg(target_os = "macos")]
impl SockaddrCtl {
    fn sock_default(id_t: u32, name: u8) -> Self {
        SockaddrCtl {
            sc_id: id_t,
            sc_len: mem::size_of::<SockaddrCtl>() as u8,
            sc_family: AF_SYSTEM,
            ss_sysaddr: AF_SYS_CONTROL,
            sc_unit: name as u32 + 1,
            sc_reserved: [0; 5],
        }
    }
}

pub struct Tun {
    handle: fs::File,
    if_name: String,
}

impl AsRawFd for Tun {
    #[inline]
    fn as_raw_fd(&self) -> RawFd {
        self.handle.as_raw_fd()
    }
}

impl Tun {
    #[cfg(target_os = "linux")]
    pub fn create(name: u8) -> Result<Tun, io::Error> {
        let path = path::Path::new("/dev/net/tun");
        let file = fs::OpenOptions::new().read(true).write(true).open(&path)?;

        let mut req = IoctlFlagsData::ioctl_default(name);

        let res = unsafe { ioctl(file.as_raw_fd(), TUNSETIFF, &mut req) };
        if res < 0 {
            return Err(io::Error::last_os_error());
        }

        let size = req.ifr_name.iter().position(|&r| r == 0).unwrap();
        let tun = Tun {
            handle: file,
            if_name: String::from_utf8(req.ifr_name[..size].to_vec()).unwrap(),
        };
        Ok(tun)
    }

    #[cfg(target_os = "macos")]
    pub fn create(name: u8) -> Result<Self, io::Error> {
        let handle = {
            let fd = unsafe { socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            unsafe { fs::File::from_raw_fd(fd) }
        };

        let mut info = CtlInfo::default();

        let res = unsafe { ioctl(handle.as_raw_fd(), CTLIOCGINFO, &mut info) };
        if res != 0 {
            // Files are automatically closed when they go out of scope.
            return Err(io::Error::last_os_error());
        }

        let addr = SockaddrCtl::sock_default(info.ctl_id, name as u32);

        // If connect() is successful, a tun%d device will be created, where "%d"
        // is our sc_unit-1
        let res = unsafe {
            let addr_ptr = &addr as *const SockaddrCtl;
            connect(
                handle.as_raw_fd(),
                addr_ptr as *const sockaddr,
                mem::size_of_val(&addr) as socklen_t,
            )
        };
        if res != 0 {
            return Err(io::Error::last_os_error());
        }

        let mut name_buf = [0u8; 64];
        let mut name_length: socklen_t = 64;
        let res = unsafe {
            getsockopt(
                handle.as_raw_fd(),
                SYSPROTO_CONTROL,
                UTUN_OPT_IFNAME,
                &mut name_buf as *mut _ as *mut c_void,
                &mut name_length as *mut socklen_t,
            )
        };
        if res != 0 {
            return Err(io::Error::last_os_error());
        }
        // F_SETFL 将描述符状态标志设置为arg。
        // O_NONBLOCK 非阻塞 I/O；如果没有数据可供读取
        // 调用，或者如果写操作会阻塞，则读取或
        // write 调用返回 -1，错误为 EAGAIN。
        let res = unsafe { fcntl(handle.as_raw_fd(), F_SETFL, O_NONBLOCK) };
        if res == -1 {
            return Err(io::Error::last_os_error());
        }
        // F_SETFD 将与 fildes 关联的 close-on-exec 标志设置为arg
        // 的低位（0 或 1 同上）。
        // close-on-exec 标志
        // 描述符fildes。如果低位
        // 返回值为 0，文件将保持打开状态

        let res = unsafe { fcntl(handle.as_raw_fd(), F_SETFD, FD_CLOEXEC) };
        if res == -1 {
            return Err(io::Error::last_os_error());
        }

        let tun = Tun {
            handle,
            if_name: {
                let len = name_buf.iter().position(|&r| r == 0).unwrap();
                String::from_utf8(name_buf[..len].to_vec()).unwrap()
            },
        };
        Ok(tun)
    }

    pub fn name(&self) -> &str {
        &self.if_name
    }

    pub fn up(&self, self_id: u8) {
        let mut status = if cfg!(target_os = "linux") {
            process::Command::new("ifconfig")
                .arg(self.if_name.clone())
                .arg(format!("10.10.10.{}/24", self_id))
                .status()
                .unwrap()
        } else if cfg!(target_os = "macos") {
            process::Command::new("ifconfig")
                .arg(self.if_name.clone())
                .arg(format!("10.10.10.{}", self_id))
                .arg("10.10.10.1")
                .status()
                .unwrap()
        } else {
            unimplemented!()
        };

        assert!(status.success());

        status = if cfg!(target_os = "linux") {
            process::Command::new("ifconfig")
                .arg(self.if_name.clone())
                .arg("mtu")
                .arg(MTU)
                .arg("up")
                .status()
                .unwrap()
        } else if cfg!(target_os = "macos") {
            process::Command::new("ifconfig")
                .arg(self.if_name.clone())
                .arg("mtu")
                .arg(MTU)
                .arg("up")
                .status()
                .unwrap()
        } else {
            unimplemented!()
        };

        assert!(status.success());
    }
}

impl Read for Tun {
    #[cfg(target_os = "linux")]
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.handle.read(buf)
    }

    #[cfg(target_os = "macos")]
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut data = [0u8; 1600];
        let result = self.handle.read(&mut data);
        match result {
            Ok(len) => {
                buf[..len - 4].clone_from_slice(&data[4..len]);
                Ok(if len > 4 { len - 4 } else { 0 })
            }
            Err(e) => Err(e),
        }
    }
}

impl Write for Tun {
    #[cfg(target_os = "linux")]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.handle.write(buf)
    }

    #[cfg(target_os = "macos")]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let ip_v = buf[0] & 0xf;
        let mut data: Vec<u8> = if ip_v == 6 {
            vec![0, 0, 0, 10]
        } else {
            vec![0, 0, 0, 2]
        };
        data.write_all(buf).unwrap();
        match self.handle.write(&data) {
            Ok(len) => Ok(if len > 4 { len - 4 } else { 0 }),
            Err(e) => Err(e),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.handle.flush()
    }
}

#[cfg(test)]
mod tests {
    use crate::device::*;
    use crate::utils;
    use std::process;

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
