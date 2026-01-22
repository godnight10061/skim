#![cfg(all(windows, feature = "cli"))]

use std::ffi::OsStr;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::ptr;
use std::thread;
use std::time::Duration;

type Handle = isize;
type Hpc = Handle;

const INVALID_HANDLE_VALUE: Handle = -1;

const EXTENDED_STARTUPINFO_PRESENT: u32 = 0x0008_0000;
const WAIT_OBJECT_0: u32 = 0;
const WAIT_TIMEOUT: u32 = 0x0000_0102;

const PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE: usize = 0x0002_0016;

#[repr(C)]
#[derive(Copy, Clone)]
struct Coord {
    x: i16,
    y: i16,
}

#[repr(C)]
struct SecurityAttributes {
    n_length: u32,
    lp_security_descriptor: *mut core::ffi::c_void,
    b_inherit_handle: i32,
}

#[repr(C)]
struct ProcessInformation {
    h_process: Handle,
    h_thread: Handle,
    dw_process_id: u32,
    dw_thread_id: u32,
}

#[repr(C)]
struct StartupInfoW {
    cb: u32,
    lp_reserved: *mut u16,
    lp_desktop: *mut u16,
    lp_title: *mut u16,
    dw_x: u32,
    dw_y: u32,
    dw_x_size: u32,
    dw_y_size: u32,
    dw_x_count_chars: u32,
    dw_y_count_chars: u32,
    dw_fill_attribute: u32,
    dw_flags: u32,
    w_show_window: u16,
    cb_reserved2: u16,
    lp_reserved2: *mut u8,
    h_std_input: Handle,
    h_std_output: Handle,
    h_std_error: Handle,
}

#[repr(C)]
struct StartupInfoExW {
    startup_info: StartupInfoW,
    lp_attribute_list: *mut core::ffi::c_void,
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreatePipe(
        h_read_pipe: *mut Handle,
        h_write_pipe: *mut Handle,
        lp_pipe_attributes: *mut SecurityAttributes,
        n_size: u32,
    ) -> i32;
    fn SetHandleInformation(h_object: Handle, dw_mask: u32, dw_flags: u32) -> i32;
    fn CloseHandle(h_object: Handle) -> i32;
    fn GetLastError() -> u32;
    fn ReadFile(
        h_file: Handle,
        lp_buffer: *mut core::ffi::c_void,
        n_number_of_bytes_to_read: u32,
        lp_number_of_bytes_read: *mut u32,
        lp_overlapped: *mut core::ffi::c_void,
    ) -> i32;
    fn WriteFile(
        h_file: Handle,
        lp_buffer: *const core::ffi::c_void,
        n_number_of_bytes_to_write: u32,
        lp_number_of_bytes_written: *mut u32,
        lp_overlapped: *mut core::ffi::c_void,
    ) -> i32;
    fn WaitForSingleObject(h_handle: Handle, dw_milliseconds: u32) -> u32;
    fn GetExitCodeProcess(h_process: Handle, lp_exit_code: *mut u32) -> i32;
    fn TerminateProcess(h_process: Handle, u_exit_code: u32) -> i32;
    fn CreateProcessW(
        lp_application_name: *const u16,
        lp_command_line: *mut u16,
        lp_process_attributes: *mut SecurityAttributes,
        lp_thread_attributes: *mut SecurityAttributes,
        b_inherit_handles: i32,
        dw_creation_flags: u32,
        lp_environment: *mut core::ffi::c_void,
        lp_current_directory: *const u16,
        lp_startup_info: *mut StartupInfoW,
        lp_process_information: *mut ProcessInformation,
    ) -> i32;

    fn InitializeProcThreadAttributeList(
        lp_attribute_list: *mut core::ffi::c_void,
        dw_attribute_count: u32,
        dw_flags: u32,
        lp_size: *mut usize,
    ) -> i32;
    fn UpdateProcThreadAttribute(
        lp_attribute_list: *mut core::ffi::c_void,
        dw_flags: u32,
        attribute: usize,
        lp_value: *mut core::ffi::c_void,
        cb_size: usize,
        lp_previous_value: *mut core::ffi::c_void,
        lp_return_size: *mut usize,
    ) -> i32;
    fn DeleteProcThreadAttributeList(lp_attribute_list: *mut core::ffi::c_void);

    fn CreatePseudoConsole(size: Coord, h_input: Handle, h_output: Handle, dw_flags: u32, ph_pc: *mut Hpc) -> i32;
    fn ClosePseudoConsole(h_pc: Hpc);
}

fn last_os_error() -> io::Error {
    io::Error::from_raw_os_error(unsafe { GetLastError() } as i32)
}

fn to_wide(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(Some(0)).collect()
}

struct OwnedHandle(Handle);

impl OwnedHandle {
    fn new(handle: Handle) -> Self {
        Self(handle)
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if self.0 != 0 && self.0 != INVALID_HANDLE_VALUE {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

struct OwnedHpc(Hpc);

impl Drop for OwnedHpc {
    fn drop(&mut self) {
        if self.0 != 0 && self.0 != INVALID_HANDLE_VALUE {
            unsafe { ClosePseudoConsole(self.0) }
        }
    }
}

fn create_pipe() -> io::Result<(OwnedHandle, OwnedHandle)> {
    let mut read_handle: Handle = 0;
    let mut write_handle: Handle = 0;
    let mut sa = SecurityAttributes {
        n_length: std::mem::size_of::<SecurityAttributes>() as u32,
        lp_security_descriptor: ptr::null_mut(),
        b_inherit_handle: 1,
    };
    let ok = unsafe { CreatePipe(&mut read_handle, &mut write_handle, &mut sa, 0) };
    if ok == 0 {
        return Err(last_os_error());
    }

    Ok((OwnedHandle::new(read_handle), OwnedHandle::new(write_handle)))
}

fn write_all(handle: Handle, mut bytes: &[u8]) -> io::Result<()> {
    while !bytes.is_empty() {
        let mut written = 0u32;
        let ok = unsafe {
            WriteFile(
                handle,
                bytes.as_ptr().cast(),
                u32::try_from(bytes.len()).unwrap_or(u32::MAX),
                &mut written,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(last_os_error());
        }
        let written = usize::try_from(written).unwrap_or(0);
        bytes = &bytes[written..];
    }
    Ok(())
}

fn read_drain(handle: Handle, limit_bytes: usize) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; 4096];
    let mut out = Vec::new();
    loop {
        let mut read = 0u32;
        let ok = unsafe {
            ReadFile(
                handle,
                buf.as_mut_ptr().cast(),
                u32::try_from(buf.len()).unwrap_or(u32::MAX),
                &mut read,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            // Broken pipe is expected once the child exits and closes the PTY.
            return Ok(out);
        }
        if read == 0 {
            return Ok(out);
        }
        let read = usize::try_from(read).unwrap_or(0);
        if out.len() < limit_bytes {
            let remaining = limit_bytes - out.len();
            out.extend_from_slice(&buf[..read.min(remaining)]);
        }
    }
}

fn wait_process(process: Handle, timeout: Duration) -> io::Result<u32> {
    let timeout_ms = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX);
    let res = unsafe { WaitForSingleObject(process, timeout_ms) };
    if res == WAIT_TIMEOUT {
        unsafe {
            let _ = TerminateProcess(process, 1);
        }
        return Err(io::Error::new(io::ErrorKind::TimedOut, "process timed out"));
    }
    if res != WAIT_OBJECT_0 {
        return Err(last_os_error());
    }
    let mut code = 0u32;
    let ok = unsafe { GetExitCodeProcess(process, &mut code) };
    if ok == 0 {
        return Err(last_os_error());
    }
    Ok(code)
}

fn spawn_cmd_in_conpty(command: &OsStr) -> io::Result<(OwnedHpc, OwnedHandle, OwnedHandle, ProcessInformation)> {
    let (pty_in_read, pty_in_write) = create_pipe()?;
    let (pty_out_read, pty_out_write) = create_pipe()?;

    // Avoid leaking the PTY handles into the child process; the pseudoconsole will own the other ends.
    let ok = unsafe { SetHandleInformation(pty_in_write.0, 1, 0) };
    if ok == 0 {
        return Err(last_os_error());
    }
    let ok = unsafe { SetHandleInformation(pty_out_read.0, 1, 0) };
    if ok == 0 {
        return Err(last_os_error());
    }

    let mut hpc: Hpc = 0;
    let hr = unsafe { CreatePseudoConsole(Coord { x: 120, y: 40 }, pty_in_read.0, pty_out_write.0, 0, &mut hpc) };
    if hr != 0 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("CreatePseudoConsole failed: {hr:#x}"),
        ));
    }
    let hpc = OwnedHpc(hpc);

    let mut attr_list_size = 0usize;
    let ok = unsafe { InitializeProcThreadAttributeList(ptr::null_mut(), 1, 0, &mut attr_list_size) };
    if ok != 0 || attr_list_size == 0 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "InitializeProcThreadAttributeList(size query) failed",
        ));
    }

    let mut attr_buf = vec![0u8; attr_list_size];
    let attr_ptr = attr_buf.as_mut_ptr().cast::<core::ffi::c_void>();
    let ok = unsafe { InitializeProcThreadAttributeList(attr_ptr, 1, 0, &mut attr_list_size) };
    if ok == 0 {
        return Err(last_os_error());
    }

    let ok = unsafe {
        UpdateProcThreadAttribute(
            attr_ptr,
            0,
            PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
            hpc.0 as *mut core::ffi::c_void,
            std::mem::size_of::<Hpc>(),
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        unsafe { DeleteProcThreadAttributeList(attr_ptr) };
        return Err(last_os_error());
    }

    let mut si_ex = StartupInfoExW {
        startup_info: StartupInfoW {
            cb: std::mem::size_of::<StartupInfoExW>() as u32,
            lp_reserved: ptr::null_mut(),
            lp_desktop: ptr::null_mut(),
            lp_title: ptr::null_mut(),
            dw_x: 0,
            dw_y: 0,
            dw_x_size: 0,
            dw_y_size: 0,
            dw_x_count_chars: 0,
            dw_y_count_chars: 0,
            dw_fill_attribute: 0,
            dw_flags: 0,
            w_show_window: 0,
            cb_reserved2: 0,
            lp_reserved2: ptr::null_mut(),
            h_std_input: 0,
            h_std_output: 0,
            h_std_error: 0,
        },
        lp_attribute_list: attr_ptr,
    };

    let mut pi = ProcessInformation {
        h_process: 0,
        h_thread: 0,
        dw_process_id: 0,
        dw_thread_id: 0,
    };

    let mut cmdline = to_wide(command);
    let ok = unsafe {
        CreateProcessW(
            ptr::null(),
            cmdline.as_mut_ptr(),
            ptr::null_mut(),
            ptr::null_mut(),
            0,
            EXTENDED_STARTUPINFO_PRESENT,
            ptr::null_mut(),
            ptr::null(),
            &mut si_ex.startup_info,
            &mut pi,
        )
    };

    unsafe { DeleteProcThreadAttributeList(attr_ptr) };
    if ok == 0 {
        return Err(last_os_error());
    }

    // `attr_buf` can be dropped after `CreateProcessW` returns, but `hpc` must stay alive until the child exits.
    Ok((hpc, pty_in_write, pty_out_read, pi))
}

fn cmd_pipeline_command(sk_path: &str, out_path: &str) -> String {
    let comspec = std::env::var("COMSPEC").unwrap_or_else(|_| "cmd.exe".to_string());
    format!(
        "{comspec} /d /q /c set SKIM_DEFAULT_OPTIONS=&& set SKIM_DEFAULT_COMMAND=&& (echo a&echo b&echo c) | {sk_path} --sync --print0 --print-query > {out_path}"
    )
}

#[test]
fn conpty_can_drive_cmd_input() -> io::Result<()> {
    let comspec = std::env::var("COMSPEC").unwrap_or_else(|_| "cmd.exe".to_string());
    let command_line = format!("{comspec} /d /q /c exit /b 0");
    let cmdline = OsStr::new(&command_line);

    let (hpc, pty_in_write, pty_out_read, pi) = spawn_cmd_in_conpty(cmdline)?;
    let drain_handle = thread::spawn(move || read_drain(pty_out_read.0, 64 * 1024));

    drop(pty_in_write);

    let exit = wait_process(pi.h_process, Duration::from_secs(10));
    unsafe {
        CloseHandle(pi.h_thread);
        CloseHandle(pi.h_process);
    }
    drop(hpc);

    let pty_output = drain_handle.join().unwrap_or_else(|_| Ok(Vec::new()))?;

    let exit_code = match exit {
        Ok(code) => code,
        Err(e) => {
            return Err(io::Error::new(
                e.kind(),
                format!("{e}; pty-output-prefix={:?}", String::from_utf8_lossy(&pty_output)),
            ));
        }
    };
    if exit_code != 0 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "cmd exited non-zero: {exit_code}; pty-output-prefix={:?}",
                String::from_utf8_lossy(&pty_output)
            ),
        ));
    }
    if pty_output.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "expected non-empty pty output; pty-output-prefix={:?}",
                String::from_utf8_lossy(&pty_output)
            ),
        ));
    }
    Ok(())
}

#[test]
fn interactive_cmd_piped_stdin_accepts_typed_query() -> io::Result<()> {
    let sk = env!("CARGO_BIN_EXE_sk");

    let mut out_path = std::env::temp_dir();
    out_path.push(format!("skim-win-cmd-out-{}.bin", std::process::id()));
    let _ = std::fs::remove_file(&out_path);

    let command_line = cmd_pipeline_command(sk, out_path.to_string_lossy().as_ref());
    let cmdline = OsStr::new(&command_line);

    let (hpc, pty_in_write, pty_out_read, pi) = spawn_cmd_in_conpty(cmdline)?;

    let drain_handle = thread::spawn(move || read_drain(pty_out_read.0, 64 * 1024));

    // Give the UI/matcher a moment to initialize before sending input.
    thread::sleep(Duration::from_millis(200));

    // Type a query that leaves a single match ("b"), then press Enter to accept.
    write_all(pty_in_write.0, b"b")?;
    thread::sleep(Duration::from_millis(200));
    write_all(pty_in_write.0, b"\r")?;

    let exit = wait_process(pi.h_process, Duration::from_secs(10));
    unsafe {
        CloseHandle(pi.h_thread);
        CloseHandle(pi.h_process);
    }

    // Close the pseudoconsole to unblock the output drain thread.
    drop(hpc);

    let pty_output = drain_handle.join().unwrap_or_else(|_| Ok(Vec::new()))?;

    let exit_code = match exit {
        Ok(code) => code,
        Err(e) => {
            return Err(io::Error::new(
                e.kind(),
                format!("{e}; pty-output-prefix={:?}", String::from_utf8_lossy(&pty_output)),
            ));
        }
    };
    if exit_code != 0 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "cmd exited non-zero: {exit_code}; pty-output-prefix={:?}",
                String::from_utf8_lossy(&pty_output)
            ),
        ));
    }

    let bytes = std::fs::read(&out_path)?;
    let parts = bytes.split(|b| *b == 0).filter(|s| !s.is_empty()).collect::<Vec<_>>();

    fn trim_end_ascii_space(mut s: &[u8]) -> &[u8] {
        while let Some((&last, rest)) = s.split_last() {
            if last == b' ' || last == b'\t' {
                s = rest;
            } else {
                break;
            }
        }
        s
    }

    let parts_trimmed = parts.into_iter().map(trim_end_ascii_space).collect::<Vec<_>>();
    if parts_trimmed != [b"b".as_slice(), b"b".as_slice()] {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("unexpected output: {:?}; raw={:?}", parts_trimmed, bytes),
        ));
    }
    Ok(())
}
