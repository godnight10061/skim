//! Command-line interface for skim fuzzy finder.
//!
//! This binary provides the `sk` command-line tool for fuzzy finding and filtering.

extern crate clap;
extern crate env_logger;
extern crate log;
extern crate shlex;
extern crate skim;

use clap::{Error, Parser};
use color_eyre::Result;
use color_eyre::eyre::eyre;
use derive_builder::Builder;
use interprocess::bound_util::RefWrite;
use interprocess::local_socket::ToNsName as _;
use interprocess::local_socket::traits::Stream as _;
use log::trace;
use skim::binds::parse_action_chain;
use skim::reader::CommandCollector;
use skim::tui::event::Action;
use std::fs::File;
use std::io::{BufReader, BufWriter, IsTerminal, Write};
use std::{env, io};
use thiserror::Error;

use skim::prelude::*;
use skim::tui::Event;

#[cfg(windows)]
mod windows_tty {
    use std::ffi::OsStr;
    use std::fs::File;
    use std::io;
    use std::os::windows::ffi::OsStrExt as _;
    use std::os::windows::io::{FromRawHandle as _, OwnedHandle, RawHandle};

    type Handle = isize;

    const INVALID_HANDLE_VALUE: Handle = -1;

    const STD_INPUT_HANDLE: i32 = -10;

    const DUPLICATE_SAME_ACCESS: u32 = 0x0000_0002;
    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    const OPEN_EXISTING: u32 = 3;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CloseHandle(h_object: Handle) -> i32;
        fn CreateFileW(
            lp_file_name: *const u16,
            dw_desired_access: u32,
            dw_share_mode: u32,
            lp_security_attributes: *mut core::ffi::c_void,
            dw_creation_disposition: u32,
            dw_flags_and_attributes: u32,
            h_template_file: Handle,
        ) -> Handle;
        fn DuplicateHandle(
            h_source_process_handle: Handle,
            h_source_handle: Handle,
            h_target_process_handle: Handle,
            lp_target_handle: *mut Handle,
            dw_desired_access: u32,
            b_inherit_handle: i32,
            dw_options: u32,
        ) -> i32;
        fn GetCurrentProcess() -> Handle;
        fn GetLastError() -> u32;
        fn GetStdHandle(n_std_handle: i32) -> Handle;
        fn SetStdHandle(n_std_handle: i32, handle: Handle) -> i32;
    }

    fn last_os_error() -> io::Error {
        io::Error::from_raw_os_error(unsafe { GetLastError() } as i32)
    }

    fn to_wide(s: &OsStr) -> Vec<u16> {
        s.encode_wide().chain(Some(0)).collect()
    }

    pub(super) fn duplicate_stdin_to_file() -> io::Result<File> {
        let stdin_handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
        if stdin_handle == 0 || stdin_handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::other("stdin handle is invalid"));
        }

        let proc = unsafe { GetCurrentProcess() };
        let mut dup: Handle = 0;
        let ok = unsafe { DuplicateHandle(proc, stdin_handle, proc, &mut dup, 0, 0, DUPLICATE_SAME_ACCESS) };
        if ok == 0 {
            return Err(last_os_error());
        }

        let raw: RawHandle = dup as RawHandle;
        Ok(unsafe { File::from_raw_handle(raw) })
    }

    pub(super) fn switch_stdin_to_conin() -> io::Result<OwnedHandle> {
        let conin = to_wide(OsStr::new("CONIN$"));
        let handle = unsafe {
            CreateFileW(
                conin.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                core::ptr::null_mut(),
                OPEN_EXISTING,
                0,
                0,
            )
        };
        if handle == 0 || handle == INVALID_HANDLE_VALUE {
            return Err(last_os_error());
        }

        let ok = unsafe { SetStdHandle(STD_INPUT_HANDLE, handle) };
        if ok == 0 {
            unsafe {
                CloseHandle(handle);
            }
            return Err(last_os_error());
        }

        Ok(unsafe { OwnedHandle::from_raw_handle(handle as RawHandle) })
    }
}

#[cfg(unix)]
fn run_tmux(opts: &SkimOptions) -> Option<SkimOutput> {
    skim::tmux::run_with(opts)
}

#[cfg(not(unix))]
fn run_tmux(_opts: &SkimOptions) -> Option<SkimOutput> {
    None
}

fn parse_args() -> Result<SkimOptions, Error> {
    let mut args = Vec::new();

    args.push(
        env::args()
            .next()
            .expect("there should be at least one arg: the application name"),
    );
    args.extend(
        env::var("SKIM_DEFAULT_OPTIONS")
            .ok()
            .and_then(|val| shlex::split(&val))
            .unwrap_or_default(),
    );
    for arg in env::args().skip(1) {
        args.push(arg);
    }

    SkimOptions::try_parse_from(args)
}

#[derive(Error, Debug)]
enum SkMainError {
    #[error("I/O error {0:?}")]
    IoError(std::io::Error),
    #[error("Argument error {0:?}")]
    ArgError(clap::Error),
}

impl From<std::io::Error> for SkMainError {
    fn from(value: std::io::Error) -> Self {
        Self::IoError(value)
    }
}

impl From<clap::Error> for SkMainError {
    fn from(value: clap::Error) -> Self {
        Self::ArgError(value)
    }
}

//------------------------------------------------------------------------------
fn main() -> Result<()> {
    let mut opts = parse_args().unwrap_or_else(|e| {
        e.exit();
    });
    color_eyre::install()?;
    let log_target = if let Some(ref log_file) = opts.log_file {
        env_logger::Target::Pipe(Box::new(File::create(log_file).expect("Failed to create log file")))
    } else {
        env_logger::Target::Stdout
    };
    env_logger::builder().target(log_target).format_timestamp_nanos().init();
    // Build the options after setting the log target
    opts = opts.build();
    trace!("Command line: {:?}", std::env::args());

    // Shell completion scripts
    if let Some(shell) = opts.shell {
        // Generate completion script directly to stdout
        skim::completions::generate(&shell);
        if opts.shell_bindings {
            use skim::completions::Shell::*;
            let binds_script = match &shell {
                Bash => include_str!("../../shell/key-bindings.bash"),
                Zsh => include_str!("../../shell/key-bindings.zsh"),
                Fish => include_str!("../../shell/key-bindings.fish"),
                _ => "",
            };
            if !binds_script.is_empty() {
                println!("{binds_script}");
            }
        }
        return Ok(());
    }
    // Man page
    if opts.man {
        crate::manpage::generate(&mut std::io::stdout())?;
        return Ok(());
    }

    if let Some(remote) = opts.remote {
        let ns_name = remote
            .to_ns_name::<interprocess::local_socket::GenericNamespaced>()
            .unwrap();
        let stream = interprocess::local_socket::Stream::connect(ns_name)?;
        let mut action_chain = String::new();
        loop {
            action_chain.clear();
            let len = std::io::stdin().read_line(&mut action_chain)?;
            log::debug!("Got line {} from stdin", action_chain.trim());
            if len == 0 {
                break;
            }
            let actions = parse_action_chain(action_chain.trim())?;
            for act in actions {
                stream
                    .as_write()
                    .write_all(format!("{}\n", ron::ser::to_string(&act)?).as_bytes())?;
                log::debug!("Sent action {act:?} to listener");
            }
        }
        return Ok(());
    }

    match sk_main(opts) {
        Ok(exit_code) => std::process::exit(exit_code),
        Err(err) => {
            // if downstream pipe is closed, exit silently, see PR#279
            match err.downcast_ref::<SkMainError>() {
                Some(SkMainError::IoError(e)) => {
                    if e.kind() == std::io::ErrorKind::BrokenPipe {
                        std::process::exit(0)
                    } else {
                        Err(eyre!(err))
                    }
                }
                Some(SkMainError::ArgError(e)) => e.exit(),
                None => match err.downcast_ref::<clap::error::Error>() {
                    Some(e) => e.exit(),
                    None => Err(eyre!(err)),
                },
            }
        }
    }
}

fn sk_main(mut opts: SkimOptions) -> Result<i32> {
    let reader_opts = SkimItemReaderOption::from_options(&opts);
    let cmd_collector = Rc::new(RefCell::new(SkimItemReader::new(reader_opts)));
    opts.cmd_collector = cmd_collector.clone() as Rc<RefCell<dyn CommandCollector>>;

    let cmd_history = opts.cmd_history.clone();
    let cmd_history_size = opts.cmd_history_size;
    let cmd_history_file = opts.cmd_history_file.clone();

    let query_history = opts.query_history.clone();
    let history_size = opts.history_size;
    let history_file = opts.history_file.clone();
    //------------------------------------------------------------------------------
    let bin_options = BinOptions {
        filter: opts.filter.clone(),
        print_query: opts.print_query,
        print_cmd: opts.print_cmd,
        print_score: opts.print_score,
        print_header: opts.print_header,
        output_ending: String::from(if opts.print0 { "\0" } else { "\n" }),
        strip_ansi: opts.ansi && !opts.no_strip_ansi,
    };

    //------------------------------------------------------------------------------
    // output

    let Some(result) = (if opts.tmux.is_some() && env::var("TMUX").is_ok() {
        run_tmux(&opts)
    } else {
        // read from pipe or command
        let stdin_is_terminal = io::stdin().is_terminal();
        let rx_item = if stdin_is_terminal || (opts.interactive && opts.cmd.is_some()) {
            None
        } else {
            #[cfg(windows)]
            let rx_item = cmd_collector
                .borrow()
                .of_bufread(BufReader::new(windows_tty::duplicate_stdin_to_file()?));
            #[cfg(not(windows))]
            let rx_item = cmd_collector.borrow().of_bufread(BufReader::new(std::io::stdin()));
            Some(rx_item)
        };
        // filter mode
        if opts.filter.is_some() {
            return Ok(filter(&bin_options, &opts, rx_item));
        }

        #[cfg(windows)]
        let _stdin_guard = if !stdin_is_terminal {
            Some(windows_tty::switch_stdin_to_conin()?)
        } else {
            None
        };

        Some(Skim::run_with(opts, rx_item)?)
    }) else {
        return Ok(135);
    };
    log::debug!("result: {result:?}");

    if result.is_abort {
        return Ok(130);
    }

    // output query
    if bin_options.print_query {
        print!("{}{}", result.query, bin_options.output_ending);
    }

    if bin_options.print_cmd {
        print!("{}{}", result.cmd, bin_options.output_ending);
    }

    if bin_options.print_header {
        print!("{}{}", result.header, bin_options.output_ending);
    }

    if let Event::Action(Action::Accept(Some(accept_key))) = result.final_event {
        print!("{}{}", accept_key, bin_options.output_ending);
    }

    for item in &result.selected_items {
        if bin_options.strip_ansi {
            print!(
                "{}{}",
                skim::helper::item::strip_ansi(&item.output()).0,
                bin_options.output_ending
            );
        } else {
            print!("{}{}", item.output(), bin_options.output_ending);
        }
        if bin_options.print_score {
            print!("{}{}", item.rank[0], bin_options.output_ending);
        }
    }

    std::io::stdout().flush()?;

    //------------------------------------------------------------------------------
    // write the history with latest item
    if let Some(file) = history_file {
        let limit = history_size;
        write_history_to_file(&query_history, &result.query, limit, &file)?;
    }

    if let Some(file) = cmd_history_file {
        let limit = cmd_history_size;
        write_history_to_file(&cmd_history, &result.cmd, limit, &file)?;
    }

    Ok(i32::from(result.selected_items.is_empty()))
}

fn write_history_to_file(
    orig_history: &[String],
    latest: &str,
    limit: usize,
    filename: &str,
) -> Result<(), std::io::Error> {
    if orig_history.last().map(String::as_str) == Some(latest) {
        // no point of having at the end of the history 5x the same command...
        return Ok(());
    }
    let additional_lines = usize::from(!latest.trim().is_empty());
    let start_index = if orig_history.len() + additional_lines > limit {
        orig_history.len() + additional_lines - limit
    } else {
        0
    };

    let mut history = orig_history[start_index..].to_vec();
    history.push(latest.to_string());

    let file = File::create(filename)?;
    let mut file = BufWriter::new(file);
    file.write_all(history.join("\n").as_bytes())?;
    Ok(())
}

/// Options specific to the binary/CLI mode
#[derive(Builder)]
#[allow(missing_docs)]
pub struct BinOptions {
    filter: Option<String>,
    output_ending: String,
    print_query: bool,
    print_cmd: bool,
    print_score: bool,
    print_header: bool,
    strip_ansi: bool,
}

/// Runs skim in filter mode, matching items against a fixed query without interactive UI
pub fn filter(bin_option: &BinOptions, options: &SkimOptions, source: Option<SkimItemReceiver>) -> i32 {
    use skim::matcher::Matcher;

    let default_command = String::from(match env::var("SKIM_DEFAULT_COMMAND").as_deref() {
        Err(_) | Ok("") => skim::platform_default_command(),
        Ok(v) => v,
    });
    let query = bin_option.filter.clone().unwrap_or_default();
    let cmd = options.cmd.clone().unwrap_or(default_command);

    // output query
    if bin_option.print_query {
        print!("{}{}", query, bin_option.output_ending);
    }

    if bin_option.print_cmd {
        print!("{}{}", cmd, bin_option.output_ending);
    }

    //------------------------------------------------------------------------------
    // matcher - use the unified factory creation from Matcher
    let engine_factory = Matcher::create_engine_factory(options);
    let engine = engine_factory.create_engine_with_case(&query, options.case);

    //------------------------------------------------------------------------------
    // start
    let components_to_stop = Arc::new(AtomicUsize::new(0));

    let mut stream_of_item = source.unwrap_or_else(|| {
        let (ret, _control) = options.cmd_collector.borrow_mut().invoke(&cmd, components_to_stop);
        ret
    });

    let mut num_matched = 0;
    let mut stdout_lock = std::io::stdout().lock();
    let mut items = Vec::new();

    // Collect all items from the stream until the channel is closed
    while let Some(item) = stream_of_item.blocking_recv() {
        items.push(item);
    }

    let mut matched_items: Vec<_> = items
        .iter()
        .filter_map(|item| engine.match_item(item.clone()).map(|result| (item, result)))
        .collect();

    if options.tac {
        matched_items.reverse();
    }

    matched_items.iter().for_each(|(item, _match_result)| {
        num_matched += 1;
        let _ = write!(stdout_lock, "{}{}", item.output(), bin_option.output_ending);
    });

    i32::from(num_matched == 0)
}
