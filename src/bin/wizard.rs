use std::borrow::Cow;
use std::io::{self, BufRead, Read, Write};
use std::os::fd::AsRawFd;
use std::process::Command;

use kernel_node::ext::ExpandTildeExt;

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const CYAN: &str = "\x1b[36m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";

fn read_line() -> String {
    let mut line = String::new();
    io::stdin()
        .lock()
        .read_line(&mut line)
        .expect("failed to read stdin");
    line.trim().to_string()
}

fn prompt_with_default(question: &str, default: &str) -> String {
    print!("{question} {DIM}[{default}]{RESET}: ");
    io::stdout().flush().unwrap();
    let answer = read_line();
    if answer.is_empty() {
        default.to_string()
    } else {
        answer
    }
}

fn prompt_optional(question: &str) -> Option<String> {
    print!("{question} {DIM}(enter to skip){RESET}: ");
    io::stdout().flush().unwrap();
    let answer = read_line();
    if answer.is_empty() {
        None
    } else {
        Some(answer)
    }
}

fn prompt_yes_no(question: &str, default: bool) -> bool {
    let hint = if default { "Y/n" } else { "y/N" };
    loop {
        print!("{question} {DIM}[{hint}]{RESET}: ");
        io::stdout().flush().unwrap();
        let answer = read_line();
        if answer.is_empty() {
            return default;
        }
        match answer.to_ascii_lowercase().as_str() {
            "y" | "yes" => return true,
            "n" | "no" => return false,
            _ => println!("please answer y or n"),
        }
    }
}

struct RawMode {
    fd: i32,
    original: libc::termios,
}

impl RawMode {
    fn enter(fd: i32) -> Option<Self> {
        unsafe {
            let mut original: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(fd, &mut original) != 0 {
                return None;
            }
            let mut raw = original;
            raw.c_lflag &= !(libc::ICANON | libc::ECHO | libc::ISIG);
            raw.c_cc[libc::VMIN] = 1;
            raw.c_cc[libc::VTIME] = 1;
            if libc::tcsetattr(fd, libc::TCSANOW, &raw) != 0 {
                return None;
            }
            Some(RawMode { fd, original })
        }
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        unsafe {
            libc::tcsetattr(self.fd, libc::TCSANOW, &self.original);
        }
        print!("\x1b[?25h");
        io::stdout().flush().ok();
    }
}

/// Arrow-key selector. Falls back to numeric input if stdin isn't a tty.
fn select(question: &str, options: &[&str], default_idx: usize) -> String {
    println!("{BOLD}{question}{RESET} {DIM}(↑/↓, enter){RESET}");

    let fd = io::stdin().as_raw_fd();
    if unsafe { libc::isatty(fd) } != 1 {
        return fallback_select(options, default_idx);
    }
    let Some(_raw) = RawMode::enter(fd) else {
        return fallback_select(options, default_idx);
    };

    print!("\x1b[?25l");
    io::stdout().flush().unwrap();

    let mut idx = default_idx.min(options.len().saturating_sub(1));
    let n = options.len();
    let mut buf = [0u8; 8];
    let mut drawn = false;

    loop {
        if drawn {
            for _ in 0..n {
                print!("\x1b[1A\x1b[2K");
            }
        }
        for (i, opt) in options.iter().enumerate() {
            if i == idx {
                println!("  {CYAN}{BOLD}> {opt}{RESET}");
            } else {
                println!("    {opt}");
            }
        }
        io::stdout().flush().unwrap();
        drawn = true;

        let read = io::stdin().read(&mut buf).unwrap_or(0);
        if read == 0 {
            continue;
        }
        match buf[0] {
            b'\r' | b'\n' => return options[idx].to_string(),
            0x03 => {
                // Ctrl-C
                drop(_raw);
                eprintln!("\naborted");
                std::process::exit(130);
            }
            0x1b if read >= 3 && buf[1] == b'[' => match buf[2] {
                b'A' => idx = if idx == 0 { n - 1 } else { idx - 1 },
                b'B' => idx = (idx + 1) % n,
                _ => {}
            },
            b'k' => idx = if idx == 0 { n - 1 } else { idx - 1 },
            b'j' => idx = (idx + 1) % n,
            _ => {}
        }
    }
}

fn fallback_select(options: &[&str], default_idx: usize) -> String {
    for (i, opt) in options.iter().enumerate() {
        let marker = if i == default_idx { ">" } else { " " };
        println!("  {marker} {i}) {opt}");
    }
    loop {
        print!("choice {DIM}[{}]{RESET}: ", options[default_idx]);
        io::stdout().flush().unwrap();
        let answer = read_line();
        if answer.is_empty() {
            return options[default_idx].to_string();
        }
        if let Some(opt) = options.iter().find(|o| o.eq_ignore_ascii_case(&answer)) {
            return (*opt).to_string();
        }
        if let Ok(idx) = answer.parse::<usize>() {
            if let Some(opt) = options.get(idx) {
                return (*opt).to_string();
            }
        }
        println!("please enter one of the listed options or its index");
    }
}

fn shell_quote(arg: &str) -> Cow<'_, str> {
    let safe = |c: char| c.is_ascii_alphanumeric() || "-_./=:,@+~".contains(c);
    if !arg.is_empty() && arg.chars().all(safe) {
        Cow::Borrowed(arg)
    } else {
        Cow::Owned(format!("'{}'", arg.replace('\'', r"'\''")))
    }
}

fn main() {
    println!("{BOLD}{CYAN}kernel-node setup wizard{RESET}");
    println!();

    let network = select(
        "Which network would you like to run on?",
        &["signet", "bitcoin"],
        0,
    );

    let datadir = prompt_with_default("Where should data be stored?", "~/.kernel-node");

    let connect = prompt_optional("Connect only to a specific node (ip:port)?");

    let sp_keys_file = loop {
        let Some(input) = prompt_optional("Path to a silent payments keys file to import?") else {
            break None;
        };
        let expanded = input.expand_tilde();
        let absolute = if expanded.is_absolute() {
            expanded
        } else {
            std::env::current_dir().unwrap().join(expanded)
        };
        match absolute.canonicalize() {
            Ok(path) => break Some(path.to_string_lossy().into_owned()),
            Err(e) => println!("{YELLOW}could not resolve {input}: {e}{RESET}"),
        }
    };

    let proxy = if prompt_yes_no("Route peer connections through a Socks5 proxy?", false) {
        Some(prompt_with_default("Proxy address", "127.0.0.1:9050"))
    } else {
        None
    };

    let daemon = prompt_yes_no("Run as daemon?", false);

    let mut args: Vec<String> = vec![
        "run".into(),
        "--bin".into(),
        "node".into(),
        "--release".into(),
        "--".into(),
        "--network".into(),
        network,
        "--datadir".into(),
        datadir,
    ];
    if let Some(c) = connect {
        args.push("--connect".into());
        args.push(c);
    }
    if let Some(k) = sp_keys_file {
        args.push("--sp-keys-file".into());
        args.push(k);
    }
    if let Some(p) = proxy {
        args.push("--proxy".into());
        args.push(p);
    }
    if daemon {
        args.push("--daemon=true".into());
    }

    println!();
    println!("{YELLOW}Run:{RESET}");
    let printable: Vec<Cow<'_, str>> = args.iter().map(|a| shell_quote(a)).collect();
    println!("  {GREEN}cargo {}{RESET}", printable.join(" "));
    println!();

    if !prompt_yes_no("Start the node now?", true) {
        return;
    }

    let status = Command::new("cargo")
        .args(&args)
        .status()
        .expect("failed to spawn cargo");
    std::process::exit(status.code().unwrap_or(1));
}
