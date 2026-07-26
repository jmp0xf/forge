#![cfg(unix)]

use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::fs::{self, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use forge_core::ports::ProcessPort as _;
use forge_core::{CommandSource, CommandSpec, Intent, RepoRelativePath};
use forge_runtime::interrupt::InterruptToken;
use forge_runtime::process::SynchronousProcessRunner;
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;

const HELPER_MODE: &str = "FORGE_SIGINT_HELPER_MODE";
const HEARTBEAT_MODE: &str = "FORGE_SIGINT_HEARTBEAT_MODE";
const HEARTBEAT_WORKER_MODE: &str = "FORGE_SIGINT_HEARTBEAT_WORKER_MODE";
const ROOT_PATH: &str = "FORGE_SIGINT_ROOT_PATH";
const HEARTBEAT_PATH: &str = "FORGE_SIGINT_HEARTBEAT_PATH";
const HEARTBEAT_WORKER_PID_PATH: &str = "FORGE_SIGINT_HEARTBEAT_WORKER_PID_PATH";
const RESULT_PATH: &str = "FORGE_SIGINT_RESULT_PATH";
const HELPER_TEST: &str = "sigint_runner_helper";
const HEARTBEAT_TEST: &str = "heartbeat_descendant";
const HEARTBEAT_WORKER_TEST: &str = "heartbeat_worker";

#[test]
fn sigint_interrupts_runner_and_stops_its_process_tree() -> Result<(), Box<dyn Error>> {
    let root = tempfile::tempdir()?;
    let heartbeat = root.path().join("heartbeat");
    let heartbeat_worker_pid = root.path().join("heartbeat-worker-pid");
    let result = root.path().join("result");
    let mut helper = Command::new(std::env::current_exe()?)
        .args(["--exact", HELPER_TEST, "--nocapture"])
        .env(HELPER_MODE, "1")
        .env(ROOT_PATH, root.path())
        .env(HEARTBEAT_PATH, &heartbeat)
        .env(HEARTBEAT_WORKER_PID_PATH, &heartbeat_worker_pid)
        .env(RESULT_PATH, &result)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;

    wait_for_nonempty_file(&heartbeat, Duration::from_secs(5)).inspect_err(|_error| {
        stop_helper(&mut helper);
        stop_heartbeat_worker(&heartbeat_worker_pid);
    })?;

    let helper_pid = i32::try_from(helper.id())?;
    kill(Pid::from_raw(helper_pid), Signal::SIGINT).inspect_err(|_error| {
        stop_helper(&mut helper);
        stop_heartbeat_worker(&heartbeat_worker_pid);
    })?;

    let status =
        match wait_for_child(&mut helper, Duration::from_secs(5)).inspect_err(|_error| {
            stop_helper(&mut helper);
            stop_heartbeat_worker(&heartbeat_worker_pid);
        })? {
            Some(status) => status,
            None => {
                stop_helper(&mut helper);
                stop_heartbeat_worker(&heartbeat_worker_pid);
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "SIGINT helper did not stop after its cancellation flag was set",
                )
                .into());
            }
        };
    let stderr = read_child_stderr(&mut helper)?;
    if !status.success() {
        stop_heartbeat_worker(&heartbeat_worker_pid);
        return Err(io::Error::other(format!(
            "SIGINT helper failed with {status}: {}",
            stderr.trim_end()
        ))
        .into());
    }

    if fs::read_to_string(&result)? != "interrupted\n" {
        stop_heartbeat_worker(&heartbeat_worker_pid);
        return Err(io::Error::other("runner did not report SIGINT as interruption").into());
    }
    let stopped_at = fs::metadata(&heartbeat)?.len();
    assert!(stopped_at > 0, "the heartbeat descendant never started");
    thread::sleep(Duration::from_millis(300));
    if fs::metadata(&heartbeat)?.len() != stopped_at {
        stop_heartbeat_worker(&heartbeat_worker_pid);
        return Err(io::Error::other(
            "the heartbeat grandchild continued after SIGINT cancellation",
        )
        .into());
    }
    Ok(())
}

#[test]
fn sigint_runner_helper() -> Result<(), Box<dyn Error>> {
    if std::env::var_os(HELPER_MODE).as_deref() != Some(OsStr::new("1")) {
        return Ok(());
    }

    let root = required_path(ROOT_PATH)?;
    let heartbeat = required_path(HEARTBEAT_PATH)?;
    let heartbeat_worker_pid = required_path(HEARTBEAT_WORKER_PID_PATH)?;
    let result = required_path(RESULT_PATH)?;
    let interrupt = InterruptToken::install()?;
    let runner =
        SynchronousProcessRunner::new(&root)?.with_cancellation_flag(interrupt.cancellation_flag());
    let mut command = CommandSpec::new(
        "runtime.sigint.integration",
        Intent::Test,
        std::env::current_exe()?,
        RepoRelativePath::root(),
        CommandSource::LanguageDefault {
            provider: "test".into(),
            rule: "sigint-process-tree".into(),
        },
    )
    .with_args(["--exact", HEARTBEAT_TEST, "--nocapture"]);
    command.timeout = Duration::from_secs(30);
    command
        .env
        .insert(OsString::from(HEARTBEAT_MODE), OsString::from("1"));
    command
        .env
        .insert(OsString::from(HEARTBEAT_PATH), heartbeat.into_os_string());
    command.env.insert(
        OsString::from(HEARTBEAT_WORKER_PID_PATH),
        heartbeat_worker_pid.into_os_string(),
    );

    let observation = runner.run(&command)?;
    if !observation.interrupted || observation.timed_out {
        return Err(io::Error::other(format!(
            "runner reported interrupted={} timed_out={}",
            observation.interrupted, observation.timed_out
        ))
        .into());
    }
    fs::write(result, b"interrupted\n")?;
    Ok(())
}

#[test]
fn heartbeat_descendant() -> Result<(), Box<dyn Error>> {
    if std::env::var_os(HEARTBEAT_MODE).as_deref() != Some(OsStr::new("1")) {
        return Ok(());
    }

    let heartbeat = required_path(HEARTBEAT_PATH)?;
    let heartbeat_worker_pid = required_path(HEARTBEAT_WORKER_PID_PATH)?;
    let status = Command::new(std::env::current_exe()?)
        .args(["--exact", HEARTBEAT_WORKER_TEST, "--nocapture"])
        .env_remove(HEARTBEAT_MODE)
        .env(HEARTBEAT_WORKER_MODE, "1")
        .env(HEARTBEAT_PATH, heartbeat)
        .env(HEARTBEAT_WORKER_PID_PATH, heartbeat_worker_pid)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if status.success() {
        return Err(io::Error::other("heartbeat worker exited before cancellation").into());
    }
    Err(io::Error::other(format!(
        "heartbeat worker failed unexpectedly with {status}"
    ))
    .into())
}

#[test]
fn heartbeat_worker() -> Result<(), Box<dyn Error>> {
    if std::env::var_os(HEARTBEAT_WORKER_MODE).as_deref() != Some(OsStr::new("1")) {
        return Ok(());
    }

    let heartbeat = required_path(HEARTBEAT_PATH)?;
    let pid_path = required_path(HEARTBEAT_WORKER_PID_PATH)?;
    fs::write(pid_path, format!("{}\n", std::process::id()))?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(heartbeat)?;
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        file.write_all(b"x")?;
        file.flush()?;
        thread::sleep(Duration::from_millis(20));
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "heartbeat worker was not terminated within its safety deadline",
    )
    .into())
}

fn required_path(key: &str) -> io::Result<PathBuf> {
    std::env::var_os(key).map(PathBuf::from).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("required test environment variable {key} is missing"),
        )
    })
}

fn wait_for_nonempty_file(path: &Path, timeout: Duration) -> io::Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        match fs::metadata(path) {
            Ok(metadata) if metadata.len() > 0 => return Ok(()),
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "heartbeat descendant did not start",
            ));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn wait_for_child(child: &mut Child, timeout: Duration) -> io::Result<Option<ExitStatus>> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn read_child_stderr(child: &mut Child) -> io::Result<String> {
    let mut stderr = String::new();
    if let Some(mut pipe) = child.stderr.take() {
        pipe.read_to_string(&mut stderr)?;
    }
    Ok(stderr)
}

fn stop_helper(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn stop_heartbeat_worker(pid_path: &Path) {
    let Ok(raw_pid) = fs::read_to_string(pid_path) else {
        return;
    };
    let Ok(pid) = raw_pid.trim().parse::<i32>() else {
        return;
    };
    let _ = kill(Pid::from_raw(pid), Signal::SIGKILL);
}
