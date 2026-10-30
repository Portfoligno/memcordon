//! Test-only role rendezvous shared by the coordinator and standalone wrapper.
use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Copy, Debug)]
pub enum Role {
    Product,
    Native,
}
impl Role {
    pub fn name(self) -> &'static str {
        match self {
            Self::Product => "product",
            Self::Native => "native",
        }
    }
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct State {
    pub product: usize,
    pub native: usize,
    pub maximum: usize,
}
impl State {
    pub fn total(self) -> usize {
        self.product + self.native
    }
}

pub struct Protocol {
    root: PathBuf,
    deadline: SystemTime,
    pub budget: usize,
}
struct Lock(PathBuf);
impl Drop for Lock {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir(&self.0) {
            eprintln!("compiler observer unlock: {error}");
        }
    }
}

impl Protocol {
    pub fn create(root: &Path, budget: usize, deadline: SystemTime) -> io::Result<Self> {
        fs::create_dir(root)?;
        let millis = deadline
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_millis();
        fs::write(root.join("protocol"), format!("1 {millis} {budget}\n"))?;
        fs::write(root.join("state"), "0 0 0\n")?;
        fs::write(root.join("events"), "")?;
        Self::open(root)
    }
    pub fn open(root: &Path) -> io::Result<Self> {
        let text = fs::read_to_string(root.join("protocol"))?;
        let fields = text.split_whitespace().collect::<Vec<_>>();
        if fields.len() != 3 || fields[0] != "1" {
            return Err(io::Error::other("compiler observer protocol differs"));
        }
        let millis = fields[1].parse::<u64>().map_err(io::Error::other)?;
        let budget = fields[2].parse::<usize>().map_err(io::Error::other)?;
        if budget == 0 {
            return Err(io::Error::other("compiler observer budget zero"));
        }
        Ok(Self {
            root: root.into(),
            deadline: UNIX_EPOCH + Duration::from_millis(millis),
            budget,
        })
    }
    fn live(&self) -> io::Result<()> {
        if SystemTime::now() >= self.deadline {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "original compiler rendezvous cutoff exhausted",
            ))
        } else {
            Ok(())
        }
    }
    fn lock(&self) -> io::Result<Lock> {
        let path = self.root.join("lock");
        loop {
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Lock(path)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    self.live()?;
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(error) => return Err(error),
            }
        }
    }
    fn state(&self) -> io::Result<State> {
        let text = fs::read_to_string(self.root.join("state"))?;
        let values = text
            .split_whitespace()
            .map(str::parse::<usize>)
            .collect::<Result<Vec<_>, _>>()
            .map_err(io::Error::other)?;
        if values.len() != 3 {
            return Err(io::Error::other("compiler observer state differs"));
        }
        Ok(State {
            product: values[0],
            native: values[1],
            maximum: values[2],
        })
    }
    pub fn snapshot(&self) -> io::Result<State> {
        let _lock = self.lock()?;
        self.state()
    }
    fn change(&self, role: Role, add: bool) -> io::Result<State> {
        let _lock = self.lock()?;
        let mut state = self.state()?;
        let count = match role {
            Role::Product => &mut state.product,
            Role::Native => &mut state.native,
        };
        *count = if add {
            count.checked_add(1)
        } else {
            count.checked_sub(1)
        }
        .ok_or_else(|| io::Error::other("compiler observer count overflow/underflow"))?;
        state.maximum = state.maximum.max(state.total());
        fs::write(
            self.root.join("state"),
            format!("{} {} {}\n", state.product, state.native, state.maximum),
        )?;
        writeln!(
            fs::OpenOptions::new()
                .append(true)
                .open(self.root.join("events"))?,
            "{} {} {} {}",
            std::process::id(),
            role.name(),
            if add { 1 } else { -1 },
            state.total()
        )?;
        Ok(state)
    }
    pub fn admit(&self, role: Role) -> io::Result<Admission<'_>> {
        self.live()?;
        let state = self.change(role, true)?;
        let admission = Admission {
            protocol: self,
            role,
            active: true,
        };
        if state.total() > self.budget || state.product > 1 {
            return Err(io::Error::other(
                "compiler admission exceeded exact role capacity",
            ));
        }
        Ok(admission)
    }
    pub fn wait_gate(&self, role: Role) -> io::Result<()> {
        loop {
            self.live()?;
            if self.root.join(role.name()).is_file() {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    pub fn release(&self, role: Role) -> io::Result<()> {
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(self.root.join(role.name()))
            .map(|_| ())
    }
    pub fn release_all(&self) -> io::Result<()> {
        let mut failure = None;
        for role in [Role::Product, Role::Native] {
            match self.release(role) {
                Err(error) if error.kind() != io::ErrorKind::AlreadyExists => failure = Some(error),
                _ => {}
            }
        }
        failure.map_or(Ok(()), Err)
    }
    pub fn release_guard(&self) -> ReleaseGuard<'_> {
        ReleaseGuard(self)
    }
    pub fn wait_roles(&self, product: usize, native: usize, cutoff: Instant) -> io::Result<State> {
        loop {
            self.live()?;
            if Instant::now() >= cutoff {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "original coordinator cutoff exhausted",
                ));
            }
            let state = self.snapshot()?;
            if state.maximum > self.budget || state.product > 1 {
                return Err(io::Error::other("compiler observer exceeded capacity"));
            }
            if state.product == product && state.native == native {
                return Ok(state);
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    pub fn events(&self) -> io::Result<String> {
        fs::read_to_string(self.root.join("events"))
    }
}
pub struct Admission<'a> {
    protocol: &'a Protocol,
    role: Role,
    active: bool,
}
impl Admission<'_> {
    pub fn finish(mut self) -> io::Result<()> {
        self.active = false;
        self.protocol.change(self.role, false).map(|_| ())
    }
}
impl Drop for Admission<'_> {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        if let Err(error) = self.protocol.change(self.role, false) {
            eprintln!("compiler observer admission cleanup: {error}");
        }
    }
}
pub struct ReleaseGuard<'a>(&'a Protocol);
impl Drop for ReleaseGuard<'_> {
    fn drop(&mut self) {
        if let Err(error) = self.0.release_all() {
            eprintln!("compiler observer gate cleanup: {error}");
        }
    }
}
