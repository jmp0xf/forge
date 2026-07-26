//! Production wall-clock boundary.

use std::time::SystemTime;

use forge_core::ports::Clock;

/// System clock implementation. Domain tests replace the `Clock` port.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}
