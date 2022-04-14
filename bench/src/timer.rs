use colored::Colorize;
use core::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

pub static CALL_DEPTH: AtomicUsize = AtomicUsize::new(0);

pub struct Timer {
  label: String,
  timer: Instant,
}

impl Timer {
  #[inline(always)]
  pub fn new(label: &str) -> Self {
    let timer = Instant::now();
    CALL_DEPTH.fetch_add(1, Ordering::Relaxed);
    let star = "* ";
    println!(
      "{:indent$}{}{}",
      "",
      star,
      label.yellow().bold(),
      indent = 2 * CALL_DEPTH.fetch_add(0, Ordering::Relaxed)
    );
    Self {
      label: label.to_string(),
      timer,
    }
  }

  #[inline(always)]
  pub fn stop(&self) -> Duration {
    let duration = self.timer.elapsed();
    let star = "* ";
    println!(
      "{:indent$}{}{} {:?}",
      "",
      star,
      self.label.blue().bold(),
      duration,
      indent = 2 * CALL_DEPTH.fetch_add(0, Ordering::Relaxed)
    );
    CALL_DEPTH.fetch_sub(1, Ordering::Relaxed);
    duration
  }

  #[inline(always)]
  pub fn print(msg: &str) {
    CALL_DEPTH.fetch_add(1, Ordering::Relaxed);
    let star = "* ";
    println!(
      "{:indent$}{}{}",
      "",
      star,
      msg.to_string().green().bold(),
      indent = 2 * CALL_DEPTH.fetch_add(0, Ordering::Relaxed)
    );
    CALL_DEPTH.fetch_sub(1, Ordering::Relaxed);
  }
}
