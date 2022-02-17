use clap::Parser;

#[derive(Parser, Debug)]
#[clap(
  name = "LedgerBench",
  about = "E2E Benchmarking utility for NimbleLedger APIs",
  version
)]
pub struct Args {
  /// The hostname of the coordinator
  #[clap(short, long, default_value = "http://[::1]:8080")]
  pub coordinator: String,

  /// The number of concurrent clients to use in the benchmark
  #[clap(short, long, default_value_t = 10)]
  pub num_clients: usize,

  /// The number of requests per client to use in the benchmark
  #[clap(short, long, default_value_t = 1000)]
  pub requests: usize,

  /** The API to benchmark, Integers in the range 1-4 corresponding to: {n}
      1. NewLedger {n}
      2. Append {n}
      3. ReadLatest {n}
      4. ReadByIndex {n}
  */
  #[clap(short, long, min_values = 1, default_values = &["1", "2"], possible_values = ["1","2","3","4"] , multiple_values = true, next_line_help = true)]
  pub methods: Vec<usize>,

  /// The number of random bytes to be generated as application bytes payload (NewLedger AppBytes/Append Block Size).
  #[clap(short, long, required = false, required_if_eq_any = &[("methods", "1"), ("methods", "2")], default_value_ifs = &[("methods", Some("3"), Some("16")), ("methods", Some("4"), Some("16"))], default_value_t = 16)]
  pub app_or_block_byte_size: usize,

  /// Write the result of the benchmark to a file.
  #[clap(
    short,
    long,
    takes_value = true,
    required = false,
    default_value = "/dev/null"
  )]
  pub write_file_out: String,
}
