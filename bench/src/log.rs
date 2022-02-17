use serde::{Deserialize, Serialize};
use std::fs::{create_dir_all, File, OpenOptions};
use std::path::Path;

pub struct FileWriter {
  writer: csv::Writer<File>,
}

impl FileWriter {
  pub fn new(writer: csv::Writer<File>) -> Self {
    FileWriter { writer }
  }

  pub fn write(&mut self, entry: &BenchmarkLog) -> Result<(), Box<dyn std::error::Error>> {
    Ok(self.writer.serialize(entry)?)
  }

  pub fn flush(&mut self) -> Result<(), Box<dyn std::error::Error>> {
    Ok(self.writer.flush()?)
  }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BenchmarkLog {
  clients: usize,
  total_requests: usize,
  reqs_per_client: usize,
  request_type: usize,
  avg_service_latency: f64,
  service_throughput: f64,
  verifier_time: f64,
}

impl BenchmarkLog {
  pub fn new(
    num_clients: usize,
    num_requests: usize,
    num_reqs_per_client: usize,
    request_type: usize,
    avg_service_latency: f64,
    service_throughput: f64,
    verifier_time: f64,
  ) -> Self {
    BenchmarkLog {
      clients: num_clients,
      total_requests: num_requests,
      reqs_per_client: num_reqs_per_client,
      request_type,
      avg_service_latency,
      service_throughput,
      verifier_time,
    }
  }
}

// Made Option<> for now to support multiple Writer types in future.
pub fn check_file_path_and_setup_dirs_necessary(file_path: &str) -> Option<FileWriter> {
  if !file_path.is_empty() {
    let p = Path::new(file_path);
    let dir_components = p.parent();
    match dir_components {
      None => {},
      Some(parent_path) => {
        let create_op = create_dir_all(parent_path);
        match create_op {
          Ok(_) => {},
          Err(e) => {
            println!("{:?}", e);
          },
        }
      },
    }
    // Time to create the file or reuse file by opening it if exists
    let file = OpenOptions::new()
      .create(true)
      .write(true)
      .append(true)
      .open(file_path)
      .unwrap();

    let wtr = csv::WriterBuilder::new()
      .has_headers(file.metadata().unwrap().len() == 0u64)
      .from_writer(file);
    return Some(FileWriter::new(wtr));
  }
  None
}
