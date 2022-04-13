fn main() -> Result<(), Box<dyn std::error::Error>> {
  tonic_build::compile_protos("../proto/endpoint.proto")?;
  tonic_build::compile_protos("../proto/coordinator.proto")?;
  Ok(())
}
