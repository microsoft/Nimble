fn main() -> Result<(), Box<dyn std::error::Error>> {
  tonic_build::compile_protos("proto/protocol.proto")?;
  tonic_build::compile_protos("proto/endorserprotocol.proto")?;
  Ok(())
}
