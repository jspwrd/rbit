use super::error::BencodeError;
use super::value::Value;
use std::io::Write;

pub fn encode(value: &Value) -> Result<Vec<u8>, BencodeError> {
    let mut buf = Vec::new();
    encode_value(value, &mut buf)?;
    Ok(buf)
}

fn encode_value<W: Write>(value: &Value, writer: &mut W) -> Result<(), BencodeError> {
    match value {
        Value::Integer(i) => {
            write!(writer, "i{}e", i)?;
        }
        Value::Bytes(b) => {
            write!(writer, "{}:", b.len())?;
            writer.write_all(b)?;
        }
        Value::List(l) => {
            writer.write_all(b"l")?;
            for item in l {
                encode_value(item, writer)?;
            }
            writer.write_all(b"e")?;
        }
        Value::Dict(d) => {
            writer.write_all(b"d")?;
            for (key, val) in d {
                write!(writer, "{}:", key.len())?;
                writer.write_all(key)?;
                encode_value(val, writer)?;
            }
            writer.write_all(b"e")?;
        }
    }
    Ok(())
}
