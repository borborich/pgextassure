use std::fs::File;
use std::io::Read;
use std::net::TcpStream;
use std::process::Command;

pub fn dangerous_probe() -> std::io::Result<String> {
    let mut file = File::open("/etc/passwd")?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    let _connection = TcpStream::connect("example.invalid:443")?;
    let output = Command::new("id").output()?;

    let first_byte = unsafe { *output.stdout.as_ptr() };
    contents.push(char::from(first_byte));
    Ok(contents)
}
