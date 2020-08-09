#![allow(deprecated)]
#![allow(dead_code)]
extern crate thrift;
mod osquery;

use osquery::*;

const EXTENSION_SOCKET: &str = "/Users/p0n002h/.osquery/shell.em";

fn main() {
    let mut client = OsqueryClient::new(EXTENSION_SOCKET).unwrap();
    client.register_extension("thrust");
    println!("{:?}", client.ping());

    println!("{:#?}", client.query("SELECT * FROM osquery_info"));

    let _ = client.deregister_extension();
}
