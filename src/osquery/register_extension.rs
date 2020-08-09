extern crate thrift;

use crate::osquery::osquery;

use osquery::*;
use std::collections::BTreeMap;
use std::error::Error;
use std::os::unix::net::UnixStream;
use thrift::protocol::{TBinaryInputProtocol, TBinaryOutputProtocol};

/// The osquery client struct which holds a thrift client to communicate
/// with the osquery extension manager socket.
pub struct OsqueryClient {
    /// The client object which is used to communicate with the osquery
    /// extensions manager socket.
    client: Box<dyn TExtensionManagerSyncClient>,

    /// The uuid of the extension which is sent by the osquery extension
    /// manager when the plugin is registered.
    uuid: i64,
}

impl OsqueryClient {
    /// Returns a new client that connects to a unix socket file over
    /// the thrift RPC. The function accepts a file path, without the
    /// protocol.
    ///
    /// # Arguments
    ///
    /// * `name` - A string that holds the socket file path
    ///
    /// # Examples
    ///
    /// ```
    /// let mut client = OsqueryClient::new("/tmp/osquery.sock").unwrap();
    /// client.register_plugin("plugin_name");
    /// let _ = client.ping();
    /// ```
    ///
    pub fn new(socket_file: &str) -> Option<Self> {
        let socket_tx = UnixStream::connect(socket_file).unwrap();
        let socket_rx = socket_tx.try_clone().unwrap();

        let in_proto = TBinaryInputProtocol::new(socket_tx, true);
        let out_proto = TBinaryOutputProtocol::new(socket_rx, true);

        Some(OsqueryClient {
            client: Box::new(ExtensionManagerSyncClient::new(in_proto, out_proto)),
            uuid: 0i64,
        })
    }

    /// Registers the plugin with the osquery extension manager with the name
    /// given to the plugin. During the registration, a uuid is returned back
    /// from the osquery extension manager which is available for the caller
    /// to use.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the extension
    pub fn register_extension(&mut self, name: &str) {
        let info = osquery::InternalExtensionInfo::new(
            String::from(name),
            String::from("0.0.1"),
            String::from("0.0.0"),
            String::from("0.0.0"),
        );

        let registry = osquery::ExtensionRegistry::default();
        let res = self.client.as_mut().register_extension(info, registry);

        match res {
            Err(e) => {
                eprintln!("Failed to register extension {:?}", e);
            }
            Ok(ext_status) => {
                println!("Registered plugin {}", name);
                self.uuid = ext_status.uuid.unwrap();
            }
        }
    }

    /// Ping the osquery extension manager. This can be used to check the
    /// health of the connection.
    pub fn ping(&mut self) -> Result<bool, Box<dyn Error>> {
        let res = self.client.as_mut().ping();
        match res {
            Err(e) => {
                eprintln!("Failed to ping the server: {:?}", e);
                Err(Box::new(e))
            }
            _ => Ok(true),
        }
    }

    /// Deregisters the extension from the osquery extension manager.
    pub fn deregister_extension(&mut self) -> Result<bool, Box<dyn Error>> {
        let res = self.client.as_mut().deregister_extension(self.uuid);
        match res {
            Err(e) => {
                eprintln!("Failed to deregister: {:?}", e);
                Err(Box::new(e))
            }
            _ => Ok(true),
        }
    }

    /// Given a query string, run the query against the connected osquery
    /// extension manager instance.
    ///
    /// # Arguments
    ///
    /// * `query` - A osquery compatible query string
    ///
    /// # Examples
    ///
    /// ```
    /// let mut client = OsqueryClient::new("~/.osquery/shell.em");
    /// client.register("dummy");
    /// let res = client.query("SELECT * FROM osquery_info");
    /// match res {
    ///     Ok(r) => println!("Response: {:#?}", r),
    ///     _ => println!("Failed to query")
    /// };
    /// ```
    pub fn query(&mut self, query: &str) -> Result<Vec<BTreeMap<String, String>>, Box<dyn Error>> {
        let res = self.client.as_mut().query(String::from(query));
        match res {
            Err(e) => Err(Box::new(e)),

            Ok(r) => {
                // FIXME: make sure the errors are returned when the
                // extension code is a success.
                //if r.status.unwrap().code.unwrap() == ExtensionCode::ExtSuccess as i32 {
                //    return Ok(r.response.unwrap());
                //}
                Ok(r.response.unwrap())
            }
        }
    }
}
