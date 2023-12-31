mod telnet;

use anyhow::Result;
use telnet::{
    connection::Connection,
    frame::TelnetFrame,
    negotiation::{TelnetAction, TelnetOption},
};
use tokio::net::{TcpListener, TcpStream};

#[tokio::main]
async fn main() -> Result<()> {
    println!("Listening on port 2323");

    let listener = TcpListener::bind("0.0.0.0:2323").await?;

    loop {
        let (socket, addr) = listener.accept().await?;

        println!("Accepted connection from: {}", addr);

        tokio::spawn(async move {
            match process(socket).await {
                Ok(_) => println!("Connection closed from {}", addr),
                Err(e) => println!("Failed to process connection: {}", e),
            };
        });
    }
}

async fn process(socket: TcpStream) -> Result<()> {
    let mut connection = Connection::new(socket);

    // Enable server echo
    connection
        .send_negotiation(TelnetAction::Will, TelnetOption::Echo)
        .await?;

    // Enable suppress go ahead
    connection
        .send_negotiation(TelnetAction::Will, TelnetOption::SuppressGoAhead)
        .await?;

    // Ask the client to enable sending terminal type
    connection
        .send_negotiation(TelnetAction::Do, TelnetOption::TerminalType)
        .await?;

    connection.request_terminal_type().await?;

    loop {
        match connection.next_frame().await {
            Some(TelnetFrame::IAC(iac)) => {
                println!("Telnet IAC frame received: {:?}", iac);
            }
            Some(TelnetFrame::CSI(f)) => {
                println!("CSI frame received: {:?}", f);
            }
            Some(TelnetFrame::Data(r)) => {
                println!("Data frame received: {:?}", r);
                connection.send(r.as_slice()).await?;
            }
            Some(TelnetFrame::Next) => {}

            // No frame available
            None => return Ok(()),
        }
    }
}
