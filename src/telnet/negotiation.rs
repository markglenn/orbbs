use num_derive::{FromPrimitive, ToPrimitive};

#[derive(FromPrimitive, ToPrimitive)]
pub enum TelnetAction {
    Will = 251,
    Wont = 252,
    Do = 253,
    Dont = 254,
}

#[derive(FromPrimitive, ToPrimitive)]
pub enum TelnetOption {
    Echo = 1,
    SuppressGoAhead = 3,
    TerminalType = 24,
    WindowSize = 31,
    Subnegotiation = 250,
    SubnegotiationEnd = 240,
}
