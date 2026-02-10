//! macOS packet capture using pf (Packet Filter) + dnctl/dummynet.
//!
//! Bandwidth shaping is delegated to the kernel via dummynet pipes.
//! Configuration via `std::process::Command` calling `dnctl` and `pfctl`.
