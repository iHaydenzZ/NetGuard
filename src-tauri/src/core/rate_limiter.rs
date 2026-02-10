//! Token Bucket rate limiter for per-process bandwidth control.
//!
//! Each rate-limited process gets its own bucket. Burst allowance is 2x the
//! configured rate. Uses `governor` crate or custom implementation.
