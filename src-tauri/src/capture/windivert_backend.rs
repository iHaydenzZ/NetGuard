//! Windows packet capture using WinDivert 2.x.
//!
//! SAFETY: This module intercepts live network packets.
//! Always use the narrowest possible filter during development.
//! See PRD section 8.2 for mandatory safeguards.
