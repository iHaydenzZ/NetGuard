# Security Hardening Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix 6 confirmed security issues from audit, prioritized by severity (CRITICAL → LOW).

**Architecture:** All changes are surgical — small edits to existing files. No new files created. Rust backend fixes use defensive arithmetic and input validation. Frontend fix is a config-only CSP change. Each task is independently testable and committable.

**Tech Stack:** Rust (backend logic + tests), JSON (Tauri config), TypeScript (frontend validation)

---

### Task 1: Enable Content Security Policy (CRITICAL — #2)

**Files:**
- Modify: `src-tauri/tauri.conf.json:20-22`

**Step 1: Apply the CSP fix**

Replace line 21 in `src-tauri/tauri.conf.json`:
```json
    "security": {
      "csp": null
    }
```
with:
```json
    "security": {
      "csp": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src ipc: http://ipc.localhost"
    }
```

Rationale:
- `default-src 'self'` blocks all external resource loading
- `script-src 'self'` prevents inline/injected scripts
- `style-src 'self' 'unsafe-inline'` needed for Tailwind's runtime styles
- `img-src 'self' data:` needed for base64-encoded process icons
- `connect-src ipc: http://ipc.localhost` needed for Tauri IPC in dev and production

**Step 2: Smoke test**

Run: `npm run tauri dev`
Expected: App launches, all UI renders correctly, no CSP errors in DevTools console. Process icons display. IPC commands work (traffic data flows).

**Step 3: Commit**

```bash
git add src-tauri/tauri.conf.json
git commit -m "security: enable Content Security Policy in Tauri config

Restricts script/resource loading to same-origin only.
Allows inline styles (Tailwind), data: URIs (process icons),
and Tauri IPC connections."
```

---

### Task 2: Validate WinDivert filter input (HIGH — #4)

**Files:**
- Modify: `src-tauri/src/commands/logic.rs:109-112`
- Test: `src-tauri/src/commands/logic.rs` (existing test module)

**Step 1: Write the failing tests**

Add these tests to the existing `mod tests` block in `src-tauri/src/commands/logic.rs`, after the `test_resolve_filter_custom` test:

```rust
    #[test]
    fn test_validate_filter_rejects_empty() {
        let result = validate_windivert_filter("");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_filter_rejects_too_long() {
        let long = "a".repeat(513);
        let result = validate_windivert_filter(&long);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_filter_rejects_null_bytes() {
        let result = validate_windivert_filter("tcp\0or udp");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_filter_rejects_non_ascii() {
        let result = validate_windivert_filter("tcp or удп");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_filter_accepts_valid() {
        assert!(validate_windivert_filter("tcp or udp").is_ok());
        assert!(validate_windivert_filter("tcp.DstPort == 5201").is_ok());
        assert!(validate_windivert_filter("tcp.DstPort == 5201 or tcp.SrcPort == 5201").is_ok());
    }
```

**Step 2: Run tests to verify they fail**

Run: `cd src-tauri && cargo test --lib commands::logic::tests::test_validate_filter -- --nocapture`
Expected: FAIL — `validate_windivert_filter` not found

**Step 3: Implement the validation function**

Add this function in `src-tauri/src/commands/logic.rs` right before `resolve_intercept_filter`:

```rust
/// Maximum allowed length for a WinDivert filter string.
const MAX_FILTER_LEN: usize = 512;

/// Validate a WinDivert filter string for safety.
/// Rejects empty, overly long, non-ASCII, or null-byte-containing filters.
pub fn validate_windivert_filter(filter: &str) -> Result<(), AppError> {
    if filter.is_empty() {
        return Err(AppError::InvalidInput("Filter cannot be empty".into()));
    }
    if filter.len() > MAX_FILTER_LEN {
        return Err(AppError::InvalidInput(format!(
            "Filter too long ({} chars, max {MAX_FILTER_LEN})",
            filter.len()
        )));
    }
    if filter.bytes().any(|b| b == 0) {
        return Err(AppError::InvalidInput("Filter contains null bytes".into()));
    }
    if !filter.is_ascii() {
        return Err(AppError::InvalidInput(
            "Filter must contain only ASCII characters".into(),
        ));
    }
    Ok(())
}
```

**Step 4: Wire validation into resolve_intercept_filter**

Replace the existing `resolve_intercept_filter` function:

```rust
/// Resolve and validate the WinDivert filter, defaulting to "tcp or udp" if not specified.
pub fn resolve_intercept_filter(filter: Option<String>) -> Result<String, AppError> {
    let filter = filter.unwrap_or_else(|| "tcp or udp".to_string());
    validate_windivert_filter(&filter)?;
    Ok(filter)
}
```

**Step 5: Update the call site in system.rs**

In `src-tauri/src/commands/system.rs:92`, change:

```rust
    let filter = resolve_intercept_filter(filter);
```
to:
```rust
    let filter = resolve_intercept_filter(filter)?;
```

**Step 6: Update existing tests for new return type**

In `src-tauri/src/commands/logic.rs`, update the two existing filter tests:

Replace:
```rust
    #[test]
    fn test_resolve_filter_default() {
        assert_eq!(resolve_intercept_filter(None), "tcp or udp");
    }

    #[test]
    fn test_resolve_filter_custom() {
        assert_eq!(
            resolve_intercept_filter(Some("tcp.DstPort == 5201".to_string())),
            "tcp.DstPort == 5201"
        );
    }
```
with:
```rust
    #[test]
    fn test_resolve_filter_default() {
        assert_eq!(resolve_intercept_filter(None).unwrap(), "tcp or udp");
    }

    #[test]
    fn test_resolve_filter_custom() {
        assert_eq!(
            resolve_intercept_filter(Some("tcp.DstPort == 5201".to_string())).unwrap(),
            "tcp.DstPort == 5201"
        );
    }
```

**Step 7: Run all tests**

Run: `cd src-tauri && cargo test --lib commands::logic`
Expected: ALL PASS (existing + new)

**Step 8: Commit**

```bash
git add src-tauri/src/commands/logic.rs src-tauri/src/commands/system.rs
git commit -m "security: validate WinDivert filter input before passing to driver

Rejects empty, overly long (>512), non-ASCII, and null-byte filters.
Prevents malformed filter strings from reaching the kernel driver."
```

---

### Task 3: Cap allocation size in win_net_table.rs (MEDIUM — #5)

**Files:**
- Modify: `src-tauri/src/core/win_net_table.rs:88-290`

**Step 1: Add a maximum buffer size constant**

Add at the top of `src-tauri/src/core/win_net_table.rs`, after the existing constants (after line 15):

```rust
/// Maximum buffer size for IP helper table queries (16 MB).
/// Prevents unbounded allocation from a corrupted API return value.
const MAX_TABLE_BUFFER: usize = 16 * 1024 * 1024;
```

**Step 2: Add buffer size cap to all 4 scan functions**

In each of the 4 functions (`scan_tcp_table`, `scan_udp_table`, `scan_tcp6_table`, `scan_udp6_table`), after the first API call that gets the size, add a cap check. The pattern is identical in all 4 functions.

For `scan_tcp_table` (line 104), replace:
```rust
    let mut buf = vec![0u8; size as usize];
```
with:
```rust
    let alloc_size = size as usize;
    if alloc_size > MAX_TABLE_BUFFER {
        tracing::warn!("GetExtendedTcpTable requested {alloc_size} bytes, exceeds cap");
        return;
    }
    let mut buf = vec![0u8; alloc_size];
```

For `scan_udp_table` (line 155), replace:
```rust
    let mut buf = vec![0u8; size as usize];
```
with:
```rust
    let alloc_size = size as usize;
    if alloc_size > MAX_TABLE_BUFFER {
        tracing::warn!("GetExtendedUdpTable requested {alloc_size} bytes, exceeds cap");
        return;
    }
    let mut buf = vec![0u8; alloc_size];
```

For `scan_tcp6_table` (line 206), replace:
```rust
    let mut buf = vec![0u8; size as usize];
```
with:
```rust
    let alloc_size = size as usize;
    if alloc_size > MAX_TABLE_BUFFER {
        tracing::warn!("GetExtendedTcpTable(AF_INET6) requested {alloc_size} bytes, exceeds cap");
        return;
    }
    let mut buf = vec![0u8; alloc_size];
```

For `scan_udp6_table` (line 257), replace:
```rust
    let mut buf = vec![0u8; size as usize];
```
with:
```rust
    let alloc_size = size as usize;
    if alloc_size > MAX_TABLE_BUFFER {
        tracing::warn!("GetExtendedUdpTable(AF_INET6) requested {alloc_size} bytes, exceeds cap");
        return;
    }
    let mut buf = vec![0u8; alloc_size];
```

**Step 3: Cap num_entries by buffer length**

In all 4 scan functions, replace the `num_entries` line with a capped version. The pattern for each:

For `scan_tcp_table` (line 123), replace:
```rust
    let num_entries = u32::from_ne_bytes(buf[0..4].try_into().unwrap()) as usize;
```
with:
```rust
    let raw_entries = u32::from_ne_bytes(buf[0..4].try_into().unwrap()) as usize;
    let num_entries = raw_entries.min(buf.len().saturating_sub(4) / row_size);
```

Apply the same pattern for `scan_udp_table` (line 174), `scan_tcp6_table` (line 225), and `scan_udp6_table` (line 276).

**Step 4: Verify it compiles**

Run: `cd src-tauri && cargo check`
Expected: No errors

**Step 5: Run existing tests**

Run: `cd src-tauri && cargo test`
Expected: All existing tests pass (win_net_table has no unit tests — it calls Windows APIs — but no regressions elsewhere)

**Step 6: Commit**

```bash
git add src-tauri/src/core/win_net_table.rs
git commit -m "security: cap allocation size and num_entries in win_net_table FFI

Limits buffer allocation to 16MB max. Caps parsed num_entries by
actual buffer length to prevent oversized loops from corrupted data."
```

---

### Task 4: Harden pointer arithmetic for 32-bit safety (MEDIUM — #1)

**Files:**
- Modify: `src-tauri/src/core/win_net_table.rs` (4 loop bodies)

**Step 1: Replace raw arithmetic with checked arithmetic in all 4 scan loops**

In all 4 functions, replace the loop body pattern:
```rust
    for i in 0..num_entries {
        let offset = 4 + i * row_size;
        if offset + row_size > buf.len() {
            break;
        }
```
with:
```rust
    for i in 0..num_entries {
        let offset = match 4_usize.checked_add(i.checked_mul(row_size).unwrap_or(usize::MAX)) {
            Some(o) => o,
            None => break,
        };
        if offset.saturating_add(row_size) > buf.len() {
            break;
        }
```

Apply this to:
- `scan_tcp_table` (lines 126-130)
- `scan_udp_table` (lines 177-181)
- `scan_tcp6_table` (lines 228-232)
- `scan_udp6_table` (lines 279-283)

**Step 2: Verify it compiles**

Run: `cd src-tauri && cargo check`
Expected: No errors

**Step 3: Run all tests**

Run: `cd src-tauri && cargo test`
Expected: All pass

**Step 4: Commit**

```bash
git add src-tauri/src/core/win_net_table.rs
git commit -m "security: use checked arithmetic in win_net_table pointer math

Prevents integer overflow in offset calculation on 32-bit targets.
Uses checked_mul/checked_add to break safely on overflow."
```

---

### Task 5: Validate profile names (MEDIUM — #6)

**Files:**
- Modify: `src-tauri/src/commands/logic.rs`
- Modify: `src-tauri/src/commands/rules.rs:72,97,145`
- Test: `src-tauri/src/commands/logic.rs` (existing test module)

**Step 1: Write the failing tests**

Add to the `mod tests` block in `src-tauri/src/commands/logic.rs`:

```rust
    #[test]
    fn test_validate_profile_name_accepts_valid() {
        assert!(validate_profile_name("my-profile").is_ok());
        assert!(validate_profile_name("Profile_1").is_ok());
        assert!(validate_profile_name("work").is_ok());
    }

    #[test]
    fn test_validate_profile_name_rejects_empty() {
        assert!(validate_profile_name("").is_err());
        assert!(validate_profile_name("   ").is_err());
    }

    #[test]
    fn test_validate_profile_name_rejects_too_long() {
        let long = "a".repeat(65);
        assert!(validate_profile_name(&long).is_err());
    }

    #[test]
    fn test_validate_profile_name_rejects_special_chars() {
        assert!(validate_profile_name("profile<script>").is_err());
        assert!(validate_profile_name("../etc/passwd").is_err());
        assert!(validate_profile_name("name\0null").is_err());
    }
```

**Step 2: Run tests to verify they fail**

Run: `cd src-tauri && cargo test --lib commands::logic::tests::test_validate_profile -- --nocapture`
Expected: FAIL — `validate_profile_name` not found

**Step 3: Implement the validation function**

Add in `src-tauri/src/commands/logic.rs`, after the `validate_windivert_filter` function:

```rust
/// Maximum allowed length for a profile name.
const MAX_PROFILE_NAME_LEN: usize = 64;

/// Validate a profile name. Allows alphanumeric, hyphens, underscores, spaces.
pub fn validate_profile_name(name: &str) -> Result<(), AppError> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(AppError::InvalidInput("Profile name cannot be empty".into()));
    }
    if trimmed.len() > MAX_PROFILE_NAME_LEN {
        return Err(AppError::InvalidInput(format!(
            "Profile name too long ({} chars, max {MAX_PROFILE_NAME_LEN})",
            trimmed.len()
        )));
    }
    if !trimmed
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == ' ')
    {
        return Err(AppError::InvalidInput(
            "Profile name may only contain letters, digits, hyphens, underscores, and spaces"
                .into(),
        ));
    }
    Ok(())
}
```

**Step 4: Run new tests**

Run: `cd src-tauri && cargo test --lib commands::logic::tests::test_validate_profile`
Expected: ALL PASS

**Step 5: Wire validation into the command handlers**

In `src-tauri/src/commands/rules.rs`, add the import at line 11:

```rust
use super::logic::{build_profile_rules, match_rules_to_processes, validate_profile_name, ApplyAction};
```

Then add validation as the first line in each of these 3 functions:

In `save_profile` (line 72), add after the function signature opening brace:
```rust
    validate_profile_name(&profile_name)?;
```

In `apply_profile` (line 97), add after the function signature opening brace:
```rust
    validate_profile_name(&profile_name)?;
```

In `delete_profile` (line 145), add after the function signature opening brace:
```rust
    validate_profile_name(&profile_name)?;
```

**Step 6: Run all tests**

Run: `cd src-tauri && cargo test`
Expected: ALL PASS

**Step 7: Commit**

```bash
git add src-tauri/src/commands/logic.rs src-tauri/src/commands/rules.rs
git commit -m "security: validate profile names in backend commands

Rejects empty, >64 char, and non-alphanumeric profile names.
Applied to save_profile, apply_profile, and delete_profile."
```

---

### Task 6: Use saturating_add for traffic counters (LOW — #8)

**Files:**
- Modify: `src-tauri/src/core/traffic.rs:83-85`

**Step 1: Replace += with saturating_add**

In `src-tauri/src/core/traffic.rs`, replace lines 83-85:

```rust
            c.bytes_sent += sent;
            c.bytes_recv += recv;
```
with:
```rust
            c.bytes_sent = c.bytes_sent.saturating_add(sent);
            c.bytes_recv = c.bytes_recv.saturating_add(recv);
```

**Step 2: Run existing tests**

Run: `cd src-tauri && cargo test --lib core::traffic`
Expected: ALL PASS (existing tests cover `record_bytes` accumulation)

**Step 3: Commit**

```bash
git add src-tauri/src/core/traffic.rs
git commit -m "security: use saturating_add for traffic byte counters

Prevents theoretical u64 wraparound on cumulative byte counts."
```

---

### Task 7: Final verification

**Step 1: Run all Rust tests**

Run: `cd src-tauri && cargo test`
Expected: All 43+ tests pass

**Step 2: Run frontend tests**

Run: `npm test`
Expected: All 31 tests pass

**Step 3: Run clippy**

Run: `cd src-tauri && cargo clippy -- -D warnings`
Expected: No warnings

**Step 4: Commit all together if any stragglers**

Only if needed — each task already commits independently.
