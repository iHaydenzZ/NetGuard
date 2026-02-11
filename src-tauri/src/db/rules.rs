//! Bandwidth rules profile table CRUD operations.

use anyhow::Result;
use rusqlite::params;

use super::{Database, SavedRule};

impl Database {
    /// Save a bandwidth rule to a profile.
    pub fn save_rule(
        &self,
        profile: &str,
        exe_path: &str,
        process_name: &str,
        download_bps: u64,
        upload_bps: u64,
        blocked: bool,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO bandwidth_rules (profile_name, exe_path, process_name, download_bps, upload_bps, blocked)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![profile, exe_path, process_name, download_bps, upload_bps, blocked as i32],
        )?;
        Ok(())
    }

    /// Load all rules for a profile.
    pub fn load_rules(&self, profile: &str) -> Result<Vec<SavedRule>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare_cached(
            "SELECT exe_path, process_name, download_bps, upload_bps, blocked
             FROM bandwidth_rules WHERE profile_name = ?1",
        )?;

        let rows = stmt.query_map(params![profile], |row| {
            Ok(SavedRule {
                exe_path: row.get(0)?,
                process_name: row.get(1)?,
                download_bps: row.get(2)?,
                upload_bps: row.get(3)?,
                blocked: row.get::<_, i32>(4)? != 0,
            })
        })?;

        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }

    /// List all profile names.
    pub fn list_profiles(&self) -> Result<Vec<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare_cached(
            "SELECT DISTINCT profile_name FROM bandwidth_rules ORDER BY profile_name",
        )?;
        let rows = stmt.query_map([], |row| row.get(0))?;
        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }

    /// Delete an entire profile and all its rules.
    pub fn delete_profile(&self, profile: &str) -> Result<usize> {
        let conn = self.conn.lock().unwrap();
        let deleted = conn.execute(
            "DELETE FROM bandwidth_rules WHERE profile_name = ?1",
            params![profile],
        )?;
        Ok(deleted)
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::open_memory_db;

    #[test]
    fn test_save_and_load_rules() {
        let db = open_memory_db();

        db.save_rule(
            "default",
            "C:\\chrome.exe",
            "chrome.exe",
            1_000_000,
            500_000,
            false,
        )
        .unwrap();
        db.save_rule(
            "default",
            "C:\\firefox.exe",
            "firefox.exe",
            2_000_000,
            1_000_000,
            true,
        )
        .unwrap();

        let rules = db.load_rules("default").unwrap();
        assert_eq!(rules.len(), 2);

        // Find chrome rule.
        let chrome_rule = rules
            .iter()
            .find(|r| r.exe_path == "C:\\chrome.exe")
            .unwrap();
        assert_eq!(chrome_rule.process_name, "chrome.exe");
        assert_eq!(chrome_rule.download_bps, 1_000_000);
        assert_eq!(chrome_rule.upload_bps, 500_000);
        assert!(!chrome_rule.blocked);

        // Find firefox rule.
        let firefox_rule = rules
            .iter()
            .find(|r| r.exe_path == "C:\\firefox.exe")
            .unwrap();
        assert_eq!(firefox_rule.process_name, "firefox.exe");
        assert_eq!(firefox_rule.download_bps, 2_000_000);
        assert_eq!(firefox_rule.upload_bps, 1_000_000);
        assert!(firefox_rule.blocked);

        // Loading rules for a non-existent profile returns empty.
        let empty = db.load_rules("nonexistent").unwrap();
        assert!(empty.is_empty());
    }

    #[test]
    fn test_list_profiles() {
        let db = open_memory_db();

        db.save_rule("gaming", "C:\\game.exe", "game.exe", 0, 0, false)
            .unwrap();
        db.save_rule("work", "C:\\slack.exe", "slack.exe", 0, 0, false)
            .unwrap();
        db.save_rule("gaming", "C:\\steam.exe", "steam.exe", 0, 0, false)
            .unwrap();

        let profiles = db.list_profiles().unwrap();
        assert_eq!(profiles.len(), 2);
        // Profiles are ordered alphabetically.
        assert!(profiles.contains(&"gaming".to_string()));
        assert!(profiles.contains(&"work".to_string()));
    }

    #[test]
    fn test_delete_profile() {
        let db = open_memory_db();

        db.save_rule("temp", "C:\\app.exe", "app.exe", 100, 200, false)
            .unwrap();
        db.save_rule("temp", "C:\\other.exe", "other.exe", 300, 400, true)
            .unwrap();

        // Verify the profile exists.
        let profiles = db.list_profiles().unwrap();
        assert!(profiles.contains(&"temp".to_string()));

        // Delete the profile.
        let deleted = db.delete_profile("temp").unwrap();
        assert_eq!(deleted, 2);

        // Profile should no longer appear.
        let profiles = db.list_profiles().unwrap();
        assert!(!profiles.contains(&"temp".to_string()));

        // Rules should be gone.
        let rules = db.load_rules("temp").unwrap();
        assert!(rules.is_empty());
    }

    #[test]
    fn test_save_rule_upsert() {
        let db = open_memory_db();

        // Save a rule.
        db.save_rule(
            "default",
            "C:\\chrome.exe",
            "chrome.exe",
            1_000_000,
            500_000,
            false,
        )
        .unwrap();

        // Save again with updated values for the same profile + exe_path.
        db.save_rule(
            "default",
            "C:\\chrome.exe",
            "chrome.exe",
            2_000_000,
            750_000,
            true,
        )
        .unwrap();

        // Should still be one rule, not two (UNIQUE constraint + INSERT OR REPLACE).
        let rules = db.load_rules("default").unwrap();
        assert_eq!(rules.len(), 1);

        let rule = &rules[0];
        assert_eq!(rule.exe_path, "C:\\chrome.exe");
        assert_eq!(rule.download_bps, 2_000_000);
        assert_eq!(rule.upload_bps, 750_000);
        assert!(rule.blocked);
    }
}
