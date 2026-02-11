import { useState, useEffect, useCallback, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { BandwidthLimit } from "../bindings";

interface UseProfilesParams {
  setLimits: React.Dispatch<React.SetStateAction<Record<number, BandwidthLimit>>>;
  setBlockedPids: React.Dispatch<React.SetStateAction<Set<number>>>;
}

export function useProfiles({ setLimits, setBlockedPids }: UseProfilesParams) {
  const [profiles, setProfiles] = useState<string[]>([]);
  const [activeProfile, setActiveProfile] = useState<string | null>(null);
  const [showProfileInput, setShowProfileInput] = useState(false);
  const [profileInput, setProfileInput] = useState("");
  const profileInputRef = useRef<HTMLInputElement>(null);

  // Initial profiles fetch
  useEffect(() => {
    invoke<string[]>("list_profiles").then(setProfiles).catch(() => {});
  }, []);

  // Focus profile input when shown
  useEffect(() => { if (showProfileInput) profileInputRef.current?.focus(); }, [showProfileInput]);

  const saveProfile = useCallback(async (name: string) => {
    if (!name.trim()) return;
    await invoke("save_profile", { profileName: name.trim() });
    const updated = await invoke<string[]>("list_profiles");
    setProfiles(updated);
    setActiveProfile(name.trim());
    setShowProfileInput(false);
    setProfileInput("");
  }, []);

  const applyProfile = useCallback(async (name: string) => {
    await invoke<number>("apply_profile", { profileName: name });
    setActiveProfile(name);
    const [newLimits, newBlocked] = await Promise.all([
      invoke<Record<number, BandwidthLimit>>("get_bandwidth_limits"),
      invoke<number[]>("get_blocked_pids"),
    ]);
    setLimits(newLimits);
    setBlockedPids(new Set(newBlocked));
  }, [setLimits, setBlockedPids]);

  const deleteProfile = useCallback(async (name: string) => {
    await invoke("delete_profile", { profileName: name });
    const updated = await invoke<string[]>("list_profiles");
    setProfiles(updated);
    if (activeProfile === name) setActiveProfile(null);
  }, [activeProfile]);

  return {
    profiles,
    activeProfile,
    showProfileInput,
    setShowProfileInput,
    profileInput,
    setProfileInput,
    profileInputRef,
    saveProfile,
    applyProfile,
    deleteProfile,
  };
}
