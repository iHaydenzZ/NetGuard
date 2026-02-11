export interface ProfileBarProps {
  profiles: string[];
  activeProfile: string | null;
  showProfileInput: boolean;
  setShowProfileInput: (v: boolean) => void;
  profileInput: string;
  setProfileInput: (v: string) => void;
  profileInputRef: React.RefObject<HTMLInputElement | null>;
  saveProfile: (name: string) => void;
  applyProfile: (name: string) => void;
  deleteProfile: (name: string) => void;
}

export function ProfileBar({
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
}: ProfileBarProps) {
  if (profiles.length === 0 && !showProfileInput) return null;

  return (
    <div className="flex items-center gap-2 px-4 py-1.5 bg-panel/60 border-b border-subtle/50 text-xs">
      <span className="text-faint font-medium uppercase tracking-wider text-[10px]">Profiles</span>
      <div className="h-3 w-px bg-subtle mx-0.5" />
      {profiles.map((p) => (
        <span key={p} className="inline-flex items-center gap-0.5">
          <button
            onClick={() => applyProfile(p)}
            className={`px-2.5 py-1 rounded-md transition-all duration-150 font-medium ${
              activeProfile === p
                ? "bg-iris/15 text-iris border border-iris/30"
                : "bg-raised text-dim border border-transparent hover:text-fg hover:bg-overlay"
            }`}
          >
            {p}
          </button>
          <button
            onClick={() => deleteProfile(p)}
            className="text-faint hover:text-danger transition-colors px-0.5"
            title={`Delete "${p}"`}
          >&times;</button>
        </span>
      ))}
      {showProfileInput ? (
        <input
          ref={profileInputRef}
          type="text"
          value={profileInput}
          onChange={(e) => setProfileInput(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") saveProfile(profileInput);
            if (e.key === "Escape") { setShowProfileInput(false); setProfileInput(""); }
          }}
          onBlur={() => { setShowProfileInput(false); setProfileInput(""); }}
          placeholder={"Profile name\u2026"}
          className="px-2 py-1 text-xs rounded-md bg-raised border border-iris/50 text-fg focus:outline-none w-28"
        />
      ) : (
        <button
          onClick={() => setShowProfileInput(true)}
          className="px-2.5 py-1 rounded-md bg-raised text-dim border border-transparent hover:text-fg hover:bg-overlay transition-all"
        >
          + Save Current
        </button>
      )}
    </div>
  );
}
