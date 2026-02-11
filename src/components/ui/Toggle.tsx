export interface ToggleProps {
  on: boolean;
  onToggle: () => void;
  color?: string;
}

export function Toggle({ on, onToggle, color }: ToggleProps) {
  return (
    <button
      onClick={onToggle}
      className={`toggle-track ${on ? "is-on" : ""}`}
      style={on && color ? { backgroundColor: color, boxShadow: `0 0 8px ${color}40` } : { backgroundColor: on ? "#00d8ff" : "#3d4f68" }}
    >
      <span className="toggle-thumb" />
    </button>
  );
}
