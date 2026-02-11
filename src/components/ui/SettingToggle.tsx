import { Toggle } from "./Toggle";

export interface SettingToggleProps {
  label: string;
  on: boolean;
  onToggle: () => void;
  color?: string;
}

export function SettingToggle({ label, on, onToggle, color }: SettingToggleProps) {
  return (
    <div className="flex items-center gap-2">
      <span className="text-dim">{label}</span>
      <Toggle on={on} onToggle={onToggle} color={on ? color : undefined} />
    </div>
  );
}
