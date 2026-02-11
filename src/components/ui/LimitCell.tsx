export interface LimitCellProps {
  pid: number;
  field: "dl" | "ul";
  currentBps: number;
  editing: { pid: number; field: "dl" | "ul" } | null;
  editRef: React.RefObject<HTMLInputElement | null>;
  onStartEdit: (pid: number, field: "dl" | "ul") => void;
  onApply: (pid: number, field: "dl" | "ul", value: string) => void;
  onCancel: () => void;
}

export function LimitCell({
  pid, field, currentBps, editing, editRef, onStartEdit, onApply, onCancel,
}: LimitCellProps) {
  const isEditing = editing?.pid === pid && editing?.field === field;
  if (isEditing) {
    return (
      <td className="px-2 py-0.5 text-right" onClick={(e) => e.stopPropagation()}>
        <input
          ref={editRef}
          type="text"
          defaultValue={currentBps > 0 ? (currentBps >= 1024 * 1024 ? `${(currentBps / (1024 * 1024)).toFixed(1)}m` : `${Math.round(currentBps / 1024)}`) : ""}
          placeholder="KB/s"
          className="w-20 px-2 py-0.5 text-xs text-right rounded-md bg-overlay border border-neon/40 text-fg font-mono focus:outline-none focus:border-neon"
          onKeyDown={(e) => {
            if (e.key === "Enter") onApply(pid, field, e.currentTarget.value);
            if (e.key === "Escape") onCancel();
            if (e.key === "Delete" || (e.key === "Backspace" && !e.currentTarget.value)) onApply(pid, field, "");
          }}
          onBlur={(e) => onApply(pid, field, e.currentTarget.value)}
        />
      </td>
    );
  }
  return (
    <td
      className="px-3 py-1.5 text-right font-mono"
      onDoubleClick={(e) => { e.stopPropagation(); onStartEdit(pid, field); }}
    >
      {currentBps > 0 ? (
        <span className="text-caution text-xs">
          {currentBps >= 1024 * 1024 ? `${(currentBps / (1024 * 1024)).toFixed(1)} MB/s` : `${Math.round(currentBps / 1024)} KB/s`}
        </span>
      ) : (
        <span className="text-faint/40 text-xs">{"\u2014"}</span>
      )}
    </td>
  );
}
