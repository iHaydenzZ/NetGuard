export interface ThProps {
  children: React.ReactNode;
  onClick: () => void;
  align?: "left" | "right";
  width?: string;
}

export function Th({ children, onClick, align = "left", width = "" }: ThProps) {
  return (
    <th
      onClick={onClick}
      className={`px-3 py-2 text-[10px] font-semibold text-faint uppercase tracking-wider cursor-pointer select-none hover:text-dim transition-colors ${width} ${
        align === "right" ? "text-right" : "text-left"
      }`}
    >
      {children}
    </th>
  );
}
