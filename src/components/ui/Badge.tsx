export interface BadgeProps {
  children: React.ReactNode;
  color: "caution" | "danger" | "neon" | "iris";
}

const colorMap = {
  caution: "bg-caution/10 text-caution border-caution/20",
  danger: "bg-danger/10 text-danger border-danger/20",
  neon: "bg-neon/10 text-neon border-neon/20",
  iris: "bg-iris/10 text-iris border-iris/20",
};

export function Badge({ children, color }: BadgeProps) {
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-full border text-[10px] font-semibold ${colorMap[color]}`}>
      {children}
    </span>
  );
}
