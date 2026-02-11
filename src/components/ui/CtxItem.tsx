export interface CtxItemProps {
  children: React.ReactNode;
  onClick: () => void;
}

export function CtxItem({ children, onClick }: CtxItemProps) {
  return (
    <button
      onClick={onClick}
      className="w-full text-left px-3 py-1.5 text-xs text-dim hover:bg-overlay hover:text-fg transition-colors rounded-sm mx-0.5"
    >
      {children}
    </button>
  );
}
