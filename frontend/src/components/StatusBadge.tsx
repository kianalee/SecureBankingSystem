type StatusBadgeProps = {
  tone: "good" | "warn" | "bad" | "neutral";
  children: string;
};

export function StatusBadge({ tone, children }: StatusBadgeProps) {
  return <span className={`status-badge status-${tone}`}>{children}</span>;
}
