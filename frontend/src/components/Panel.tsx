import { PropsWithChildren } from "react";

type PanelProps = PropsWithChildren<{
  title?: string;
  eyebrow?: string;
  className?: string;
}>;

export function Panel({ title, eyebrow, className, children }: PanelProps) {
  return (
    <section className={`panel ${className ?? ""}`.trim()}>
      {(eyebrow || title) && (
        <div className="panel-header">
          {eyebrow ? <p className="eyebrow">{eyebrow}</p> : null}
          {title ? <h2>{title}</h2> : null}
        </div>
      )}
      {children}
    </section>
  );
}
