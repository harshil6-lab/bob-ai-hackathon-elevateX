/**
 * Logo — the ElevateX Defence System mark.
 *
 * A shield carrying two ascending chevrons: the shield reads as defence, the
 * chevrons as rank insignia and as the "elevate" in ElevateX. Drawn inline as
 * a single path set so it inherits the surrounding text colour and stays crisp
 * in both themes — no raster asset, no extra network request.
 *
 * Purely decorative by default; pass a `title` where the mark has to stand in
 * for text (a link with no visible label, for example).
 */

export interface LogoProps {
  /** Rendered size in pixels. The mark is square. */
  size?: number;
  /** Accessible name. Omit for a decorative mark beside visible text. */
  title?: string;
  className?: string;
}

export function Logo({ size = 26, title, className }: LogoProps) {
  const labelled = Boolean(title);

  return (
    <svg
      className={`logo${className ? ` ${className}` : ''}`}
      width={size}
      height={size}
      viewBox="0 0 32 32"
      fill="none"
      role={labelled ? 'img' : undefined}
      aria-hidden={labelled ? undefined : true}
      focusable="false"
    >
      {labelled ? <title>{title}</title> : null}

      {/* Shield */}
      <path
        d="M16 2.6 L28 7 V15.6 C28 22.4 23 27.7 16 29.6 C9 27.7 4 22.4 4 15.6 V7 Z"
        className="logo__shield"
        strokeWidth="1.8"
        strokeLinejoin="round"
      />
      {/* Leading chevron — the accent carries the identity */}
      <path
        d="M10.2 17.4 L16 11.6 L21.8 17.4"
        className="logo__chevron logo__chevron--lead"
        strokeWidth="2.6"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      {/* Trailing chevron */}
      <path
        d="M10.2 23 L16 17.2 L21.8 23"
        className="logo__chevron"
        strokeWidth="2.2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}
