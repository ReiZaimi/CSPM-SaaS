import { cn } from "@/lib/format";

/**
 * The shield mark. A checked shield rather than a lock: CloudGuard's job is to
 * confirm things are sound, not to seal them shut.
 */
export function ShieldMark({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" className={cn("h-7 w-7", className)} aria-hidden="true">
      <path
        fill="currentColor"
        d="M12 2 4 5.5v6c0 4.6 3.2 8.9 8 10.5 4.8-1.6 8-5.9 8-10.5v-6L12 2Z"
        opacity="0.12"
      />
      <path
        fill="none"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinejoin="round"
        d="M12 2.9 4.8 6.1v5.4c0 4.2 2.9 8.1 7.2 9.6 4.3-1.5 7.2-5.4 7.2-9.6V6.1L12 2.9Z"
      />
      <path
        fill="none"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinecap="round"
        strokeLinejoin="round"
        d="m8.8 12.2 2.2 2.2 4.2-4.4"
      />
    </svg>
  );
}
