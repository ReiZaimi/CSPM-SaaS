/**
 * A spinner with a sentence, for the two steps that wait on somebody else.
 *
 * Only rendered while waiting is still a plausible explanation. Once a
 * deployment has stalled the spinner is replaced rather than kept company: a
 * spinner that never stops claims progress that is not happening, and gives no
 * way to tell a colleague who has not got round to it from a deployment that
 * failed outright.
 */
export function WaitingNote({ text }: { text: string }) {
  return (
    <p className="flex items-center gap-2 text-sm text-muted-foreground">
      <span className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-input border-t-foreground" />
      {text}
    </p>
  );
}
