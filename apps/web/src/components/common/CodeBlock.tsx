import { useEffect, useRef, useState } from "react";
import { toast } from "sonner";
import { CheckIcon, CopyIcon } from "lucide-react";

import { Button } from "@/components/ui/button";
import { cn } from "@/lib/format";

/**
 * A block of code or evidence, with the one thing anybody wants to do to it.
 *
 * Everything shown in a monospace block here exists to be run or pasted
 * somewhere else -- an az command, an ARM fragment, the raw JSON behind a
 * finding -- so selecting it by hand is the failure case, and it is the failure
 * case exactly when the content is long enough to matter.
 *
 * The button is visible rather than revealed on hover -- a hover-only
 * affordance does not exist at all on a touch screen -- and sits in its own
 * column beside the code, never over it, so a long line scrolls past nothing.
 *
 * Clipboard access can be refused outright -- an insecure origin, a browser
 * policy -- so the failure says what to do instead rather than leaving a button
 * that silently does nothing.
 */
export function CodeBlock({
  code,
  className,
  label = "Copy to clipboard",
}: {
  code: string;
  /** Extra classes for the frame, for blocks styled differently. */
  className?: string;
  label?: string;
}) {
  const [copied, setCopied] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => () => {
    if (timer.current) clearTimeout(timer.current);
  }, []);

  function copy() {
    const written = navigator.clipboard?.writeText(code);
    if (!written) {
      toast.error("Could not copy", {
        description: "This browser refused clipboard access — select the text instead.",
      });
      return;
    }
    void written
      .then(() => {
        setCopied(true);
        if (timer.current) clearTimeout(timer.current);
        timer.current = setTimeout(() => setCopied(false), 1500);
      })
      .catch(() =>
        toast.error("Could not copy", {
          description: "This browser refused clipboard access — select the text instead.",
        }),
      );
  }

  return (
    // A column for the code and a column for the button, rather than the button
    // floating over the code. Overlaying it worked on a wide card and failed in
    // the narrow panels: a horizontally scrolling command ran underneath a
    // transparent icon, so the button sat on top of characters it did not hide
    // and the line looked corrupted rather than scrollable.
    <div
      className={cn(
        "flex items-start gap-2 rounded-lg border bg-muted/60 p-3 text-xs leading-relaxed",
        className,
      )}
    >
      {/* `min-w-0`, or the flex item refuses to shrink below its content and
          the block widens its container instead of scrolling inside it. */}
      {/* The size and colour live on the frame, so a caller restyling one
          block changes both the code and the space around it. */}
      <pre className="min-w-0 flex-1 overflow-x-auto font-mono">
        {code}
      </pre>
      <Button
        variant="ghost"
        size="icon-sm"
        aria-label={copied ? "Copied" : label}
        className="shrink-0 opacity-60 transition-opacity hover:opacity-100 focus-visible:opacity-100"
        onClick={copy}
      >
        {copied ? <CheckIcon className="text-ok" /> : <CopyIcon />}
      </Button>
    </div>
  );
}
