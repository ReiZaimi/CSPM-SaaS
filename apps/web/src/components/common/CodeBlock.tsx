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
 * The button is visible rather than revealed on hover. A hover-only affordance
 * does not exist at all on a touch screen, and dims by default so it does not
 * compete with the code it sits on.
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
  /** Extra classes for the `pre`, for blocks that are styled differently. */
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
    <div className="group relative">
      {/* Right padding, so a long single line scrolls under the button rather
          than ending beneath it. */}
      <pre
        className={cn(
          "overflow-x-auto rounded-lg border bg-muted/60 p-3 pr-11 font-mono text-xs leading-relaxed",
          className,
        )}
      >
        {code}
      </pre>
      <Button
        variant="ghost"
        size="icon-sm"
        aria-label={copied ? "Copied" : label}
        className="absolute right-1.5 top-1.5 opacity-60 transition-opacity hover:opacity-100 focus-visible:opacity-100 group-hover:opacity-100"
        onClick={copy}
      >
        {copied ? <CheckIcon className="text-ok" /> : <CopyIcon />}
      </Button>
    </div>
  );
}
