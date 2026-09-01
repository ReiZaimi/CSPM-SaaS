import { useEffect, useRef, useState } from "react";

import { useT } from "@/i18n";
import { Button } from "@/components/ui/button";

/**
 * Copy to clipboard, with the confirmation on the button itself.
 *
 * The timer is cleared on unmount: the consent step is copied and then left
 * behind the moment the link is sent, and a `setState` two seconds after that
 * is a warning in the console about a component that is already gone.
 */
export function CopyButton({
  text,
  label,
  variant = "secondary",
}: {
  text: string;
  label: string;
  variant?: "secondary" | "outline" | "ghost";
}) {
  const t = useT();
  const [copied, setCopied] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => () => {
    if (timer.current) clearTimeout(timer.current);
  }, []);

  return (
    <Button
      type="button"
      variant={variant}
      onClick={() => {
        void navigator.clipboard.writeText(text);
        setCopied(true);
        if (timer.current) clearTimeout(timer.current);
        timer.current = setTimeout(() => setCopied(false), 2000);
      }}
    >
      {copied ? t.connection.copied : label}
    </Button>
  );
}
