import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

export type Option = { value: string; label: string };

/**
 * A select whose trigger says what was chosen.
 *
 * The bug this exists to make impossible: Base UI keeps a select's options in a
 * portal that is **not mounted while the control is closed**, so a bare
 * `<SelectValue />` has no item to read a label from and falls back to the raw
 * value. A filter set to "Last 30 days" then sits there reading `30`, and one
 * set to Critical reads `CRITICAL` — the machine's word for the thing, shown to
 * the person.
 *
 * `ScheduleControl` solved it locally by rendering from the value; every other
 * filter in the app had the same bug. Passing one list of options to both the
 * trigger and the menu also removes the other half of the problem, which is a
 * label defined twice and only updated once.
 */
export function SelectField({
  id,
  value,
  onValueChange,
  options,
  ariaLabel,
  className,
  size = "sm",
  disabled,
  placeholder,
  fallbackLabel,
}: {
  /** Forwarded to the trigger, so a `FieldLabel`'s `htmlFor` still lands. */
  id?: string;
  value: string;
  onValueChange: (value: string) => void;
  options: Option[];
  /** What this filter is, for a reader who cannot see the row it sits in. */
  ariaLabel: string;
  className?: string;
  size?: "sm" | "default";
  disabled?: boolean;
  /** Shown when nothing is selected — usually because there is nothing to pick. */
  placeholder?: string;
  /**
   * What to call a value the option list does not carry. Without it the raw
   * value is printed, which is right for a stale filter and wrong for anything
   * whose value is an identifier a person never chose to read.
   */
  fallbackLabel?: (value: string) => string;
}) {
  return (
    <Select
      value={value}
      disabled={disabled}
      onValueChange={(next) => onValueChange(String(next ?? ""))}
    >
      <SelectTrigger
        id={id}
        size={size}
        className={className}
        aria-label={ariaLabel}
      >
        <SelectValue placeholder={placeholder}>
          {(current) => {
            const chosen = String(current ?? "");
            // The options are consulted first, including for the empty string:
            // "" is a legitimate value with a legitimate label — "Manual
            // scanning only" — and treating empty as "nothing selected" left
            // that control blank, which reads as broken rather than as off.
            const known = options.find((option) => option.value === chosen);
            if (known) return known.label;
            if (!chosen) return placeholder ?? "";
            return fallbackLabel?.(chosen) ?? chosen;
          }}
        </SelectValue>
      </SelectTrigger>
      <SelectContent>
        {options.map((option) => (
          <SelectItem key={option.value} value={option.value}>
            {option.label}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}
