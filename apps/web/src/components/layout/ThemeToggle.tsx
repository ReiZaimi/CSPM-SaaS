import { LaptopIcon, MoonIcon, SunIcon } from "lucide-react";

import { setThemeChoice, useTheme, type ThemeChoice } from "@/lib/theme";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

const OPTIONS: { value: ThemeChoice; label: string; icon: typeof SunIcon }[] = [
  { value: "light", label: "Light", icon: SunIcon },
  { value: "dark", label: "Dark", icon: MoonIcon },
  { value: "system", label: "System", icon: LaptopIcon },
];

/**
 * Light, dark, or whatever the machine says.
 *
 * Three options rather than a two-state switch, because "system" is a real
 * answer and not a synonym for either: a laptop that goes dark in the evening
 * should take CloudGuard with it, and a binary toggle can only record the
 * choice made at one moment of one day.
 *
 * Worth having in a security product for an unglamorous reason -- this is a
 * console people sit in front of during an incident, often at night, and a
 * full-screen white findings table at 2am is a real cost. The severity palette
 * is re-lit for the dark surface rather than reused (`index.css`), so a
 * CRITICAL badge stays the most urgent thing on the page in both.
 */
export function ThemeToggle() {
  const { choice, resolved } = useTheme();
  const Icon = resolved === "dark" ? MoonIcon : SunIcon;

  return (
    <DropdownMenu>
      <DropdownMenuTrigger
        render={
          <Button
            variant="ghost"
            size="icon"
            // Names the state, not just the control: a screen reader user
            // otherwise has no way to tell which theme is currently on.
            aria-label={`Theme: ${choice}`}
          />
        }
      >
        <Icon />
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-36">
        <DropdownMenuRadioGroup
          value={choice}
          onValueChange={(value) => setThemeChoice(value as ThemeChoice)}
        >
          {OPTIONS.map((option) => (
            <DropdownMenuRadioItem key={option.value} value={option.value}>
              <option.icon />
              {option.label}
            </DropdownMenuRadioItem>
          ))}
        </DropdownMenuRadioGroup>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
