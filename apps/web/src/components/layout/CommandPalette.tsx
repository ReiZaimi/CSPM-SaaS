import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  BoxesIcon,
  LaptopIcon,
  ListChecksIcon,
  MoonIcon,
  SearchIcon,
  SunIcon,
} from "lucide-react";

import { api } from "@/lib/api";
import type { Asset, Rule } from "@/lib/types";
import { NAV_GROUPS } from "@/components/layout/nav";
import { setThemeChoice, type ThemeChoice } from "@/lib/theme";
import { resourceTypeLabel } from "@/lib/format";
import { SeverityBadge } from "@/components/security/SeverityBadge";
import { Button } from "@/components/ui/button";
import {
  Command,
  CommandDialog,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandShortcut,
} from "@/components/ui/command";

/** Below this, a search is a letter or two and would match most of an estate. */
const MIN_QUERY = 2;
const RESULT_LIMIT = 6;
const DEBOUNCE_MS = 200;

const THEME_COMMANDS: {
  choice: ThemeChoice;
  label: string;
  icon: typeof SunIcon;
}[] = [
  { choice: "light", label: "Switch to light theme", icon: SunIcon },
  { choice: "dark", label: "Switch to dark theme", icon: MoonIcon },
  { choice: "system", label: "Follow the system theme", icon: LaptopIcon },
];

/**
 * The label for the shortcut, which is display only.
 *
 * Both chords are bound regardless, so a wrong guess about the platform costs a
 * reader nothing worse than a hint naming the other key.
 */
function shortcutLabel(): string {
  const mac =
    typeof navigator !== "undefined" &&
    /Mac|iPhone|iPad/.test(navigator.userAgent);
  return mac ? "\u2318K" : "Ctrl K";
}

/** The same substring rule the API applies, so both halves agree on a match. */
function matches(haystack: string, query: string): boolean {
  return haystack.toLowerCase().includes(query.toLowerCase());
}

/**
 * Everything reachable, from the keyboard, in one place.
 *
 * The product's own shape is what makes this worth having rather than a
 * fashion: an estate has thousands of assets and the inventory paginates fifty
 * at a time, so "open the storage account called payroll" is otherwise a
 * navigate, a search, and a page turn. Here it is four keystrokes.
 *
 * **What it searches, and why not more.** Assets go to the API, which already
 * filters by name (`GET /assets?search=`). Rules are filtered here, out of the
 * cache the rules page has usually already filled -- the catalogue is dozens of
 * entries, not thousands, so a round trip would buy nothing. Findings are
 * absent: the endpoint has no text search, and the honest workaround is that a
 * rule opens its own findings (`/findings?rule_id=`) and an asset opens its
 * own. Faking it by filtering one loaded page would silently search a
 * hundredth of the data and report nothing found for the rest.
 *
 * **Navigation only, no mutations.** No "run a scan" entry, deliberately.
 * Everything here is one keystroke from a highlighted row, and a scan reads a
 * customer's whole environment; an action with a cost belongs behind a button
 * somebody meant to press.
 *
 * `shouldFilter={false}` because two filters disagreeing is worse than one:
 * cmdk's fuzzy scoring would re-rank -- and sometimes drop -- rows the server
 * already decided matched.
 */
export function CommandPalette() {
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [debounced, setDebounced] = useState("");

  useEffect(() => {
    function onKeyDown(event: KeyboardEvent) {
      if (event.key.toLowerCase() !== "k") return;
      // Cmd on a Mac, Ctrl elsewhere. Both, rather than detecting the platform:
      // a wrong guess leaves a user with no shortcut at all.
      if (!event.metaKey && !event.ctrlKey) return;
      event.preventDefault();
      setOpen((previous) => !previous);
    }
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, []);

  // Typing "payroll" is six renders and would be six requests without this.
  useEffect(() => {
    const timer = setTimeout(() => setDebounced(query), DEBOUNCE_MS);
    return () => clearTimeout(timer);
  }, [query]);

  const searching = debounced.trim().length >= MIN_QUERY;

  const { data: assets } = useQuery({
    queryKey: ["command-assets", debounced],
    queryFn: () =>
      api
        .get<Asset[]>(
          `/api/v1/assets?search=${encodeURIComponent(debounced)}&limit=${RESULT_LIMIT}`,
        )
        .then((r) => r.data),
    enabled: open && searching,
  });

  // The same key the rules page uses, so opening the palette after visiting it
  // costs nothing and the two can never show different catalogues.
  const { data: rules } = useQuery({
    queryKey: ["rules"],
    queryFn: () => api.get<Rule[]>("/api/v1/rules").then((r) => r.data),
    enabled: open,
  });

  const trimmed = query.trim();
  const filtering = trimmed.length > 0;

  const pages = useMemo(
    () =>
      NAV_GROUPS.flatMap((group) =>
        group.items
          .filter(
            (item) =>
              !filtering || matches(`${item.label} ${group.label}`, trimmed),
          )
          .map((item) => ({ ...item, group: group.label })),
      ),
    [filtering, trimmed],
  );

  const ruleHits = useMemo(() => {
    if (!filtering || !rules) return [];
    return rules
      .filter((rule) =>
        matches(`${rule.name} ${rule.rule_id} ${rule.category}`, trimmed),
      )
      .slice(0, RESULT_LIMIT);
  }, [rules, filtering, trimmed]);

  const themeHits = useMemo(
    () =>
      filtering ? THEME_COMMANDS.filter((c) => matches(c.label, trimmed)) : [],
    [filtering, trimmed],
  );

  const go = useCallback(
    (to: string) => {
      setOpen(false);
      setQuery("");
      navigate(to);
    },
    [navigate],
  );

  const assetHits = searching ? (assets ?? []) : [];
  const nothing =
    pages.length === 0 &&
    assetHits.length === 0 &&
    ruleHits.length === 0 &&
    themeHits.length === 0;

  return (
    <>
      {/* A palette nobody knows about is dead weight, and the shortcut is
          undiscoverable by construction -- so the header carries a real
          control that names the key it stands for. */}
      <Button
        variant="outline"
        size="sm"
        onClick={() => setOpen(true)}
        className="gap-2 text-muted-foreground"
        aria-label="Search CloudGuard"
      >
        <SearchIcon data-icon="inline-start" />
        <span className="hidden sm:inline">Search</span>
        <kbd className="hidden rounded border bg-muted px-1.5 py-0.5 text-[10px] font-medium sm:inline">
          {shortcutLabel()}
        </kbd>
      </Button>

      <CommandDialog
        open={open}
        onOpenChange={(next: boolean) => {
          setOpen(next);
          if (!next) setQuery("");
        }}
        title="Search CloudGuard"
        description="Jump to a page, an asset, or a rule."
      >
        {/* Filtering is done above, against the same substring rule the API
          uses, so cmdk's own scoring is switched off rather than layered on. */}
        <Command shouldFilter={false}>
          <CommandInput
            value={query}
            onValueChange={setQuery}
            placeholder="Search assets, rules and pages…"
          />
          <CommandList>
            {/* Not cmdk's `CommandEmpty`, which renders off its own filtered
              count -- and `shouldFilter={false}` has taken that count out of
              the loop. Deciding emptiness here keeps one authority over what
              matched. */}
          {nothing && (
              <div className="py-6 text-center text-sm">
                <span className="text-muted-foreground">
                  Nothing matches “{trimmed}”.
                </span>
                {/* Says what was searched, because a bare "no results" over a
                partial search is a claim the product cannot support. */}
                <span className="mt-1 block text-xs text-muted-foreground">
                  Assets, rules and pages are searched. Findings are reached
                  through their rule or their asset.
                </span>
              </div>
            )}

            {pages.length > 0 && (
              <CommandGroup heading="Go to">
                {pages.map((page) => (
                  <CommandItem
                    key={page.to}
                    value={page.to}
                    onSelect={() => go(page.to)}
                  >
                    <page.icon />
                    {page.label}
                    <CommandShortcut>{page.group}</CommandShortcut>
                  </CommandItem>
                ))}
              </CommandGroup>
            )}

            {assetHits.length > 0 && (
              <CommandGroup heading="Assets">
                {assetHits.map((asset) => (
                  <CommandItem
                    key={asset.id}
                    value={asset.id}
                    onSelect={() => go(`/assets/${asset.id}`)}
                  >
                    <BoxesIcon />
                    <span className="min-w-0 flex-1 truncate">
                      {asset.name}
                    </span>
                    <span className="shrink-0 text-xs text-muted-foreground">
                      {resourceTypeLabel(asset.resource_type)}
                    </span>
                    {/* Exposure travels with the name: an asset worth jumping to
                    is usually one somebody is worried about. */}
                    <SeverityBadge level={asset.public_exposure} size="sm" />
                  </CommandItem>
                ))}
              </CommandGroup>
            )}

            {ruleHits.length > 0 && (
              <CommandGroup heading="Rules">
                {ruleHits.map((rule) => (
                  <CommandItem
                    key={rule.rule_id}
                    value={rule.rule_id}
                    // A rule on its own is a definition; what a reader wants is
                    // what it found in their environment.
                    onSelect={() =>
                      go(
                        `/findings?rule_id=${encodeURIComponent(rule.rule_id)}`,
                      )
                    }
                  >
                    <ListChecksIcon />
                    <span className="min-w-0 flex-1 truncate">{rule.name}</span>
                    <SeverityBadge level={rule.severity} size="sm" />
                  </CommandItem>
                ))}
              </CommandGroup>
            )}

            {themeHits.length > 0 && (
              <CommandGroup heading="Appearance">
                {themeHits.map((command) => (
                  <CommandItem
                    key={command.choice}
                    value={command.choice}
                    onSelect={() => {
                      setThemeChoice(command.choice);
                      setOpen(false);
                      setQuery("");
                    }}
                  >
                    <command.icon />
                    {command.label}
                  </CommandItem>
                ))}
              </CommandGroup>
            )}
          </CommandList>
        </Command>
      </CommandDialog>
    </>
  );
}
