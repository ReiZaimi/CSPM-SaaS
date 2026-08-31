import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it } from "vitest";

import { ThemeToggle } from "@/components/layout/ThemeToggle";
import { DARK_CLASS, THEME_STORAGE_KEY, setThemeChoice } from "@/lib/theme";

describe("the theme toggle", () => {
  beforeEach(() => {
    window.localStorage.clear();
    document.documentElement.className = "";
    setThemeChoice("system");
  });

  it("says which theme is current, not merely that it is a theme control", () => {
    setThemeChoice("dark");
    render(<ThemeToggle />);

    // A control labelled only "Theme" leaves a screen reader user unable to
    // tell what it is currently set to.
    expect(screen.getByRole("button", { name: "Theme: dark" })).toBeInTheDocument();
  });

  it("offers system as its own answer, not as a synonym for light", async () => {
    render(<ThemeToggle />);
    fireEvent.click(screen.getByRole("button"));

    expect(await screen.findByRole("menuitemradio", { name: "System" })).toBeInTheDocument();
    expect(screen.getByRole("menuitemradio", { name: "Light" })).toBeInTheDocument();
    expect(screen.getByRole("menuitemradio", { name: "Dark" })).toBeInTheDocument();
  });

  it("applies and stores the choice", async () => {
    render(<ThemeToggle />);
    fireEvent.click(screen.getByRole("button"));
    fireEvent.click(await screen.findByRole("menuitemradio", { name: "Dark" }));

    expect(document.documentElement.classList.contains(DARK_CLASS)).toBe(true);
    expect(window.localStorage.getItem(THEME_STORAGE_KEY)).toBe("dark");
  });
});
