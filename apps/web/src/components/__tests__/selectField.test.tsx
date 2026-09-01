/**
 * A filter has to say what it is filtering by.
 *
 * Base UI keeps a select's options in a portal that is not mounted while the
 * control is closed, so a bare `<SelectValue />` has nothing to read a label
 * from and falls back to the raw value. Every filter in the app had this: a
 * window set to "Last 30 days" sat there reading `30`, and a severity filter
 * read `CRITICAL` — the machine's word for the thing, shown to the person.
 */
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { SelectField } from "@/components/common/SelectField";

const WINDOWS = [
  { value: "1", label: "Last 24 hours" },
  { value: "7", label: "Last 7 days" },
  { value: "30", label: "Last 30 days" },
];

describe("SelectField", () => {
  it("shows the chosen option's label, not its value", () => {
    render(
      <SelectField
        value="30"
        onValueChange={() => {}}
        options={WINDOWS}
        ariaLabel="Window"
      />,
    );

    expect(screen.getByLabelText("Window")).toHaveTextContent("Last 30 days");
    expect(screen.getByLabelText("Window")).not.toHaveTextContent(/^30$/);
  });

  it("keeps saying it after the reader picks something else", async () => {
    // `userEvent` rather than `fireEvent`: the listbox is built out of pointer
    // events and a synthetic click never reaches an option.
    const user = userEvent.setup();
    const onValueChange = vi.fn();

    render(
      <SelectField
        value="30"
        onValueChange={onValueChange}
        options={WINDOWS}
        ariaLabel="Window"
      />,
    );

    await user.click(screen.getByLabelText("Window"));
    await user.click(await screen.findByRole("option", { name: "Last 7 days" }));

    expect(onValueChange).toHaveBeenCalledWith("7");
  });

  it("labels an option whose value is the empty string", () => {
    // The schedule control's "manual" option really is `""`, and treating an
    // empty value as "nothing selected" left that control blank — which reads
    // as broken rather than as switched off.
    render(
      <SelectField
        value=""
        onValueChange={() => {}}
        options={[
          { value: "", label: "Manual scanning only" },
          { value: "24", label: "Daily" },
        ]}
        ariaLabel="Schedule"
      />,
    );

    expect(screen.getByLabelText("Schedule")).toHaveTextContent(
      "Manual scanning only",
    );
  });

  it("falls back to the raw value rather than showing nothing", () => {
    // A value the option list does not carry — a stored filter from an older
    // build, say. Showing it is worse than showing a label and better than an
    // empty control that looks broken.
    render(
      <SelectField
        value="90"
        onValueChange={() => {}}
        options={WINDOWS}
        ariaLabel="Window"
      />,
    );

    expect(screen.getByLabelText("Window")).toHaveTextContent("90");
  });
});
