import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { CodeBlock } from "@/components/common/CodeBlock";

function withClipboard(writeText: (text: string) => Promise<void>) {
  Object.defineProperty(navigator, "clipboard", {
    value: { writeText },
    configurable: true,
  });
}

describe("a block of code", () => {
  afterEach(() => {
    Object.defineProperty(navigator, "clipboard", {
      value: undefined,
      configurable: true,
    });
  });

  it("shows the command as well as offering to copy it", () => {
    // A customer is being asked to run this against their own tenant. Pasting
    // a command they were never shown is the habit a security product must not
    // teach.
    withClipboard(() => Promise.resolve());
    render(<CodeBlock code="az role assignment delete --assignee 00000000" />);

    expect(
      screen.getByText(/az role assignment delete --assignee 00000000/),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /copy/i })).toBeInTheDocument();
  });

  it("copies the exact text and says that it did", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    withClipboard(writeText);
    render(<CodeBlock code="terraform plan" />);

    await userEvent.click(screen.getByRole("button", { name: /copy/i }));

    expect(writeText).toHaveBeenCalledWith("terraform plan");
    // The button itself is the confirmation: there is nowhere else on a code
    // block for one to live.
    expect(await screen.findByRole("button", { name: "Copied" })).toBeInTheDocument();
  });

  it("survives a browser that refuses the clipboard", async () => {
    // An insecure origin, or a policy that blocks it. Previously this threw
    // inside the handler; what matters is that the block stays usable and the
    // text stays selectable.
    render(<CodeBlock code="az account list" />);

    await userEvent.click(screen.getByRole("button", { name: /copy/i }));

    expect(screen.getByText("az account list")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Copied" })).not.toBeInTheDocument();
  });
});
