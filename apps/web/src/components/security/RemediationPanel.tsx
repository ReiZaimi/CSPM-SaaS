import { useState } from "react";
import { CheckIcon, CopyIcon, InfoIcon } from "lucide-react";

import type { RemediationSpec } from "@/lib/types";
import { formatEffort } from "@/lib/format";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

/**
 * How to fix it, in whichever form the reader works in.
 *
 * The prose was all there was, and prose is what somebody reads at two in the
 * morning -- so it stays, as the first tab. What is new is everything the
 * backend already had and the UI never showed: the settings that must become
 * true, the commands that set them, the Terraform arguments for a reader who
 * manages this in code, and an Azure Policy that refuses the whole class of it.
 *
 * A tab appears only when there is something in it. An empty "Terraform" tab
 * would suggest CloudGuard had nothing to say about Terraform, when the truth
 * is that this particular rule has nothing to say -- and for Policy that
 * difference is load-bearing: `enforceable: false` is a fact about the check
 * (an MFA requirement is a directory setting no policy can express), not work
 * left undone.
 */
export function RemediationPanel({
  remediation,
  spec,
  effortMinutes,
  footer,
}: {
  remediation: string;
  spec?: RemediationSpec | null;
  effortMinutes?: number;
  /**
   * What to do about this fix, as opposed to how to make it. Optional because
   * the rules catalogue shows the same panel for a rule nobody has a finding
   * for, and there is no work to schedule against a rule.
   */
  footer?: React.ReactNode;
}) {
  const hasCli = (spec?.cli?.length ?? 0) > 0;
  const hasTerraform = (spec?.terraform?.length ?? 0) > 0;
  const hasPolicy = Boolean(spec?.azure_policy);

  return (
    <Card>
      <CardHeader>
        <CardTitle>Recommended fix</CardTitle>
        <CardDescription>
          {effortMinutes
            ? `Estimated effort: ${formatEffort(effortMinutes)}`
            : "What to change, and how to confirm it took"}
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        {spec && spec.expected_state.length > 0 && (
          <div className="rounded-lg border bg-muted/40 p-3">
            <p className="text-xs font-medium text-muted-foreground">
              This finding closes when
            </p>
            <ul className="mt-1.5 flex flex-col gap-1">
              {spec.expected_state.map((state) => (
                <li key={state.field} className="flex items-start gap-2 text-sm">
                  <CheckIcon className="mt-0.5 size-3.5 shrink-0 text-ok" aria-hidden />
                  <span>{state.describes}</span>
                </li>
              ))}
            </ul>
          </div>
        )}

        <Tabs defaultValue="steps">
          <TabsList>
            <TabsTrigger value="steps">Steps</TabsTrigger>
            {hasCli && <TabsTrigger value="cli">CLI</TabsTrigger>}
            {hasTerraform && <TabsTrigger value="terraform">Terraform</TabsTrigger>}
            {hasPolicy && <TabsTrigger value="policy">Policy</TabsTrigger>}
          </TabsList>

          <TabsContent value="steps">
            <p className="whitespace-pre-wrap text-sm leading-relaxed text-muted-foreground">
              {remediation}
            </p>
          </TabsContent>

          {hasCli && (
            <TabsContent value="cli" className="flex flex-col gap-2">
              {spec!.cli.map((command) => (
                <CodeBlock key={command} code={command} />
              ))}
              <p className="text-xs text-muted-foreground">
                Placeholders are left in angle brackets on purpose — a command carrying a
                made-up resource name is a command somebody runs.
              </p>
            </TabsContent>
          )}

          {hasTerraform && (
            <TabsContent value="terraform" className="flex flex-col gap-2">
              <CodeBlock
                code={spec!.terraform
                  .map((hint) => `${hint.attribute} = ${hint.value}`)
                  .join("\n")}
              />
              <p className="text-xs text-muted-foreground">
                The arguments to set on the resource you already manage — not a whole
                block, which would be missing everything Terraform requires and could not
                be applied.
              </p>
            </TabsContent>
          )}

          {hasPolicy && (
            <TabsContent value="policy" className="flex flex-col gap-2">
              <CodeBlock code={JSON.stringify(spec!.azure_policy, null, 2)} />
              <p className="text-xs text-muted-foreground">
                Deploying this refuses the whole class of this misconfiguration, rather
                than only today's instance of it.
              </p>
            </TabsContent>
          )}
        </Tabs>

        {spec?.notes && (
          <p className="flex items-start gap-2 rounded-lg border border-dashed p-3 text-xs leading-relaxed text-muted-foreground">
            <InfoIcon className="mt-0.5 size-3.5 shrink-0" aria-hidden />
            {spec.notes}
          </p>
        )}

        {footer && <div className="border-t pt-4">{footer}</div>}
      </CardContent>
    </Card>
  );
}

function CodeBlock({ code }: { code: string }) {
  const [copied, setCopied] = useState(false);

  return (
    <div className="group relative">
      <pre className="overflow-x-auto rounded-lg border bg-muted/60 p-3 pr-11 font-mono text-xs leading-relaxed">
        {code}
      </pre>
      <Button
        variant="ghost"
        size="icon"
        aria-label={copied ? "Copied" : "Copy to clipboard"}
        className="absolute right-1.5 top-1.5 opacity-0 transition-opacity group-hover:opacity-100 focus-visible:opacity-100"
        onClick={() => {
          void navigator.clipboard?.writeText(code);
          setCopied(true);
          window.setTimeout(() => setCopied(false), 1500);
        }}
      >
        {copied ? <CheckIcon className="text-ok" /> : <CopyIcon />}
      </Button>
    </div>
  );
}
