import { Link, useSearchParams } from "react-router-dom";
import { Button } from "@/components/ui";

/**
 * Where Entra sends the customer's browser back to after admin consent.
 * Unauthenticated by nature -- the backend already verified the signed state
 * before recording anything.
 */
export function ConnectResultPage() {
  const [params] = useSearchParams();
  const status = params.get("status");
  const message = params.get("message");
  const granted = status === "granted";

  return (
    <div className="flex min-h-screen items-center justify-center px-6">
      <div className="w-full max-w-md rounded-xl border border-stone-200 bg-white p-8 text-center shadow-sm">
        <div
          className={`mx-auto flex h-12 w-12 items-center justify-center rounded-full text-xl ${
            granted ? "bg-ok-bg text-ok" : "bg-critical-bg text-critical"
          }`}
        >
          {granted ? "✓" : "!"}
        </div>
        <h1 className="mt-4 text-lg font-semibold">
          {granted ? "Admin consent granted" : "Consent was not completed"}
        </h1>
        <p className="mt-2 text-sm text-stone-600">
          {granted
            ? "One step left: assign CloudGuard the Reader role on the subscription you want scanned, then verify the connection."
            : message || "You can close this window and try again."}
        </p>
        <Link to="/connections">
          <Button className="mt-6 w-full">Back to connections</Button>
        </Link>
      </div>
    </div>
  );
}
