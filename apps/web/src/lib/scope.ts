/**
 * Where an asset sits, read out of the provider's own identifier.
 *
 * Parsed rather than fetched, because the id is authoritative about this and
 * nothing else needs asking -- an ARM id spells out its subscription and its
 * resource group. The backend derives containment the same way when it builds
 * the asset graph, so a group shown here and an edge drawn there agree by
 * construction rather than by coincidence.
 *
 * Case-insensitive on the segment names because ARM is: `/resourcegroups/` and
 * `/resourceGroups/` are the same path, and an estate whose ids arrive in the
 * other casing would otherwise show every asset as ungrouped.
 */
export interface AssetScope {
  subscriptionId: string | null;
  resourceGroup: string | null;
}

export function parseScope(providerResourceId: string | undefined): AssetScope {
  if (!providerResourceId) return { subscriptionId: null, resourceGroup: null };

  const parts = providerResourceId.split("/");
  let subscriptionId: string | null = null;
  let resourceGroup: string | null = null;

  for (let i = 0; i < parts.length - 1; i += 1) {
    const segment = parts[i].toLowerCase();
    if (segment === "subscriptions") subscriptionId = parts[i + 1];
    if (segment === "resourcegroups") resourceGroup = parts[i + 1];
  }

  return { subscriptionId, resourceGroup };
}

/**
 * The label a reader recognises.
 *
 * A directory asset -- a user, a service principal -- belongs to the tenant and
 * sits in no resource group at all. Calling that "Ungrouped" would read as a
 * tagging oversight rather than as what it is, so it is named.
 */
export function scopeLabel(providerResourceId: string | undefined): string {
  const { subscriptionId, resourceGroup } = parseScope(providerResourceId);
  if (resourceGroup) return resourceGroup;
  if (subscriptionId) return "Subscription scope";
  return "Directory";
}
