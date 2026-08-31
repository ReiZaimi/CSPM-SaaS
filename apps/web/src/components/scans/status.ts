/**
 * The states in which a scan is still doing something.
 *
 * Its own module because both the page (which polls while any scan is in one of
 * these) and the card (which decides whether to offer Cancel) read it, and a
 * constant exported beside a component defeats fast refresh for that file.
 */
export const IN_FLIGHT = [
  "QUEUED",
  "DISCOVERING",
  "NORMALIZING",
  "EVALUATING",
  "CALCULATING_RISK",
];
