import { createContext, useContext, type ReactNode } from "react";
import { en, type Strings } from "./en";

/**
 * Minimal i18n. Deliberately not a library: the MVP ships one language, and the
 * job here is to make sure no string is hardcoded in a component, not to build
 * a translation pipeline nobody is using yet.
 */
const I18nContext = createContext<Strings>(en);

export function I18nProvider({ children }: { children: ReactNode }) {
  return <I18nContext.Provider value={en}>{children}</I18nContext.Provider>;
}

export function useT(): Strings {
  return useContext(I18nContext);
}
