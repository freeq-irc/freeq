/**
 * How the kit names the harness it runs in, in text people read and on the
 * wire. The defaults are pi's, so freeq-pi's text and wire output are what
 * they were before the kit existed.
 */
export interface HarnessNames {
  /**
   * The harness's short name: the prefix of its identities and nicks
   * (`pi-<slug>`), the `agent` of its discovery hello, and the word for a
   * session in text ("another pi session").
   */
  name: string;
  /** How the person runs a subcommand: `/freeq accept` in pi. */
  hint(sub: string): string;
}

export const PI_NAMES: HarnessNames = {
  name: "pi",
  hint: (sub) => `/freeq ${sub}`,
};
