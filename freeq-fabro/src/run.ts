// freeq-fabro's lifetime: start the bot, open the relay once the bot is in,
// and shut down on a signal or when the server refuses the bot. A refusal is
// a stop on purpose, so it exits 0, as a signal does; anything else that
// stops start() is a fault, and is thrown for the caller to exit 1.

import { SignInRefusedError } from "@freeq/bot-kit";

/** The parts of a FreeqBot that run() uses. */
export interface RunBot {
  start(): Promise<"ready" | "deferred">;
  stop(reason?: string): Promise<void>;
  /** Settles with the reason once the bot has stopped, on its own too. */
  readonly stopped: Promise<string>;
  on(event: "ready", handler: () => void): unknown;
  on(event: "authErrorRetry", handler: (reason: string) => void): unknown;
  readonly client: { readonly nick: string | null };
  readonly identity: { readonly did: string };
}

/** What run() closes when it shuts down. */
export interface Relay {
  close(): void;
}

export interface RunDeps {
  bot: RunBot;
  /** Open the HTTP relay; called once, when the bot is in. */
  startRelay: () => Relay;
  exit: (code: number) => void;
  log: (msg: string) => void;
  onSignal: (signal: "SIGTERM" | "SIGINT", fn: () => void) => void;
}

export async function run({ bot, startRelay, exit, log, onSignal }: RunDeps): Promise<void> {
  let stopping = false;
  let relay: Relay | undefined;

  const shutdown = async (why: string): Promise<void> => {
    if (stopping) return;
    stopping = true;
    log(`${why} — shutting down`);
    relay?.close();
    await bot.stop("freeq-fabro stopping");
    exit(0);
  };
  onSignal("SIGTERM", () => void shutdown("SIGTERM"));
  onSignal("SIGINT", () => void shutdown("SIGINT"));
  // The bot stops itself when the server refuses its key or its sign-in.
  void bot.stopped.then((why) => shutdown(`refused: ${why}`));

  // The server could not check the bot just now, and the SDK keeps trying
  // on a growing wait: said once, until the bot is in.
  let retrySaid = false;
  bot.on("authErrorRetry", (reason) => {
    if (retrySaid) return;
    retrySaid = true;
    log(`the server could not check this bot just now: ${reason}`);
  });
  bot.on("ready", () => {
    retrySaid = false;
  });

  // Posts go nowhere until the server has let the bot in, so the relay
  // opens then: at once, or at the 'ready' after a deferred start.
  const openRelay = (): void => {
    if (stopping || relay) return;
    relay = startRelay();
    log(`connected as ${bot.client.nick} (${bot.identity.did})`);
  };

  let how: "ready" | "deferred";
  try {
    how = await bot.start();
  } catch (err) {
    // A signal or a refusal is already shutting down; a signal during
    // start() stops the bot, which rejects start().
    if (stopping) return;
    if (err instanceof SignInRefusedError) {
      await shutdown(`refused: ${err.reason}`);
      return;
    }
    throw err;
  }
  if (stopping) return;
  if (how === "ready") openRelay();
  else bot.on("ready", openRelay);
}
