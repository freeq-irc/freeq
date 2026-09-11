/**
 * The layout every bar across the top of the app shares, so the bars cannot
 * drift apart. Each bar adds its own colours: background, text and line.
 */
export const TOP_BAR = 'flex items-center justify-center gap-3 py-1.5 px-4 text-xs shrink-0 border-b';

/** The colours of a bar that offers something rather than warns. */
export const TOP_BAR_ACCENT = 'bg-accent/5 border-accent/10';

/** The bar's sentence, which wraps before any button does. */
export const TOP_BAR_TEXT = 'min-w-0';

/** A button beside the sentence: never shrinks, never breaks onto two lines. */
export const TOP_BAR_BUTTON = 'shrink-0 whitespace-nowrap font-semibold hover:underline';

/** A button inside the sentence: stays on one line. */
export const TOP_BAR_INLINE_BUTTON = 'whitespace-nowrap font-semibold hover:underline';

/** The ✕ that dismisses a bar. */
export const TOP_BAR_CLOSE = 'shrink-0 whitespace-nowrap text-fg-dim/40 hover:text-fg-dim ml-1';
