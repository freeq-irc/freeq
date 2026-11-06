/**
 * A pluggable per-channel cipher.
 *
 * `FreeqClient.setChannelCipher(channel, cipher)` hands the send/receive path
 * an encryptor the app owns — a group-key cipher (`makeGroupCipher` in
 * `e2ee_group.ts`) for an instant room, or anything else with the same shape.
 * The client treats it exactly like the built-in ENC1 passphrase path: `say()`
 * encrypts and tags `+encrypted`, a `+E` channel accepts the send, and every
 * inbound PRIVMSG (single line, multiline batch, CHATHISTORY replay) that
 * `isCiphertext` recognises is decrypted before it reaches a `message` event.
 */
export interface ChannelCipher {
  /** Plaintext → wire body. `null` means "cannot encrypt right now" (no key). */
  encrypt(plaintext: string): Promise<string | null>;
  /** Wire body → plaintext. `null` means "could not decrypt" (wrong key,
   *  unknown epoch, tampered); the client shows `[encrypted message]`. */
  decrypt(wire: string): Promise<string | null>;
  /** Cheap, synchronous: does this wire body belong to this cipher? */
  isCiphertext(wire: string): boolean;
}
