package com.freeq.model

import com.freeq.ffi.KeyLookupStore
import java.io.File

/**
 * Where the SDK's key lookup keeps what it has learned between launches:
 * the signing keys it found, each account's proven records with their
 * listing time, and the proof CIDs that checked.
 *
 * One file per device, shared by every session on it, guests included, and
 * kept through sign-out, as the web app keeps its snapshot.
 * Nothing here is secret — every record in it is public in its account's
 * repository, and every proof was checked before it was kept — so it sits in
 * `filesDir` beside the buffer cache rather than in `securePrefs`, and needs
 * no account to name it.
 */
class AndroidKeyLookupStore(private val dir: File) : KeyLookupStore {

    private val file: File get() = File(dir, FILE_NAME)

    override fun load(): String? =
        try {
            if (file.exists()) file.readText() else null
        } catch (e: Exception) {
            android.util.Log.w("freeq.keylookup", "reading the key lookup cache failed", e)
            null
        }

    /**
     * Write through a temporary file and rename, so a process killed
     * mid-write leaves the previous snapshot intact rather than a half file.
     */
    override fun save(snapshot: String) {
        try {
            if (!dir.exists() && !dir.mkdirs()) return
            val tmp = File(dir, TMP_NAME)
            tmp.writeText(snapshot)
            if (!tmp.renameTo(file)) tmp.delete()
        } catch (e: Exception) {
            android.util.Log.w("freeq.keylookup", "keeping the key lookup cache failed", e)
        }
    }

    companion object {
        private const val FILE_NAME = "key-lookup.json"
        private const val TMP_NAME = "$FILE_NAME.tmp"
    }
}
