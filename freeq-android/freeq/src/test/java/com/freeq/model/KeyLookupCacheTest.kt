package com.freeq.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.io.File

/**
 * Pure-JVM tests for the key lookup's file store. The file is plain JSON in
 * a directory, so no Android runtime is needed.
 */
class KeyLookupCacheTest {

    private fun tempDir(name: String): File =
        File(System.getProperty("java.io.tmpdir"), "freeq-key-lookup-$name-${System.nanoTime()}").also {
            it.deleteRecursively()
        }

    @Test fun loads_nothing_before_the_first_save() {
        val dir = tempDir("empty")
        assertNull(AndroidKeyLookupStore(dir).load())
        dir.deleteRecursively()
    }

    @Test fun round_trips_a_snapshot_through_the_file() {
        val dir = tempDir("round-trip")
        val store = AndroidKeyLookupStore(dir)
        val snapshot = """{"keys":[],"records":[],"refreshed":[],"proven":["bafy"]}"""
        store.save(snapshot)
        assertEquals(snapshot, store.load())
        assertEquals("it is the one shared file", snapshot, File(dir, "key-lookup.json").readText())
        dir.deleteRecursively()
    }

    @Test fun a_second_store_on_the_same_directory_reads_what_the_first_wrote() {
        val dir = tempDir("shared")
        val snapshot = """{"keys":[],"records":[],"refreshed":[],"proven":["bafy"]}"""
        AndroidKeyLookupStore(dir).save(snapshot)
        assertEquals(snapshot, AndroidKeyLookupStore(dir).load())
        dir.deleteRecursively()
    }
}
