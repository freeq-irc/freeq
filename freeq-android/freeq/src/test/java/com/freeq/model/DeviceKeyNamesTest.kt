package com.freeq.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pure-JVM tests for the entry names each account's device key is kept
 * under. The store itself is bound to the Android Keystore.
 */
class DeviceKeyNamesTest {

    private fun all(names: DeviceKeyNames.Names) =
        listOf(names.seed, names.createdAt, names.recordUri, names.refused)

    @Test fun two_accounts_get_different_names() {
        val alice = all(DeviceKeyNames.forDid("did:plc:alice"))
        val bob = all(DeviceKeyNames.forDid("did:plc:bob"))
        assertTrue("no name shared: $alice $bob", alice.intersect(bob.toSet()).isEmpty())
        assertEquals("four distinct names", 4, alice.toSet().size)
    }

    @Test fun one_account_gets_the_same_names_each_time() {
        assertEquals(DeviceKeyNames.forDid("did:plc:alice"), DeviceKeyNames.forDid("did:plc:alice"))
    }

    @Test fun the_old_shared_names_are_the_ones_deleted_and_no_account_uses_them() {
        assertEquals(
            listOf("deviceKeySeed", "deviceKeyCreatedAt", "deviceKeyRecordUri", "deviceKeyRefused"),
            DeviceKeyNames.LEGACY,
        )
        val alice = all(DeviceKeyNames.forDid("did:plc:alice"))
        assertTrue(alice.intersect(DeviceKeyNames.LEGACY.toSet()).isEmpty())
    }
}
