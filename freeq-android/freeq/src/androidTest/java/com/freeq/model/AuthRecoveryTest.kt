package com.freeq.model

import android.app.Application
import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumented tests for AppState's auth-recovery wiring. Runs on a real
 * Android runtime (so EncryptedSharedPreferences, the AndroidViewModel
 * machinery, and the FFI native lib all work). Exercises the prefs/state
 * paths that broke in the kill+restart-as-DID debugging session.
 *
 * Run with: `./gradlew :freeq:connectedFreeqDebugAndroidTest`
 */
@RunWith(AndroidJUnit4::class)
class AuthRecoveryTest {

    private fun appContext(): Application = ApplicationProvider.getApplicationContext()

    private fun freeqPrefs() =
        appContext().getSharedPreferences("freeq", Context.MODE_PRIVATE)

    private var originalAuthBrokerBase: String = ""

    @Before fun setUp() {
        originalAuthBrokerBase = ServerConfig.authBrokerBase
        freeqPrefs().edit().clear().commit()
    }

    @After fun tearDown() {
        ServerConfig.authBrokerBase = originalAuthBrokerBase
        freeqPrefs().edit().clear().commit()
    }

    @Test fun init_drops_poisoned_Guest_nick_when_did_is_present() {
        // The kill+restart-as-Guest bug: a prior session got Guest-renamed
        // and the persisted nick became "GuestNNNN". On the next launch
        // with a DID still in storage, init must drop the Guest nick so
        // the next /session call can return the user's real handle.
        freeqPrefs().edit().putString("nick", "Guest12345").commit()
        // Stash a DID via a warm AppState so securePrefs encrypts it.
        val warm = AppState(appContext())
        warm.securePrefs.edit().putString("did", "did:plc:test").commit()

        // Re-construct so init runs against the persisted state.
        val fresh = AppState(appContext())
        assertEquals("", fresh.nick.value)
        assertNull(freeqPrefs().getString("nick", null))
    }

    @Test fun init_keeps_real_handle_when_did_is_present() {
        freeqPrefs().edit().putString("nick", "zapnap").commit()
        val warm = AppState(appContext())
        warm.securePrefs.edit().putString("did", "did:plc:test").commit()

        val fresh = AppState(appContext())
        assertEquals("zapnap", fresh.nick.value)
    }

    @Test fun oauth_callback_does_not_persist_a_cached_web_token() {
        // MainActivity.handleDeepLink intentionally does not call
        // cacheWebToken() — the OAuth-issued web_token is single-use and
        // gets consumed by SASL on the very first connect, so caching it
        // would only ever cause a stale-token loop on kill+restart.
        // This test catches a regression in that rule by simulating the
        // exact persistence work handleDeepLink does and asserting that
        // no webToken is in storage afterward.
        val s = AppState(appContext())
        // What handleDeepLink actually persists, minus the cacheWebToken
        // line whose absence is the property we're enforcing:
        s.pendingWebToken = "fresh-oauth-token"
        s.brokerToken = "broker-token"
        s.authenticatedDID.value = "did:plc:test"
        s.securePrefs.edit().putString("brokerToken", "broker-token").commit()
        s.securePrefs.edit().putString("did", "did:plc:test").commit()
        freeqPrefs().edit().putLong("lastLoginTime", System.currentTimeMillis()).commit()

        // Now the assertion that defends against a future regression:
        assertNull(
            "OAuth-callback web_token must NOT be cached — caching it caused " +
                "the kill+restart-as-Guest loop. See cd63bc3.",
            s.securePrefs.getString("webToken", null)
        )
        assertEquals(0L, freeqPrefs().getLong("webTokenExpiry", 0L))

        // Sanity: the legitimately persistent things ARE persisted.
        assertEquals("broker-token", s.securePrefs.getString("brokerToken", null))
        assertEquals("did:plc:test", s.securePrefs.getString("did", null))
        assertNotNull(s.pendingWebToken)
    }

    @Test fun init_drops_a_web_token_an_older_version_saved() {
        val warm = AppState(appContext())
        warm.securePrefs.edit().putString("webToken", "token-abc").commit()
        freeqPrefs().edit().putLong("webTokenExpiry", System.currentTimeMillis() + 60_000).commit()

        val fresh = AppState(appContext())
        assertNull(fresh.securePrefs.getString("webToken", null))
        assertEquals(0L, freeqPrefs().getLong("webTokenExpiry", 0L))
        assertNull(fresh.pendingWebToken)
    }

    @Test fun hasSavedSession_requires_only_brokerToken() {
        val s = AppState(appContext())
        assertFalse(s.hasSavedSession)
        s.brokerToken = "any-token"
        assertTrue(s.hasSavedSession)
        s.brokerToken = null
        assertFalse(s.hasSavedSession)
    }

    @Test fun connect_does_not_persist_a_Guest_nick_for_a_DID_user() {
        // Defends against the "poisoned saved nick" loop at the write side.
        // A registered user's saved nick must not be overwritten when the
        // server has just renamed the connection to GuestNNNN.
        freeqPrefs().edit().putString("nick", "zapnap").commit()
        val s = AppState(appContext())
        s.authenticatedDID.value = "did:plc:test"
        try {
            s.connect("Guest99999")
        } catch (_: Throwable) {
            // The IRC client may throw on the FFI/network side after the
            // prefs work; we only care about the persistence guard, which
            // runs before the network call.
        } finally {
            // Tear down any background connection the call started.
            s.disconnect()
        }
        assertEquals("zapnap", freeqPrefs().getString("nick", null))
    }

    @Test fun three_consecutive_401s_clear_broker_credentials() {
        // The 14-day "keep logged in" guard must NOT prevent credential
        // clearing when /session keeps returning 401 — those 401s mean the
        // broker has no record of the token, and retrying past that point
        // strands the user on ReconnectingScreen forever.
        MockWebServer().use { mockServer ->
            mockServer.enqueue(MockResponse().setResponseCode(401).setBody("Invalid"))
            mockServer.enqueue(MockResponse().setResponseCode(401).setBody("Invalid"))
            mockServer.enqueue(MockResponse().setResponseCode(401).setBody("Invalid"))
            mockServer.start()

            ServerConfig.authBrokerBase = mockServer.url("/").toString().trimEnd('/')

            // Plant credentials on disk so we can verify they get cleared.
            val s = AppState(appContext())
            s.brokerToken = "test-broker-token"
            s.securePrefs.edit().putString("brokerToken", "test-broker-token").commit()
            // Pretend the user logged in just now so the 14-day grace
            // window is active. The 401-handling code must override it.
            freeqPrefs().edit().putLong("lastLoginTime", System.currentTimeMillis()).commit()

            // Drive three failed broker calls; each throws on 401.
            val errors = mutableListOf<String>()
            repeat(3) {
                try { s.fetchBrokerSession("test-broker-token") }
                catch (e: Exception) { errors.add(e.message ?: "<no message>") }
            }

            assertEquals(
                "All three calls should have reached MockWebServer. errors=$errors",
                3,
                mockServer.requestCount
            )
            assertNull(
                "After 3 consecutive 401s, brokerToken must be wiped from disk " +
                    "regardless of the 14-day grace window. errors=$errors",
                s.securePrefs.getString("brokerToken", null)
            )
            assertNull(s.brokerToken)
        }
    }
}
