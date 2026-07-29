plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.freeq"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.freeq.app"
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "0.1"

        ndk {
            abiFilters += listOf("arm64-v8a", "x86_64")
        }

        // Defaults consumed by ServerConfig.kt. Override per flavor for
        // deployments other than freeq.at (e.g. zerosum.org with embedded
        // auth broker).
        buildConfigField("String", "IRC_SERVER", "\"irc.freeq.at:6667\"")
        buildConfigField("String", "AUTH_BROKER_BASE", "\"https://auth.freeq.at\"")

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }

    // Per-deployment baked-in URLs. Values surface to the app via
    // BuildConfig.IRC_SERVER / BuildConfig.AUTH_BROKER_BASE, read by
    // ServerConfig.kt. Build a specific flavor with e.g.
    //   ./gradlew :freeq:assembleZerosumDebug
    //   ./gradlew :freeq:assembleFreeqDebug
    // To add a deployment, append a new productFlavors entry below.
    flavorDimensions += "deployment"
    productFlavors {
        create("freeq") {
            dimension = "deployment"
            // Inherits defaults: irc.freeq.at + auth.freeq.at standalone broker.
        }
        create("zerosum") {
            dimension = "deployment"
            applicationIdSuffix = ".zerosum"
            buildConfigField("String", "IRC_SERVER", "\"irc.zerosum.org:6667\"")
            // Embedded broker on the IRC server itself (no standalone /auth).
            buildConfigField("String", "AUTH_BROKER_BASE", "\"https://irc.zerosum.org\"")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }
    composeOptions {
        kotlinCompilerExtensionVersion = "1.5.8"
    }
}

dependencies {
    // Compose BOM
    val composeBom = platform("androidx.compose:compose-bom:2024.02.00")
    implementation(composeBom)

    // Core
    implementation("androidx.core:core-ktx:1.12.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.7.0")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.7.0")
    implementation("androidx.activity:activity-compose:1.8.2")

    // Compose UI
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.foundation:foundation")

    // Material 3
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")

    // Navigation
    implementation("androidx.navigation:navigation-compose:2.7.7")

    // Image loading
    implementation("io.coil-kt:coil-compose:2.5.0")

    // Browser (Chrome Custom Tabs for OAuth)
    implementation("androidx.browser:browser:1.7.0")

    // Security (EncryptedSharedPreferences)
    implementation("androidx.security:security-crypto:1.1.0-alpha06")

    // Emoji picker
    implementation("androidx.emoji2:emoji2-emojipicker:1.5.0")

    // JNA (required by UniFFI-generated Kotlin bindings)
    implementation("net.java.dev.jna:jna:5.13.0@aar")

    // Debug
    debugImplementation("androidx.compose.ui:ui-tooling")

    // Unit tests (pure JVM, plain JUnit — no Robolectric on aarch64 Linux).
    testImplementation("junit:junit:4.13.2")
    // android.jar stubs org.json to throw "not mocked"; this supplies a real
    // implementation to the host JVM so JSON code paths are testable.
    testImplementation("org.json:json:20240303")

    // Instrumented tests (run on a device/emulator).
    androidTestImplementation("androidx.test.ext:junit:1.1.5")
    androidTestImplementation("androidx.test:runner:1.5.2")
    androidTestImplementation("androidx.test:rules:1.5.0")
    androidTestImplementation("com.squareup.okhttp3:mockwebserver:4.12.0")
}
