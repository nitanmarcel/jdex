import java.util.zip.ZipFile

plugins {
    alias(libs.plugins.kotlin.jvm)
    application
    alias(libs.plugins.shadow)
}

repositories {
    mavenCentral()
    google()
}

dependencies {
    implementation(libs.apksig)
    implementation(libs.bined.swing)
    implementation(libs.binary.data)
    implementation(libs.binary.data.array)
    implementation(libs.flatlaf)
    implementation(libs.flatlaf.extras)
    implementation(libs.flatlaf.intellij.themes)
    implementation(libs.graalpy.polyglot)
    implementation(libs.graalpy.language)
    implementation(libs.graalpy.resources)
    implementation(libs.graalpy.truffle.runtime)
    implementation(libs.graalpy.regex)
    implementation(libs.jadx.core)
    implementation(libs.jadx.dex.input)
    implementation(libs.kotlinx.coroutines.swing)
    implementation(libs.miglayout.swing)
    implementation(libs.moderndocking.single.app)
    implementation(libs.moderndocking.ui)
    implementation(libs.rsyntaxtextarea)
    implementation(libs.sqlite.jdbc)

    testImplementation(libs.junit.jupiter)
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(21)
    }
}

application {
    mainClass = "io.github.nitanmarcel.jdex.AppKt"
}

tasks.named<Test>("test") {
    useJUnitPlatform()
}

tasks.shadowJar {
    archiveBaseName = "jdex"
    archiveClassifier = ""
    archiveVersion = ""
    duplicatesStrategy = DuplicatesStrategy.INCLUDE
    mergeServiceFiles()
    val builtJar = archiveFile
    doLast {
        val zip = ZipFile(builtJar.get().asFile)
        val langs = zip.use {
            val e = it.getEntry("META-INF/services/com.oracle.truffle.api.provider.TruffleLanguageProvider")
            it.getInputStream(e).bufferedReader().use { r -> r.readText() }
        }
        listOf("PythonLanguageProvider", "RegexLanguageProvider").forEach {
            check(langs.contains(it)) { "shadowJar dropped $it from the Truffle language registry" }
        }
    }
}
