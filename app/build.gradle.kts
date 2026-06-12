plugins {
    alias(libs.plugins.kotlin.jvm)
    application
    alias(libs.plugins.shadow)
}

repositories {
    mavenCentral()
}

dependencies {
    implementation(libs.flatlaf)
    implementation(libs.flatlaf.extras)
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
    mainClass = "org.example.AppKt"
}

tasks.named<Test>("test") {
    useJUnitPlatform()
}

tasks.shadowJar {
    archiveBaseName = "jdex"
    archiveClassifier = ""
    archiveVersion = ""
}
