import org.gradle.process.ExecOperations
import javax.inject.Inject

plugins {
    java
}

abstract class CmakeBuild @Inject constructor(private val exec: ExecOperations) : DefaultTask() {
    @get:Internal abstract val source: DirectoryProperty
    @get:Internal abstract val workDir: DirectoryProperty
    @get:OutputFile abstract val output: RegularFileProperty
    @get:Input abstract val cmake: Property<String>
    @get:Input abstract val libName: Property<String>
    @get:Input abstract val version: Property<String>

    @TaskAction
    fun run() {
        val build = workDir.get().asFile.also { it.mkdirs() }
        val src = source.get().asFile
        check(File(src, "CMakeLists.txt").isFile) { "capstone submodule missing at $src — run: git submodule update --init" }
        exec.exec {
            commandLine(
                cmake.get(), "-S", src.absolutePath, "-B", build.absolutePath,
                "-DCMAKE_BUILD_TYPE=Release", "-DBUILD_SHARED_LIBS=ON",
                "-DCAPSTONE_BUILD_CSTOOL=OFF", "-DCAPSTONE_BUILD_TESTS=OFF",
            )
        }
        exec.exec { commandLine(cmake.get(), "--build", build.absolutePath, "--config", "Release", "-j") }
        val produced = build.walkTopDown()
            .filter { it.isFile && it.name.startsWith(libName.get()) }
            .maxByOrNull { it.length() }
            ?: error("capstone build produced no ${libName.get()} under $build")
        val out = output.get().asFile
        out.parentFile.mkdirs()
        produced.copyTo(out, overwrite = true)
    }
}

fun jnaPlatform(): String {
    val os = System.getProperty("os.name").lowercase()
    val arch = when (val a = System.getProperty("os.arch").lowercase()) {
        "amd64", "x86_64" -> "x86-64"
        "aarch64", "arm64" -> "aarch64"
        "x86", "i386", "i486", "i586", "i686" -> "x86"
        "arm" -> "arm"
        else -> a
    }
    return when {
        os.contains("win") -> "win32-$arch"
        os.contains("mac") || os.contains("darwin") -> "darwin"
        else -> "linux-$arch"
    }
}

fun libFileName(): String {
    val os = System.getProperty("os.name").lowercase()
    return when {
        os.contains("win") -> "capstone.dll"
        os.contains("mac") || os.contains("darwin") -> "libcapstone.dylib"
        else -> "libcapstone.so"
    }
}

val nativesRoot = layout.buildDirectory.dir("natives")

val buildCapstone = tasks.register<CmakeBuild>("buildCapstone") {
    source.set(layout.projectDirectory.dir("capstone"))
    workDir.set(layout.buildDirectory.dir("capstone-cmake"))
    output.set(nativesRoot.map { it.dir(jnaPlatform()).file(libFileName()) })
    cmake.set((project.findProperty("cmake.path") as String?) ?: "cmake")
    libName.set(libFileName())
    version.set("capstone-5.0.1")
}

sourceSets.named("main") { resources.srcDir(nativesRoot) }
tasks.named("processResources") { dependsOn(buildCapstone) }
