import org.jetbrains.kotlin.gradle.tasks.KotlinCompile
import java.util.Properties

plugins {
    kotlin("jvm") version "1.7.10"
    id("com.github.ben-manes.versions") version "0.42.0"
}

group = "com.martmists"
version = "1.0-SNAPSHOT"

val fp = File(projectDir, "gradle-local.properties")
if (fp.exists()) {
    val props = Properties()
    props.load(fp.inputStream())
    for ((k, v) in props) {
        extra[k.toString()] = v.toString()
    }
}

repositories {
    mavenCentral()
}

dependencies {
    implementation(kotlin("reflect"))
}

val ghidraInstallDir = System.getenv("GHIDRA_INSTALL_DIR") ?: project.properties["GHIDRA_INSTALL_DIR"] as? String ?: throw GradleException("GHIDRA_INSTALL_DIR not set")
apply(from = "$ghidraInstallDir/support/buildExtension.gradle")

tasks {
    val buildExtension by getting(Zip::class) {
        exclude(
            ".idea/",
            "gradle/",
            "dist/",
            "*.kts",
            "gradle*.properties",
            "*.cxi",
            "exefs/",
            "romfs/",
        )
    }

    withType<KotlinCompile> {
        kotlinOptions {
            jvmTarget = "1.8"
            freeCompilerArgs = listOf(
                "-opt-in=kotlin.contracts.ExperimentalContracts"
            )
        }
    }
}
