import org.jetbrains.kotlin.gradle.tasks.KotlinCompile
import java.util.Properties

plugins {
    kotlin("jvm") version "1.9.21"
    id("com.github.ben-manes.versions") version "0.50.0"
}

group = "com.martmists"
version = "1.0.0"

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


val main by sourceSets.getting {
    java.srcDirs(
        "ghidra_scripts",
    )
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
            "*.cia",
            "exefs/",
            "romfs/",
        )
    }

    withType<JavaCompile> {
        sourceCompatibility = JavaVersion.VERSION_1_8.toString()
        targetCompatibility = JavaVersion.VERSION_1_8.toString()
    }

    withType<KotlinCompile> {
        kotlinOptions {
            jvmTarget = JavaVersion.VERSION_1_8.toString()
            freeCompilerArgs = listOf(
                "-opt-in=kotlin.contracts.ExperimentalContracts"
            )
        }
    }
}
