plugins {
    kotlin("jvm") version "2.2.0"
}

group = "ro.roro"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    testImplementation(kotlin("test"))

    implementation("org.bouncycastle:bcpkix-jdk18on:1.79")
    implementation("org.bouncycastle:bcprov-jdk18on:1.79")
}

tasks.test {
    useJUnitPlatform()
}