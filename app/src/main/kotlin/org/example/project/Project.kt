package org.example.project

import java.io.File
import java.security.MessageDigest
import java.sql.Connection
import java.sql.DriverManager

class Project private constructor(val file: File, private val connection: Connection) : AutoCloseable {

    fun setInput(input: File) {
        connection.prepareStatement("INSERT OR REPLACE INTO input(id, path, sha256) VALUES(1, ?, ?)").use {
            it.setString(1, input.absolutePath)
            it.setString(2, sha256(input))
            it.executeUpdate()
        }
    }

    fun input(): File? =
        connection.createStatement().use { statement ->
            statement.executeQuery("SELECT path FROM input WHERE id = 1").use {
                if (it.next()) File(it.getString(1)) else null
            }
        }

    fun save() = connection.commit()

    override fun close() {
        save()
        connection.close()
    }

    companion object {
        const val EXTENSION = "jdexproj"

        fun open(file: File): Project {
            val connection = DriverManager.getConnection("jdbc:sqlite:${file.absolutePath}")
            migrate(connection)
            connection.autoCommit = false
            return Project(file, connection)
        }

        fun forInput(input: File): Project =
            open(input.resolveSibling("${input.nameWithoutExtension}.$EXTENSION")).apply {
                setInput(input)
            }

        private fun migrate(connection: Connection) {
            connection.createStatement().use { statement ->
                val version = statement.executeQuery("PRAGMA user_version").use { it.getInt(1) }
                if (version < 1) {
                    statement.executeUpdate(
                        "CREATE TABLE input(id INTEGER PRIMARY KEY CHECK (id = 1), path TEXT NOT NULL, sha256 TEXT NOT NULL)"
                    )
                    statement.executeUpdate("PRAGMA user_version = 1")
                }
            }
        }

        private fun sha256(file: File): String {
            val digest = MessageDigest.getInstance("SHA-256")
            file.inputStream().use { input ->
                val buffer = ByteArray(64 * 1024)
                while (true) {
                    val read = input.read(buffer)
                    if (read < 0) break
                    digest.update(buffer, 0, read)
                }
            }
            return digest.digest().joinToString("") { "%02x".format(it) }
        }
    }
}
