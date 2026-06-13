package io.github.nitanmarcel.jdex.project

import java.io.File
import java.security.MessageDigest
import java.sql.Connection
import java.sql.DriverManager

class Project private constructor(val file: File, private val connection: Connection) : AutoCloseable, CommentStore, BookmarkStore, RenameStore, DexStore {

    override fun importedDexes(): List<StoredDex> {
        val list = mutableListOf<StoredDex>()
        connection.createStatement().use { st ->
            st.executeQuery("SELECT sha, name, bytes FROM imported_dex").use { rs ->
                while (rs.next()) list.add(StoredDex(rs.getString(1), rs.getString(2), rs.getBytes(3)))
            }
        }
        return list
    }

    override fun patch(sha: String): DexPatch? =
        connection.prepareStatement("SELECT patch FROM dex_patch WHERE source_sha = ?").use {
            it.setString(1, sha)
            it.executeQuery().use { rs -> if (rs.next()) DexPatch.deserialize(rs.getBytes(1)) else null }
        }

    override fun savePatch(sha: String, patch: DexPatch) {
        connection.prepareStatement("INSERT OR REPLACE INTO dex_patch(source_sha, patch) VALUES(?, ?)").use {
            it.setString(1, sha)
            it.setBytes(2, patch.serialize())
            it.executeUpdate()
        }
        save()
    }

    override fun saveImported(sha: String, name: String, bytes: ByteArray) {
        connection.prepareStatement("INSERT OR REPLACE INTO imported_dex(sha, name, bytes) VALUES(?, ?, ?)").use {
            it.setString(1, sha)
            it.setString(2, name)
            it.setBytes(3, bytes)
            it.executeUpdate()
        }
        save()
    }

    override fun renames(): Map<String, String> {
        val map = LinkedHashMap<String, String>()
        connection.createStatement().use { st ->
            st.executeQuery("SELECT key, name FROM rename").use { rs ->
                while (rs.next()) map[rs.getString(1)] = rs.getString(2)
            }
        }
        return map
    }

    override fun setRename(key: String, name: String?) {
        if (name.isNullOrBlank()) {
            connection.prepareStatement("DELETE FROM rename WHERE key = ?").use { it.setString(1, key); it.executeUpdate() }
        } else {
            connection.prepareStatement("INSERT OR REPLACE INTO rename(key, name) VALUES(?, ?)").use {
                it.setString(1, key)
                it.setString(2, name)
                it.executeUpdate()
            }
        }
        save()
    }

    override fun toggle(line: Int): Boolean {
        val exists = connection.prepareStatement("SELECT 1 FROM bookmark WHERE line = ?").use {
            it.setInt(1, line)
            it.executeQuery().use { rs -> rs.next() }
        }
        if (exists) {
            connection.prepareStatement("DELETE FROM bookmark WHERE line = ?").use { it.setInt(1, line); it.executeUpdate() }
        } else {
            connection.prepareStatement("INSERT INTO bookmark(line) VALUES(?)").use { it.setInt(1, line); it.executeUpdate() }
        }
        return !exists
    }

    override fun bookmarks(): Set<Int> {
        val set = LinkedHashSet<Int>()
        connection.createStatement().use { st ->
            st.executeQuery("SELECT line FROM bookmark").use { rs -> while (rs.next()) set.add(rs.getInt(1)) }
        }
        return set
    }

    override fun get(key: String): String? =
        connection.prepareStatement("SELECT text FROM comment WHERE anchor = ?").use {
            it.setString(1, key)
            it.executeQuery().use { rs -> if (rs.next()) rs.getString(1) else null }
        }

    override fun set(key: String, text: String?) {
        if (text.isNullOrBlank()) {
            connection.prepareStatement("DELETE FROM comment WHERE anchor = ?").use { it.setString(1, key); it.executeUpdate() }
        } else {
            connection.prepareStatement("INSERT OR REPLACE INTO comment(anchor, text) VALUES(?, ?)").use {
                it.setString(1, key)
                it.setString(2, text)
                it.executeUpdate()
            }
        }
    }

    override fun all(): Map<String, String> {
        val map = LinkedHashMap<String, String>()
        connection.createStatement().use { st ->
            st.executeQuery("SELECT anchor, text FROM comment").use { rs ->
                while (rs.next()) map[rs.getString(1)] = rs.getString(2)
            }
        }
        return map
    }

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
                if (version < 2) {
                    statement.executeUpdate("CREATE TABLE comment(offset INTEGER PRIMARY KEY, text TEXT NOT NULL)")
                    statement.executeUpdate("PRAGMA user_version = 2")
                }
                if (version < 3) {
                    statement.executeUpdate("CREATE TABLE comment_v3(anchor TEXT PRIMARY KEY, text TEXT NOT NULL)")
                    statement.executeUpdate("INSERT INTO comment_v3(anchor, text) SELECT 'i:' || printf('%08x', offset), text FROM comment")
                    statement.executeUpdate("DROP TABLE comment")
                    statement.executeUpdate("ALTER TABLE comment_v3 RENAME TO comment")
                    statement.executeUpdate("PRAGMA user_version = 3")
                }
                if (version < 4) {
                    statement.executeUpdate("CREATE TABLE bookmark(line INTEGER PRIMARY KEY)")
                    statement.executeUpdate("PRAGMA user_version = 4")
                }
                if (version < 5) {
                    statement.executeUpdate("CREATE TABLE rename(key TEXT PRIMARY KEY, name TEXT NOT NULL)")
                    statement.executeUpdate("PRAGMA user_version = 5")
                }
                if (version < 6) {
                    statement.executeUpdate("CREATE TABLE imported_dex(sha TEXT PRIMARY KEY, name TEXT NOT NULL, bytes BLOB NOT NULL)")
                    statement.executeUpdate("CREATE TABLE dex_patch(source_sha TEXT PRIMARY KEY, patch BLOB NOT NULL)")
                    statement.executeUpdate("PRAGMA user_version = 6")
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
