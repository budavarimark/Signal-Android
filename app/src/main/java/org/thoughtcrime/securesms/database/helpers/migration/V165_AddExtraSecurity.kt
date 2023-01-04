package org.thoughtcrime.securesms.database.helpers.migration

import android.app.Application
import androidx.sqlite.db.SupportSQLiteDatabase
import net.zetetic.database.sqlcipher.SQLiteDatabase

/**
 * Add columns needed to track remote megaphone specific snooze rates.
 */
object V165_AddExtraSecurity : SignalDatabaseMigration {
  override fun migrate(context: Application, db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
    /*
    "extra_secure INTEGER DEFAULT 0, " +
    "extra_secure_key TEXT DEFAULT NULL, " +
     */

    if (columnMissing(db, "extra_secure")) {
      // db.execSQL("ALTER TABLE recipient ADD COLUMN extra_secure TEXT DEFAULT NULL")
      db.execSQL("ALTER TABLE recipient ADD COLUMN extra_secure INTEGER DEFAULT 0")
    }
    if (columnMissing(db, "extra_secure_key")) {
      db.execSQL("ALTER TABLE recipient ADD COLUMN extra_secure_key TEXT DEFAULT ''")
    }

  }

  private fun columnMissing(db: SupportSQLiteDatabase, column: String): Boolean {
    db.query("PRAGMA table_info(recipient)", null).use { cursor ->
      val nameColumnIndex = cursor.getColumnIndexOrThrow("name")
      while (cursor.moveToNext()) {
        val name = cursor.getString(nameColumnIndex)
        if (name == column) {
          return false
        }
      }
    }
    return true
  }
}
