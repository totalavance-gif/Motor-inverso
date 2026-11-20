package com.apkauditor.app.data.db

import androidx.room.Dao
import androidx.room.Database
import androidx.room.Entity
import androidx.room.Insert
import androidx.room.PrimaryKey
import androidx.room.Query
import androidx.room.RoomDatabase
import kotlinx.coroutines.flow.Flow

/** Una auditoría guardada: resumen para el historial + reporte completo en JSON. */
@Entity(tableName = "audits")
data class AuditEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val fileName: String,
    val packageName: String,
    val versionName: String,
    val score: Int,
    val dateMillis: Long,
    val reportJson: String
)

@Dao
interface AuditDao {
    @Insert
    suspend fun insert(audit: AuditEntity): Long

    @Query("SELECT * FROM audits ORDER BY dateMillis DESC")
    fun observeAll(): Flow<List<AuditEntity>>

    @Query("SELECT * FROM audits WHERE id = :id")
    suspend fun getById(id: Long): AuditEntity?

    @Query("DELETE FROM audits WHERE id = :id")
    suspend fun deleteById(id: Long)

    @Query("DELETE FROM audits")
    suspend fun deleteAll()
}

@Database(entities = [AuditEntity::class], version = 1, exportSchema = false)
abstract class AuditDatabase : RoomDatabase() {
    abstract fun auditDao(): AuditDao
}
