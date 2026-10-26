package io.syn443.android.chat

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import org.json.JSONObject
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Single UI-process writer, ciphertext-only SQLite under noBackupFilesDir. */
class ChatOutbox(context:Context,private val generation:Long,private val namespace:String="support-chat"):AutoCloseable {
    companion object {
        fun erase(context:Context,namespace:String="support-chat") {
            require(namespace=="support-chat" || namespace.matches(Regex("test-[a-z0-9-]{1,40}")))
            try {
                val file=File(context.noBackupFilesDir,"$namespace.db")
                if(file.exists())SQLiteDatabase.openDatabase(file.path,null,SQLiteDatabase.OPEN_READWRITE).use {db->
                    db.beginTransaction();try {db.execSQL("DELETE FROM chunks");db.execSQL("DELETE FROM files");db.execSQL("DELETE FROM drafts");db.setTransactionSuccessful()} finally {db.endTransaction()}
                }
            } finally {
                val keys=KeyStore.getInstance("AndroidKeyStore").apply {load(null)}
                keys.aliases().toList().filter {it.startsWith("syn443-chat-$namespace-")}.forEach(keys::deleteEntry)
            }
        }
    }
    private val helper=object:SQLiteOpenHelper(context,File(context.noBackupFilesDir,"$namespace.db").path,null,1) {
        override fun onConfigure(db:SQLiteDatabase) {db.setForeignKeyConstraintsEnabled(true)}
        override fun onCreate(db:SQLiteDatabase) {
            db.execSQL("CREATE TABLE drafts(id TEXT PRIMARY KEY,generation INTEGER NOT NULL,body BLOB NOT NULL)")
            db.execSQL("CREATE TABLE files(id TEXT PRIMARY KEY,generation INTEGER NOT NULL,size INTEGER NOT NULL,body BLOB NOT NULL)")
            db.execSQL("CREATE TABLE chunks(file TEXT REFERENCES files(id) ON DELETE CASCADE,part INTEGER,data BLOB NOT NULL,PRIMARY KEY(file,part))")
        }
        override fun onUpgrade(db:SQLiteDatabase,old:Int,new:Int) {error("chat_schema_version")}
    }
    private val db=helper.writableDatabase
    private val alias="syn443-chat-$namespace-$generation"
    private val key:SecretKey
    init {
        require(generation>=0)
        require(namespace=="support-chat" || namespace.matches(Regex("test-[a-z0-9-]{1,40}")))
        // A new login never resumes a previous account's sends. All local contents
        // are ciphertext; deleting old keys also covers SQLite free pages/WAL.
        val keys=KeyStore.getInstance("AndroidKeyStore").apply {load(null)}
        keys.aliases().toList().filter {it.startsWith("syn443-chat-$namespace-") && it!=alias}.forEach(keys::deleteEntry)
        db.delete("drafts","generation<>?",arrayOf(generation.toString()));db.delete("files","generation<>?",arrayOf(generation.toString()))
        key=(keys.getKey(alias,null) as? SecretKey)?:KeyGenerator.getInstance("AES","AndroidKeyStore").apply {
            init(KeyGenParameterSpec.Builder(alias,KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).build())
        }.generateKey()
    }
    private fun crypt(id:String,bytes:ByteArray,decrypt:Boolean=false):ByteArray {
        val c=Cipher.getInstance("AES/GCM/NoPadding")
        if(decrypt) {require(bytes.size>=28);c.init(Cipher.DECRYPT_MODE,key,GCMParameterSpec(128,bytes.copyOfRange(0,12)))}
        else c.init(Cipher.ENCRYPT_MODE,key)
        c.updateAAD("$generation/$id".toByteArray())
        return if(decrypt)c.doFinal(bytes,12,bytes.size-12) else c.iv+c.doFinal(bytes)
    }
    fun saveDraft(id:String,body:JSONObject) {
        require(id.matches(Regex("[0-9a-f]{32}")) && body.toString().toByteArray().size<=32768)
        val count=db.rawQuery("SELECT count(*) FROM drafts",null).use {it.moveToFirst();it.getInt(0)}
        require(count<8 || draft(id)!=null)
        db.insertWithOnConflict("drafts",null,ContentValues().apply {put("id",id);put("generation",generation);put("body",crypt("draft/$id",body.toString().toByteArray()))},SQLiteDatabase.CONFLICT_REPLACE).also {check(it!=-1L)}
    }
    fun draft(id:String):JSONObject?=db.rawQuery("SELECT body FROM drafts WHERE id=? AND generation=?",arrayOf(id,generation.toString())).use {
        if(it.moveToFirst())JSONObject(crypt("draft/$id",it.getBlob(0),true).toString(Charsets.UTF_8)) else null
    }
    fun drafts():List<Pair<String,JSONObject>> = db.rawQuery("SELECT id,body FROM drafts WHERE generation=? ORDER BY rowid",arrayOf(generation.toString())).use {c->
        buildList {while(c.moveToNext()) {val id=c.getString(0);add(id to JSONObject(crypt("draft/$id",c.getBlob(1),true).toString(Charsets.UTF_8)))}}
    }
    fun removeDraft(id:String) {db.delete("drafts","id=? AND generation=?",arrayOf(id,generation.toString()))}
    fun importFile(file:File,name:String,mime:String,kind:String):JSONObject {
        require(file.length() in 1..ChatLimits.file.toLong())
        val used=db.rawQuery("SELECT COALESCE(sum(size),0) FROM files",null).use {it.moveToFirst();it.getLong(0)}
        require(used+file.length()<=100L*1024*1024)
        val id=ChatLimits.id();val hash=java.security.MessageDigest.getInstance("SHA-256")
        file.inputStream().use {input->val buffer=ByteArray(ChatLimits.chunk);while(true) {val n=input.read(buffer);if(n<0)break;hash.update(buffer,0,n)}}
        val info=JSONObject().put("localId",id).put("clientId",id).put("name",name).put("mime",mime).put("kind",kind).put("size",file.length())
            .put("sha256",hash.digest().joinToString("") {"%02x".format(it)})
        db.beginTransaction()
        try {
            check(db.insertOrThrow("files",null,ContentValues().apply {put("id",id);put("generation",generation);put("size",file.length());put("body",crypt("file/$id",info.toString().toByteArray()))})!=-1L)
            file.inputStream().buffered().use {input->var part=0;while(true) {
                val data=ByteArray(ChatLimits.chunk);var n=0
                while(n<data.size) {val count=input.read(data,n,data.size-n);if(count<0)break;n+=count}
                if(n==0)break
                db.insertOrThrow("chunks",null,ContentValues().apply {put("file",id);put("part",part);put("data",crypt("$id/$part",data.copyOf(n)))})
                part++
            }}
            db.setTransactionSuccessful()
        } finally {db.endTransaction()}
        return info
    }
    fun chunk(id:String,part:Int):ByteArray=db.rawQuery("SELECT c.data FROM chunks c JOIN files f ON f.id=c.file WHERE f.id=? AND f.generation=? AND c.part=?",arrayOf(id,generation.toString(),part.toString())).use {
        check(it.moveToFirst());crypt("$id/$part",it.getBlob(0),true)
    }
    fun removeFile(id:String) {db.delete("files","id=? AND generation=?",arrayOf(id,generation.toString()))}
    override fun close() {helper.close()}
}
