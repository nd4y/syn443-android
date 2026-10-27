@file:androidx.annotation.OptIn(androidx.media3.common.util.UnstableApi::class)
package io.syn443.android.chat

import android.content.Context
import android.graphics.Bitmap
import android.graphics.ImageDecoder
import android.media.MediaMetadataRetriever
import android.net.Uri
import android.provider.OpenableColumns
import androidx.media3.common.MediaItem
import androidx.media3.common.MimeTypes
import androidx.media3.common.util.Clock
import androidx.media3.effect.FrameDropEffect
import androidx.media3.effect.Presentation
import androidx.media3.exoplayer.mediacodec.MediaCodecSelector
import androidx.media3.transformer.*
import kotlinx.coroutines.*
import java.io.File
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

data class PreparedMedia(val file:File,val name:String,val mime:String,val kind:String):AutoCloseable {
    override fun close() {file.delete()}
}
object ChatMedia {
    internal val decoderSelector=MediaCodecSelector {mime,secure,tunneling->
        val defaults=MediaCodecSelector.DEFAULT.getDecoderInfos(mime,secure,tunneling)
        // API37's emulator H264 decoder fails while draining real 1080p input.
        // Keep the device's normal hardware order; exclude only that exact
        // virtual codec, letting Media3 use the remaining platform decoder.
        if(android.os.Build.VERSION.SDK_INT>=37)
            defaults.filterNot {it.name=="c2.goldfish.h264.decoder"}
        else defaults
    }
    private fun safeName(value:String)=value.filter { !it.isISOControl() && it!='/' && it!='\\' && Character.getType(it)!=Character.FORMAT.toInt() }
        .take(60).trim().takeUnless {it.isEmpty() || it=="." || it==".."}?:"attachment"
    suspend fun prepare(context:Context,uri:Uri,compress:Boolean,progress:(String)->Unit):PreparedMedia {
        require(uri.scheme=="content")
        val raw=File(context.cacheDir,"chat-${ChatLimits.id()}.input")
        val output=File(context.cacheDir,"chat-${ChatLimits.id()}.output")
        try {
            val metadata=withContext(Dispatchers.IO) {
                val name=context.contentResolver.query(uri,arrayOf(OpenableColumns.DISPLAY_NAME),null,null,null)?.use {if(it.moveToFirst())it.getString(0) else null}?:"attachment"
                val mime=context.contentResolver.getType(uri)?:"application/octet-stream"
                context.contentResolver.openInputStream(uri).use {input->
                    requireNotNull(input);raw.outputStream().use {out->
                        val buf=ByteArray(65536);var total=0L
                        while(true) {ensureActive();val n=input.read(buf);if(n<0)break;total+=n
                            require(total<=if(compress)512L*1024*1024 else ChatLimits.file.toLong());out.write(buf,0,n)}
                        require(total>0)
                    }
                }
                safeName(name) to mime
            }
            val (name,mime)=metadata
            if(!compress)return PreparedMedia(raw,name,when(mime) {
                "application/pdf","application/zip","text/plain","image/jpeg","image/png","image/webp","video/mp4"->mime
                else->"application/octet-stream"
            },"file")
            if(mime.startsWith("image/")) {
                progress("Сжатие фотографии")
                withContext(Dispatchers.IO) {
                    val bitmap=ImageDecoder.decodeBitmap(ImageDecoder.createSource(raw)) {decoder,info,_->
                        val w=info.size.width;val h=info.size.height
                        require(w in 1..32768 && h in 1..32768 && w.toLong()*h<=64_000_000)
                        val scale=minOf(1.0,1600.0/maxOf(w,h))
                        decoder.setTargetSize(maxOf(1,(w*scale).toInt()),maxOf(1,(h*scale).toInt()))
                        decoder.allocator=ImageDecoder.ALLOCATOR_SOFTWARE
                        decoder.setTargetColorSpace(android.graphics.ColorSpace.get(android.graphics.ColorSpace.Named.SRGB))
                    }
                    try {output.outputStream().use {check(bitmap.compress(Bitmap.CompressFormat.JPEG,85,it))}}
                    finally {bitmap.recycle()}
                }
                require(output.length() in 1..ChatLimits.file.toLong())
                return PreparedMedia(output,name.substringBeforeLast('.',name)+".jpg","image/jpeg","photo")
            }
            require(mime.startsWith("video/"))
            val duration=withContext(Dispatchers.IO) {
                MediaMetadataRetriever().use {it.setDataSource(raw.path);requireNotNull(it.extractMetadata(MediaMetadataRetriever.METADATA_KEY_DURATION)?.toLongOrNull())}
            }
            require(duration in 1..900_000)
            // Leave room for MP4 overhead and AAC, then check the actual output.
            val bitrate=(ChatLimits.file.toLong()*8*900/duration-96_000).coerceAtMost(2_000_000).toInt()
            require(bitrate>=160_000)
            progress("Сжатие видео на устройстве")
            withContext(Dispatchers.Main.immediate) {withTimeout(300_000) {
                var transformer:Transformer?=null
                var monitor:Job?=null
                try {
                    suspendCancellableCoroutine<Unit> {cont->
                        val encoder=DefaultEncoderFactory.Builder(context)
                            .setRequestedVideoEncoderSettings(VideoEncoderSettings.Builder().setBitrate(bitrate).build())
                            .setRequestedAudioEncoderSettings(AudioEncoderSettings.Builder().setBitrate(96_000).build()).build()
                        transformer=Transformer.Builder(context).setEncoderFactory(encoder)
                            .setAssetLoaderFactory(DefaultAssetLoaderFactory(context,
                                DefaultDecoderFactory.Builder(context).setMediaCodecSelector(decoderSelector)
                                    .setEnableDecoderFallback(true).build(),Clock.DEFAULT,null))
                            .setVideoMimeType(MimeTypes.VIDEO_H264).setAudioMimeType(MimeTypes.AUDIO_AAC)
                            .addListener(object:Transformer.Listener {
                                override fun onCompleted(composition:Composition,result:ExportResult) {if(cont.isActive)cont.resume(Unit)}
                                override fun onError(composition:Composition,result:ExportResult,error:ExportException) {
                                    if(cont.isActive)cont.resumeWithException(ChatFailure("MEDIA_UNSUPPORTED").apply {
                                        // The UI keeps a fixed message; synthetic instrumentation
                                        // retains the codec cause instead of losing its failure stage.
                                        if(io.syn443.android.BuildConfig.DEBUG)initCause(error)
                                    })
                                }
                            }).build()
                        val edited=EditedMediaItem.Builder(MediaItem.fromUri(Uri.fromFile(raw)))
                            .setEffects(Effects(emptyList(),listOf(Presentation.createForWidthAndHeight(1280,720,Presentation.LAYOUT_SCALE_TO_FIT),FrameDropEffect.createDefaultFrameDropEffect(30f)))).build()
                        val activeTransformer=requireNotNull(transformer)
                        activeTransformer.start(edited,output.path)
                        progress("Сжатие видео: 0%")
                        monitor=launch {
                            val holder=ProgressHolder()
                            while(isActive) {
                                delay(250)
                                if(activeTransformer.getProgress(holder)==Transformer.PROGRESS_STATE_AVAILABLE)
                                    progress("Сжатие видео: ${holder.progress}%")
                            }
                        }
                    }
                } finally {monitor?.cancel();transformer?.cancel()}
            }}
            require(output.length() in 1..ChatLimits.file.toLong())
            return PreparedMedia(output,name.substringBeforeLast('.',name)+".mp4","video/mp4","video")
        } catch(e:Exception) {output.delete();raw.delete();throw e}
        finally {if(output.exists())raw.delete()}
    }
}
