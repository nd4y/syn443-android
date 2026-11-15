package io.syn443.android

import android.graphics.Bitmap
import android.net.Uri
import androidx.core.content.FileProvider
import androidx.test.platform.app.InstrumentationRegistry
import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter
import io.syn443.identity.Identity
import org.junit.Assert.*
import org.junit.Test
import java.io.File

class EnrollmentQrTest {
    @Test fun qrImageReturnsOnlyASyntacticallyBoundedInvitation(){
        val context=InstrumentationRegistry.getInstrumentation().targetContext
        val directory=File(context.cacheDir,"enrollment-camera").apply {mkdirs()}
        val file=File(directory,"qr-test.png")
        val code=Identity.random()
        val link="syn443://enroll/v1?service=service-a&origin=https%3A%2F%2Fapi.example.invalid&code=$code&bootstrap=x.y.z"
        val matrix=QRCodeWriter().encode(link,BarcodeFormat.QR_CODE,1024,1024)
        val pixels=IntArray(matrix.width*matrix.height){i->if(matrix[i%matrix.width,i/matrix.width])android.graphics.Color.BLACK else android.graphics.Color.WHITE}
        val bitmap=Bitmap.createBitmap(pixels,matrix.width,matrix.height,Bitmap.Config.ARGB_8888)
        try {
            file.outputStream().use {assertTrue(bitmap.compress(Bitmap.CompressFormat.PNG,100,it))}
            val uri=FileProvider.getUriForFile(context,"io.syn443.android.enrollment.files",file)
            assertEquals(link,InvitationQr.decode(context,uri))
            file.writeBytes(byteArrayOf(1,2,3));try {InvitationQr.decode(context,uri);fail("invalid image decoded")}catch(_:Exception){}
            try {InvitationQr.decode(context,Uri.parse("https://api.example.invalid/qr"));fail("remote image accepted")}catch(_:IllegalArgumentException){}
        }finally{bitmap.recycle();file.delete()}
    }
}
