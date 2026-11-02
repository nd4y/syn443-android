package io.syn443.android

import android.content.Intent
import android.graphics.ImageDecoder
import android.net.Uri
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.core.content.FileProvider
import com.google.zxing.*
import com.google.zxing.common.HybridBinarizer
import io.syn443.identity.BootstrapTrust
import kotlinx.coroutines.*
import org.json.JSONObject
import java.io.File
import java.util.UUID

// Separate provider identity keeps camera paths independent of debug chat fixtures.
class EnrollmentFileProvider:FileProvider()

/** Incoming content is preview-only. No key/code leaves this device before the
 * explicit binding confirmation and installation-root verification. */
class EnrollmentActivity:ComponentActivity() {
    override fun onCreate(savedInstanceState:Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        val incoming=intent.dataString?.takeIf {it.length<=BootstrapTrust.MAX_LINK}.orEmpty()
        intent=Intent(this,EnrollmentActivity::class.java) // Do not retain a secret in the Activity intent.
        setContent {MaterialTheme(colorScheme=darkColorScheme()){Surface(Modifier.fillMaxSize()){EnrollmentScreen(incoming){browser->
            startActivity(Intent(this,MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_REORDER_TO_FRONT));
            if(browser!=null)startActivity(Intent(Intent.ACTION_VIEW,Uri.parse(browser)).addCategory(Intent.CATEGORY_BROWSABLE))
            finish()
        }}}}
    }
}

internal object InvitationQr {
    fun decode(context:android.content.Context,uri:Uri):String {
        require(uri.scheme=="content")
        val bytes=context.contentResolver.openInputStream(uri).use {input->
            requireNotNull(input);val output=java.io.ByteArrayOutputStream();val buffer=ByteArray(16384)
            while(true){val count=input.read(buffer);if(count<0)break;require(output.size()+count<=16*1024*1024);output.write(buffer,0,count)}
            output.toByteArray()
        }
        val bitmap=ImageDecoder.decodeBitmap(ImageDecoder.createSource(java.nio.ByteBuffer.wrap(bytes))){decoder,info,_->
            val width=info.size.width;val height=info.size.height
            require(width in 1..16384 && height in 1..16384 && width.toLong()*height<=32_000_000)
            val scale=maxOf(width,height).toDouble()/2048
            if(scale>1)decoder.setTargetSize((width/scale).toInt().coerceAtLeast(1),(height/scale).toInt().coerceAtLeast(1))
            decoder.allocator=ImageDecoder.ALLOCATOR_SOFTWARE
        }
        return try {
            val pixels=IntArray(bitmap.width*bitmap.height);bitmap.getPixels(pixels,0,bitmap.width,0,0,bitmap.width,bitmap.height)
            val source=RGBLuminanceSource(bitmap.width,bitmap.height,pixels)
            val hints=mapOf(DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE),DecodeHintType.TRY_HARDER to true)
            val reader=MultiFormatReader()
            val result=runCatching {reader.decode(BinaryBitmap(HybridBinarizer(source)),hints)}.getOrElse {
                reader.reset();reader.decode(BinaryBitmap(HybridBinarizer(source.invert())),hints)
            }
            result.text.also {require(it.length<=BootstrapTrust.MAX_LINK);BootstrapTrust.parse(it)}
        } finally {bitmap.recycle();bytes.fill(0)}
    }
}

@Composable private fun EnrollmentScreen(initial:String,onStarted:(String?)->Unit) {
    val context=LocalContext.current;val scope=rememberCoroutineScope();val endpoint=Uri.parse("content://io.syn443.control")
    var link by remember {mutableStateOf(initial)};var message by remember {mutableStateOf("")}
    var ticket by remember {mutableStateOf("")};var preview by remember {mutableStateOf<JSONObject?>(null)}
    var busy by remember {mutableStateOf(false)};var rotation by remember {mutableStateOf("")};var showRotation by remember {mutableStateOf(false)}
    val cameraFile=remember {File(File(context.cacheDir,"enrollment-camera").apply {mkdirs()},"frame.jpg")}
    suspend fun command(method:String,arg:String?=null,extras:Bundle?=null)=withContext(Dispatchers.IO){context.contentResolver.call(endpoint,method,arg,extras)}
    fun decode(uri:Uri) {scope.launch {
        busy=true;preview=null
        try {link=withContext(Dispatchers.Default){InvitationQr.decode(context,uri)};message="QR прочитан. Проверьте приглашение."}
        catch(_:Exception){message="Не удалось прочитать приглашение из QR."}
        finally {busy=false;cameraFile.delete()}
    }}
    val image=rememberLauncherForActivityResult(ActivityResultContracts.GetContent()){uri->if(uri!=null)decode(uri)}
    val camera=rememberLauncherForActivityResult(ActivityResultContracts.TakePicture()){success->
        if(success)decode(FileProvider.getUriForFile(context,"io.syn443.android.enrollment.files",cameraFile))else cameraFile.delete()
    }
    LaunchedEffect(ticket) {
        if(ticket.isNotEmpty())repeat(100){
            val result=runCatching {JSONObject(command("auth-invite-result",ticket)?.getString("json")?:"{}")}.getOrNull()
            when(result?.optString("state")){
                "verified"->{preview=result;busy=false;return@LaunchedEffect}
                "gone","rejected"->{message="Приглашение отклонено или истекло. Проверьте ссылку и текущую сессию.";busy=false;return@LaunchedEffect}
            };delay(100)
        }
        if(busy){busy=false;message="Проверка не завершена. Повторите попытку."}
    }
    Column(Modifier.fillMaxSize().safeDrawingPadding().verticalScroll(rememberScrollState()).padding(24.dp),verticalArrangement=Arrangement.spacedBy(12.dp)) {
        Text("Привязка SYN443",style=MaterialTheme.typography.headlineMedium)
        Text("Проверьте сервис, затем выберите вход через Keycloak или ручную привязку с подтверждением администратора.")
        OutlinedTextField(value=link,onValueChange={if(it.length<=BootstrapTrust.MAX_LINK){link=it;preview=null}},label={Text("Ссылка syn443://")},
            visualTransformation=PasswordVisualTransformation(),keyboardOptions=KeyboardOptions(keyboardType=KeyboardType.Password,autoCorrectEnabled=false),modifier=Modifier.fillMaxWidth().testTag("invite-link"),enabled=!busy,maxLines=3)
        Row(horizontalArrangement=Arrangement.spacedBy(8.dp)) {
            Button(enabled=!busy,onClick={runCatching {image.launch("image/*")}.onFailure {message="Не удалось открыть выбор изображения."}},modifier=Modifier.testTag("invite-image")){Text("QR из фото")}
            Button(enabled=!busy,onClick={runCatching {camera.launch(FileProvider.getUriForFile(context,"io.syn443.android.enrollment.files",cameraFile))}.onFailure {message="Приложение камеры недоступно."}},modifier=Modifier.testTag("invite-camera")){Text("Камера")}
        }
        Button(enabled=!busy && link.isNotBlank(),onClick={scope.launch {
            busy=true;message="";preview=null
            val id=UUID.randomUUID().toString().replace("-","")
            val result=runCatching {command("auth-invite-preview",id,Bundle().apply {putString("link",link)})}.getOrNull()
            if(result?.getBoolean("admitted")==true)ticket=id else {busy=false;message="Завершите текущую сессию или дождитесь операции."}
        }},modifier=Modifier.testTag("invite-preview")){Text(if(busy)"Проверка…" else "Проверить приглашение")}
        preview?.let {verified->
            Text("Сервис: "+verified.optString("serviceId"),Modifier.testTag("invite-service"))
            Text("Сервер: "+verified.optString("origin"))
            Text("Подпись сервиса проверена установленным корнем доверия. Код ещё не отправлен.")
            Button(enabled=!busy,onClick={scope.launch {
                busy=true
                val result=runCatching {command("auth-invite-start",ticket)}.getOrNull()
                if(result?.getBoolean("ok")==true){link="";onStarted(null)}else {busy=false;message="Не удалось начать привязку. Проверьте, что VPN остановлен."}
            }},modifier=Modifier.testTag("invite-confirm")){Text("Привязать это устройство")}
        }
        if(preview!=null)OutlinedButton(enabled=!busy,onClick={scope.launch {
            busy=true
            try {
                check(command("auth-service-start",ticket)?.getBoolean("ok")==true)
                var browser:String?=null
                withTimeout(15_000){while(browser==null){
                    val status=JSONObject(command("auth-status")?.getString("json")?:"{}")
                    if(status.optBoolean("browserReady"))browser=command("auth-browser",status.optLong("generation",-1).toString())?.getString("url")
                    else if(!status.optBoolean("busy"))error("browser preparation failed")
                    if(browser==null)delay(100)
                }}
                link="";onStarted(checkNotNull(browser))
            }catch(_:Exception){busy=false;message="Не удалось открыть вход. Проверьте статус сессии на главном экране."}
        }},modifier=Modifier.testTag("service-keycloak")){Text("Войти в сервис через Keycloak")}
        if(message.isNotEmpty())Text(message,Modifier.testTag("invite-message"))
        TextButton(onClick={showRotation=!showRotation}){Text("Смена корня доверия")}
        if(showRotation){
            Text("Только сертификат перехода с подписями прежнего и нового корня. Новый ключ из ссылки сам по себе не принимается.")
            OutlinedTextField(rotation,{if(it.length<=16384)rotation=it},label={Text("Сертификат перехода")},modifier=Modifier.fillMaxWidth())
            Button(enabled=!busy && rotation.isNotBlank(),onClick={scope.launch {
                val result=runCatching {command("auth-trust-rotation",rotation)}.getOrNull()
                message=if(result?.getBoolean("ok")==true)"Проверка сертификата запущена. Результат появится в статусе входа." else "Не удалось принять сертификат."
                rotation=""
            }}){Text("Проверить переход")}
        }
    }
}
