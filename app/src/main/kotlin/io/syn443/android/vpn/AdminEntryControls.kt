package io.syn443.android.vpn

import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag

/** The ordinary web grant controls its home shortcut. Explicit separate-account
 * authentication remains available in collapsed account settings and grants no role. */
@Composable internal fun AdminEntryControls(provisioned:Boolean,mainAccess:Boolean,busy:Boolean,onOpen:()->Unit) {
    if(mainAccess)TextButton(enabled=!busy,onClick=onOpen,modifier=Modifier.testTag("auth-admin-panel")) {
        Text("Администрирование")
    }
    if(provisioned) {
        var expanded by rememberSaveable {mutableStateOf(false)}
        TextButton(onClick={expanded=!expanded},modifier=Modifier.testTag("auth-additional-options")) {
            Text("Дополнительные настройки аккаунта")
        }
        if(expanded)TextButton(onClick=onOpen,modifier=Modifier.testTag("auth-separate-admin-login")) {
            Text("Войти как администратор")
        }
    }
}
