package io.syn443.android

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.res.colorResource

@Composable
internal fun Syn443Theme(content: @Composable () -> Unit) {
    val surface = colorResource(R.color.syn443_surface)
    val palette = remember(surface) { darkColorScheme(background = surface, surface = surface) }
    MaterialTheme(colorScheme = palette, content = content)
}
