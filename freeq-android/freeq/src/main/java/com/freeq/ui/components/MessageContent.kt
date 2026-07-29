package com.freeq.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Favorite
import androidx.compose.material.icons.filled.Link
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Repeat
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import coil.compose.AsyncImage
import coil.compose.SubcomposeAsyncImage
import com.freeq.model.Jumbomoji
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.net.URI
import java.net.URL
import java.net.URLEncoder

private val IMAGE_PATTERN = Regex(
    """https?://\S+\.(?:png|jpg|jpeg|gif|webp)(?:\?\S*)?""",
    RegexOption.IGNORE_CASE
)
private val CDN_PATTERN = Regex(
    """https?://cdn\.bsky\.app/img/[^\s<]+""",
    RegexOption.IGNORE_CASE
)
private val YOUTUBE_PATTERN = Regex(
    """(?:youtube\.com/watch\?v=|youtu\.be/)([a-zA-Z0-9_-]{11})"""
)
private val BSKY_POST_PATTERN = Regex(
    """https?://bsky\.app/profile/([^/]+)/post/([a-zA-Z0-9]+)"""
)
private val URL_PATTERN = Regex(
    """https?://\S+"""
)
internal val EMOJI_SHORTCODE = Regex(""":([a-zA-Z0-9_+-]+):""")
internal val EMOJI_MAP = mapOf(
    "smile" to "😊", "grin" to "😁", "laugh" to "😂", "joy" to "😂",
    "rofl" to "🤣", "wink" to "😉", "blush" to "😊", "heart_eyes" to "😍",
    "kissing_heart" to "😘", "thinking" to "🤔", "shushing" to "🤫",
    "raised_eyebrow" to "🤨", "neutral" to "😐", "expressionless" to "😑",
    "unamused" to "😒", "rolling_eyes" to "🙄", "grimace" to "😬",
    "relieved" to "😌", "pensive" to "😔", "sleepy" to "😴",
    "drool" to "🤤", "yum" to "😋", "stuck_out_tongue" to "😛",
    "sunglasses" to "😎", "nerd" to "🤓", "confused" to "😕",
    "worried" to "😟", "frown" to "☹️", "open_mouth" to "😮",
    "hushed" to "😯", "astonished" to "😲", "flushed" to "😳",
    "scream" to "😱", "fearful" to "😨", "cold_sweat" to "😰",
    "cry" to "😢", "sob" to "😭", "angry" to "😠", "rage" to "🤬",
    "swear" to "🤬", "skull" to "💀", "poop" to "💩",
    "clown" to "🤡", "ghost" to "👻", "alien" to "👽",
    "robot" to "🤖", "wave" to "👋", "ok_hand" to "👌",
    "pinch" to "🤏", "v" to "✌️", "crossed_fingers" to "🤞",
    "love_you" to "🤟", "metal" to "🤘", "point_left" to "👈",
    "point_right" to "👉", "point_up" to "👆", "point_down" to "👇",
    "middle_finger" to "🖕", "thumbsup" to "👍", "thumbup" to "👍",
    "+1" to "👍", "thumbsdown" to "👎", "thumbdown" to "👎",
    "-1" to "👎", "fist" to "✊", "punch" to "👊",
    "clap" to "👏", "raised_hands" to "🙌", "pray" to "🙏",
    "handshake" to "🤝", "muscle" to "💪", "flex" to "💪",
    "heart" to "❤️", "red_heart" to "❤️", "orange_heart" to "🧡",
    "yellow_heart" to "💛", "green_heart" to "💚", "blue_heart" to "💙",
    "purple_heart" to "💜", "black_heart" to "🖤", "white_heart" to "🤍",
    "broken_heart" to "💔", "fire" to "🔥", "flame" to "🔥",
    "100" to "💯", "star" to "⭐", "sparkles" to "✨",
    "boom" to "💥", "collision" to "💥", "zap" to "⚡",
    "sun" to "☀️", "moon" to "🌙", "rainbow" to "🌈",
    "cloud" to "☁️", "rain" to "🌧️", "snow" to "❄️",
    "eyes" to "👀", "eye" to "👁️", "brain" to "🧠",
    "check" to "✅", "white_check_mark" to "✅", "x" to "❌",
    "warning" to "⚠️", "question" to "❓", "exclamation" to "❗",
    "pin" to "📌", "pushpin" to "📌", "link" to "🔗",
    "lock" to "🔒", "unlock" to "🔓", "key" to "🔑",
    "bulb" to "💡", "lightbulb" to "💡", "mag" to "🔍",
    "bell" to "🔔", "megaphone" to "📣", "speech_balloon" to "💬",
    "thought_balloon" to "💭", "zzz" to "💤",
    "tada" to "🎉", "party" to "🎉", "confetti" to "🎊",
    "balloon" to "🎈", "gift" to "🎁", "trophy" to "🏆",
    "medal" to "🏅", "crown" to "👑",
    "rocket" to "🚀", "airplane" to "✈️", "car" to "🚗",
    "ship" to "🚢", "bike" to "🚲",
    "coffee" to "☕", "tea" to "🍵", "beer" to "🍺", "beers" to "🍻",
    "wine" to "🍷", "cocktail" to "🍸", "pizza" to "🍕",
    "burger" to "🍔", "fries" to "🍟", "hotdog" to "🌭",
    "taco" to "🌮", "burrito" to "🌯", "sushi" to "🍣",
    "cookie" to "🍪", "cake" to "🎂", "ice_cream" to "🍦",
    "donut" to "🍩", "apple" to "🍎", "banana" to "🍌",
    "dog" to "🐕", "cat" to "🐈", "bug" to "🐛",
    "butterfly" to "🦋", "snake" to "🐍", "dragon" to "🐉",
    "unicorn" to "🦄", "bee" to "🐝", "penguin" to "🐧",
    "monkey" to "🐒", "fox" to "🦊", "panda" to "🐼",
    "pig" to "🐷", "frog" to "🐸", "chicken" to "🐔",
    "whale" to "🐋", "dolphin" to "🐬", "fish" to "🐟",
    "octopus" to "🐙", "crab" to "🦀", "shrimp" to "🦐",
    "music" to "🎵", "notes" to "🎶", "guitar" to "🎸",
    "mic" to "🎤", "headphones" to "🎧", "drum" to "🥁",
    "computer" to "💻", "phone" to "📱", "keyboard" to "⌨️",
    "gear" to "⚙️", "wrench" to "🔧", "hammer" to "🔨",
    "sword" to "⚔️", "shield" to "🛡️", "bow" to "🏹",
    "flag" to "🏁", "checkered_flag" to "🏁",
    "thumbs_up" to "👍", "thumbs_down" to "👎",
    "ok" to "👌", "peace" to "✌️", "shrug" to "🤷",
    "facepalm" to "🤦", "lol" to "😂", "lmao" to "🤣",
    "xd" to "😆", "haha" to "😄", "hmm" to "🤔",
    "sus" to "🤨", "cap" to "🧢", "no_cap" to "🚫🧢",
    "goat" to "🐐", "W" to "🏆", "L" to "❌",
    "skull_emoji" to "💀", "dead" to "💀", "rip" to "🪦",
    "salute" to "🫡", "moai" to "🗿", "nerd_face" to "🤓",
    "hot" to "🥵", "cold" to "🥶", "sick" to "🤮",
    "money" to "💰", "dollar" to "💵", "gem" to "💎",
    "ring" to "💍", "clock" to "🕐", "hourglass" to "⏳",
    "earth" to "🌍", "world" to "🌍", "map" to "🗺️",
    "house" to "🏠", "tent" to "⛺", "mountain" to "⛰️",
    "tree" to "🌳", "flower" to "🌸", "rose" to "🌹",
    "seedling" to "🌱", "leaf" to "🍃", "cactus" to "🌵",
    "poop_emoji" to "💩", "shit" to "💩"
)

internal fun replaceEmojiShortcodes(text: String): String {
    return EMOJI_SHORTCODE.replace(text) { match ->
        EMOJI_MAP[match.groupValues[1].lowercase()] ?: match.value
    }
}

private val BOLD_PATTERN = Regex("""\*\*(.+?)\*\*""")
private val CODE_PATTERN = Regex("""`([^`]+)`""")
private val CODE_BLOCK_PATTERN = Regex("""```([\s\S]*?)```""")

private data class StyledSpan(val start: Int, val end: Int, val style: SpanStyle, val displayText: String)

private data class ContentPart(val text: String, val isCodeBlock: Boolean)

private fun splitCodeBlocks(text: String): List<ContentPart> {
    val parts = mutableListOf<ContentPart>()
    var lastEnd = 0
    CODE_BLOCK_PATTERN.findAll(text).forEach { match ->
        if (match.range.first > lastEnd) {
            parts.add(ContentPart(text.substring(lastEnd, match.range.first), false))
        }
        parts.add(ContentPart(match.groupValues[1], true))
        lastEnd = match.range.last + 1
    }
    if (lastEnd < text.length) {
        parts.add(ContentPart(text.substring(lastEnd), false))
    }
    return parts
}

private fun formatMarkdown(text: String, codeBg: Color): AnnotatedString {
    val spans = mutableListOf<StyledSpan>()

    BOLD_PATTERN.findAll(text).forEach { match ->
        spans.add(StyledSpan(
            start = match.range.first,
            end = match.range.last + 1,
            style = SpanStyle(fontWeight = FontWeight.Bold),
            displayText = match.groupValues[1]
        ))
    }

    CODE_PATTERN.findAll(text).forEach { match ->
        // Skip if overlapping with a bold span
        val range = match.range
        if (spans.none { it.start < range.last + 1 && range.first < it.end }) {
            spans.add(StyledSpan(
                start = range.first,
                end = range.last + 1,
                style = SpanStyle(fontFamily = FontFamily.Monospace, background = codeBg),
                displayText = match.groupValues[1]
            ))
        }
    }

    if (spans.isEmpty()) return AnnotatedString(text)

    spans.sortBy { it.start }

    return buildAnnotatedString {
        var cursor = 0
        for (span in spans) {
            if (span.start > cursor) {
                append(text.substring(cursor, span.start))
            }
            withStyle(span.style) {
                append(span.displayText)
            }
            cursor = span.end
        }
        if (cursor < text.length) {
            append(text.substring(cursor))
        }
    }
}

@Composable
fun MessageContent(
    text: String,
    isAction: Boolean,
    fromNick: String,
    onImageClick: ((String) -> Unit)? = null
) {
    val uriHandler = LocalUriHandler.current
    val displayText = replaceEmojiShortcodes(text)

    // Jumbomoji: a message of just 1–3 emoji renders large. Checked after
    // shortcode expansion so `:tada:` jumbos like the emoji it becomes.
    val jumboSize = if (isAction) null else Jumbomoji.size(displayText)
    if (jumboSize != null) {
        SelectionContainer {
            Text(
                text = displayText.trim(),
                fontSize = jumboSize.sp,
                color = MaterialTheme.colorScheme.onBackground
            )
        }
        return
    }

    // Priority: image > Bluesky post > YouTube > generic link
    val imageUrl = IMAGE_PATTERN.find(displayText)?.value ?: CDN_PATTERN.find(displayText)?.value
    val bskyMatch = if (imageUrl == null) BSKY_POST_PATTERN.find(displayText) else null
    val ytMatch = if (imageUrl == null && bskyMatch == null) YOUTUBE_PATTERN.find(displayText) else null
    val linkUrl = if (imageUrl == null && bskyMatch == null && ytMatch == null) URL_PATTERN.find(displayText)?.value else null

    val embedUrl = imageUrl
        ?: bskyMatch?.let { URL_PATTERN.find(displayText)?.value }
        ?: ytMatch?.let { URL_PATTERN.find(displayText)?.value }
        ?: linkUrl
    val remainingText = embedUrl?.let { displayText.replace(it, "").trim() } ?: displayText

    // Text portion
    val showText = if (embedUrl != null) remainingText else displayText
    val codeBg = MaterialTheme.colorScheme.surfaceVariant
    if (showText.isNotEmpty()) {
        SelectionContainer {
            if (isAction) {
                Text(
                    text = "$fromNick $showText",
                    fontSize = 15.sp,
                    fontStyle = FontStyle.Italic,
                    color = MaterialTheme.colorScheme.onBackground
                )
            } else if (showText.contains("```")) {
                // Has code blocks — render as column with distinct code block styling.
                // SDK normalizes both wire forms (BATCH and legacy `+freeq.at/multiline`)
                // into real `\n` before this point, so no decode here.
                val parts = splitCodeBlocks(showText)
                Column {
                    for (part in parts) {
                        if (part.isCodeBlock) {
                            Box(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(vertical = 2.dp)
                                    .background(codeBg, RoundedCornerShape(6.dp))
                                    .padding(8.dp)
                            ) {
                                Text(
                                    text = part.text.trim(),
                                    fontFamily = FontFamily.Monospace,
                                    fontSize = 13.sp,
                                    color = MaterialTheme.colorScheme.onBackground
                                )
                            }
                        } else if (part.text.isNotEmpty()) {
                            Text(
                                text = formatMarkdown(part.text, codeBg),
                                fontSize = 15.sp,
                                color = MaterialTheme.colorScheme.onBackground
                            )
                        }
                    }
                }
            } else {
                val styled = formatMarkdown(showText, codeBg)
                Text(
                    text = styled,
                    fontSize = 15.sp,
                    color = MaterialTheme.colorScheme.onBackground
                )
            }
        }
    } else if (isAction && embedUrl != null) {
        // Action with only a URL — still show nick
        Text(
            text = fromNick,
            fontSize = 15.sp,
            fontStyle = FontStyle.Italic,
            color = MaterialTheme.colorScheme.onBackground
        )
    }

    // Embed
    when {
        imageUrl != null -> {
            InlineImage(url = imageUrl, onClick = { onImageClick?.invoke(imageUrl) })
        }
        bskyMatch != null -> {
            val handle = bskyMatch.groupValues[1]
            val rkey = bskyMatch.groupValues[2]
            val postUrl = bskyMatch.value
            BlueskyEmbed(
                handle = handle,
                rkey = rkey,
                onClick = { uriHandler.openUri(postUrl) },
                onImageClick = onImageClick
            )
        }
        ytMatch != null -> {
            val videoId = ytMatch.groupValues[1]
            YouTubeThumbnail(
                videoId = videoId,
                onClick = { uriHandler.openUri("https://youtube.com/watch?v=$videoId") }
            )
        }
        linkUrl != null -> {
            LinkPreview(url = linkUrl, onClick = { uriHandler.openUri(linkUrl) })
        }
    }
}

@Composable
private fun InlineImage(url: String, onClick: () -> Unit) {
    SubcomposeAsyncImage(
        model = url,
        contentDescription = null,
        modifier = Modifier
            .padding(top = 4.dp)
            .widthIn(max = 280.dp)
            .heightIn(max = 280.dp)
            .clip(RoundedCornerShape(8.dp))
            .clickable(onClick = onClick),
        contentScale = ContentScale.Fit,
        loading = {
            Box(
                modifier = Modifier
                    .size(120.dp, 80.dp)
                    .clip(RoundedCornerShape(8.dp))
                    .background(MaterialTheme.colorScheme.surfaceVariant),
                contentAlignment = Alignment.Center
            ) {
                CircularProgressIndicator(
                    modifier = Modifier.size(20.dp),
                    strokeWidth = 2.dp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f)
                )
            }
        },
        error = {
            Text(
                text = url,
                fontSize = 15.sp,
                color = MaterialTheme.colorScheme.primary
            )
        }
    )
}

@Composable
private fun YouTubeThumbnail(videoId: String, onClick: () -> Unit) {
    val thumbnailUrl = "https://img.youtube.com/vi/$videoId/mqdefault.jpg"

    Box(
        modifier = Modifier
            .padding(top = 4.dp)
            .widthIn(max = 280.dp)
            .clip(RoundedCornerShape(10.dp))
            .border(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.3f), RoundedCornerShape(10.dp))
            .clickable(onClick = onClick)
    ) {
        AsyncImage(
            model = thumbnailUrl,
            contentDescription = "YouTube video",
            modifier = Modifier
                .fillMaxWidth()
                .aspectRatio(16f / 9f),
            contentScale = ContentScale.Crop
        )

        // Play button overlay
        Box(
            modifier = Modifier
                .align(Alignment.Center)
                .size(48.dp)
                .background(Color(0xCCFF0000), CircleShape),
            contentAlignment = Alignment.Center
        ) {
            Icon(
                Icons.Default.PlayArrow,
                contentDescription = "Play",
                tint = Color.White,
                modifier = Modifier.size(28.dp)
            )
        }
    }
}

@Composable
private fun LinkPreview(url: String, onClick: () -> Unit) {
    val domain = try {
        URI(url).host?.removePrefix("www.") ?: url
    } catch (_: Exception) { url }

    val path = try {
        val p = URI(url).path ?: ""
        if (p.length > 50) p.take(50) + "..." else p
    } catch (_: Exception) { "" }

    Row(
        modifier = Modifier
            .padding(top = 4.dp)
            .widthIn(max = 300.dp)
            .clip(RoundedCornerShape(10.dp))
            .border(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.3f), RoundedCornerShape(10.dp))
            .background(MaterialTheme.colorScheme.surfaceVariant)
            .clickable(onClick = onClick)
            .padding(10.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        Box(
            modifier = Modifier
                .size(28.dp)
                .background(
                    MaterialTheme.colorScheme.primary.copy(alpha = 0.1f),
                    RoundedCornerShape(6.dp)
                ),
            contentAlignment = Alignment.Center
        ) {
            Icon(
                Icons.Default.Link,
                contentDescription = null,
                modifier = Modifier.size(16.dp),
                tint = MaterialTheme.colorScheme.primary
            )
        }

        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = domain,
                fontSize = 13.sp,
                fontWeight = FontWeight.Medium,
                color = MaterialTheme.colorScheme.onBackground,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
            if (path.isNotEmpty() && path != "/") {
                Text(
                    text = path,
                    fontSize = 11.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }
        }
    }
}

// ── Bluesky post embed ──

private data class BskyPost(
    val authorName: String,
    val authorHandle: String,
    val authorAvatar: String?,
    val text: String,
    val imageUrl: String?,
    val likeCount: Int,
    val repostCount: Int
)

@Composable
private fun BlueskyEmbed(
    handle: String,
    rkey: String,
    onClick: () -> Unit,
    onImageClick: ((String) -> Unit)? = null
) {
    var post by remember { mutableStateOf<BskyPost?>(null) }
    var failed by remember { mutableStateOf(false) }

    LaunchedEffect(handle, rkey) {
        post = withContext(Dispatchers.IO) { fetchBskyPost(handle, rkey) }
        if (post == null) failed = true
    }

    if (failed) {
        // Fall back to link preview
        LinkPreview(url = "https://bsky.app/profile/$handle/post/$rkey", onClick = onClick)
        return
    }

    val p = post ?: run {
        // Loading
        Row(
            modifier = Modifier.padding(top = 4.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            CircularProgressIndicator(
                modifier = Modifier.size(16.dp),
                strokeWidth = 2.dp,
                color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f)
            )
            Text(
                "Loading Bluesky post...",
                fontSize = 12.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.6f)
            )
        }
        return
    }

    Column(
        modifier = Modifier
            .padding(top = 4.dp)
            .widthIn(max = 300.dp)
            .clip(RoundedCornerShape(12.dp))
            .border(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.3f), RoundedCornerShape(12.dp))
            .background(MaterialTheme.colorScheme.surfaceVariant)
            .clickable(onClick = onClick)
            .padding(12.dp)
    ) {
        // Author row
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            UserAvatar(nick = p.authorHandle, size = 20.dp)
            Text(
                text = p.authorName.ifEmpty { p.authorHandle },
                fontSize = 13.sp,
                fontWeight = FontWeight.SemiBold,
                color = MaterialTheme.colorScheme.onBackground,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.weight(1f)
            )
            // Bluesky butterfly icon (blue)
            Text(
                text = "\uD83E\uDD8B",
                fontSize = 14.sp
            )
        }

        // Post text
        if (p.text.isNotEmpty()) {
            Spacer(modifier = Modifier.height(6.dp))
            Text(
                text = p.text,
                fontSize = 14.sp,
                color = MaterialTheme.colorScheme.onBackground,
                maxLines = 4,
                overflow = TextOverflow.Ellipsis
            )
        }

        // Post image
        p.imageUrl?.let { imgUrl ->
            Spacer(modifier = Modifier.height(8.dp))
            AsyncImage(
                model = imgUrl,
                contentDescription = null,
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(max = 160.dp)
                    .clip(RoundedCornerShape(8.dp))
                    .clickable { onImageClick?.invoke(imgUrl) },
                contentScale = ContentScale.Crop
            )
        }

        // Stats row
        if (p.likeCount > 0 || p.repostCount > 0) {
            Spacer(modifier = Modifier.height(8.dp))
            Row(
                horizontalArrangement = Arrangement.spacedBy(16.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                if (p.likeCount > 0) {
                    Row(
                        horizontalArrangement = Arrangement.spacedBy(4.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            Icons.Default.Favorite,
                            contentDescription = null,
                            modifier = Modifier.size(14.dp),
                            tint = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.6f)
                        )
                        Text(
                            "${p.likeCount}",
                            fontSize = 12.sp,
                            color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.6f)
                        )
                    }
                }
                if (p.repostCount > 0) {
                    Row(
                        horizontalArrangement = Arrangement.spacedBy(4.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            Icons.Default.Repeat,
                            contentDescription = null,
                            modifier = Modifier.size(14.dp),
                            tint = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.6f)
                        )
                        Text(
                            "${p.repostCount}",
                            fontSize = 12.sp,
                            color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.6f)
                        )
                    }
                }
            }
        }
    }
}

private fun fetchBskyPost(handle: String, rkey: String): BskyPost? {
    return try {
        val uri = "at://$handle/app.bsky.feed.post/$rkey"
        val encoded = URLEncoder.encode(uri, "UTF-8")
        val url = URL("https://public.api.bsky.app/xrpc/app.bsky.feed.getPostThread?uri=$encoded&depth=0")
        val conn = url.openConnection().apply {
            connectTimeout = 5000
            readTimeout = 5000
        }
        val text = conn.getInputStream().bufferedReader().readText()
        val json = JSONObject(text)
        val thread = json.optJSONObject("thread") ?: return null
        val post = thread.optJSONObject("post") ?: return null
        val author = post.optJSONObject("author") ?: return null
        val record = post.optJSONObject("record") ?: return null

        // Extract first image if present
        val embed = post.optJSONObject("embed")
        val imageUrl = embed?.optJSONArray("images")
            ?.optJSONObject(0)
            ?.optString("thumb")
            ?.takeIf { it.isNotEmpty() }

        BskyPost(
            authorName = author.optString("displayName", ""),
            authorHandle = author.optString("handle", handle),
            authorAvatar = author.optString("avatar").takeIf { it.isNotEmpty() },
            text = record.optString("text", ""),
            imageUrl = imageUrl,
            likeCount = post.optInt("likeCount", 0),
            repostCount = post.optInt("repostCount", 0)
        )
    } catch (_: Exception) {
        null
    }
}
