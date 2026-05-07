package io.jenkins.plugins.akeyless.credentials.provider.client;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Parses Akeyless {@link io.akeyless.client.model.Item#getItemTags()} entries into a flat key → value map.
 * Supports common formats: {@code key=value}, {@code key:value}, or JSON objects with {@code key}/{@code value} fields.
 */
final class ItemTagParser {

    private ItemTagParser() {}

    static Map<String, String> parseItemTags(List<String> itemTags) {
        if (itemTags == null || itemTags.isEmpty()) {
            return Collections.emptyMap();
        }
        Map<String, String> out = new HashMap<>();
        for (String raw : itemTags) {
            if (raw == null || raw.isBlank()) {
                continue;
            }
            String s = raw.trim();
            if (s.startsWith("{")) {
                parseJsonTagEntry(s, out);
                continue;
            }
            int eq = s.indexOf('=');
            if (eq > 0) {
                out.put(s.substring(0, eq).trim(), s.substring(eq + 1).trim());
                continue;
            }
            int col = s.indexOf(':');
            if (col > 0) {
                out.put(s.substring(0, col).trim(), s.substring(col + 1).trim());
            }
        }
        return out;
    }

    private static void parseJsonTagEntry(String s, Map<String, String> out) {
        try {
            com.google.gson.JsonElement el = com.google.gson.JsonParser.parseString(s);
            if (!el.isJsonObject()) {
                return;
            }
            com.google.gson.JsonObject o = el.getAsJsonObject();
            if (o.has("key") && o.has("value") && o.get("key").isJsonPrimitive() && o.get("value").isJsonPrimitive()) {
                out.put(o.get("key").getAsString(), o.get("value").getAsString());
            }
        } catch (RuntimeException ignored) {
            // ignore malformed JSON tag lines
        }
    }
}
