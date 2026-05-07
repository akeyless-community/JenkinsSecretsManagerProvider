package io.jenkins.plugins.akeyless.credentials.provider.credentials;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import javax.annotation.Nullable;

/**
 * Parses JSON secret values when {@code jenkins:credentials:valueFormat=json} is set on the Akeyless item.
 */
final class SecretJsonBodies {

    private SecretJsonBodies() {}

    static boolean isJsonFormat(String valueFormat) {
        return valueFormat != null && "json".equalsIgnoreCase(valueFormat.trim());
    }

    static boolean looksLikeJsonObject(String raw) {
        return raw != null && raw.trim().startsWith("{");
    }

    @Nullable
    static UsernamePasswordJson parseUsernamePassword(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        try {
            JsonElement el = JsonParser.parseString(raw.trim());
            if (!el.isJsonObject()) {
                return null;
            }
            JsonObject o = el.getAsJsonObject();
            String user = firstString(o, "username", "user", "usr");
            String pass = firstString(o, "password", "psw", "secret", "passwd");
            if (pass == null) {
                return null;
            }
            return new UsernamePasswordJson(user != null ? user : "", pass);
        } catch (RuntimeException e) {
            return null;
        }
    }

    @Nullable
    static SshJson parseSsh(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        try {
            JsonElement el = JsonParser.parseString(raw.trim());
            if (!el.isJsonObject()) {
                return null;
            }
            JsonObject o = el.getAsJsonObject();
            String user = firstString(o, "username", "user", "usr");
            String key = firstString(o, "privateKey", "private_key", "key");
            if (key == null) {
                return null;
            }
            String pass = firstString(o, "passphrase", "pass", "password");
            return new SshJson(user != null ? user : "", key, pass != null ? pass : "");
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static String firstString(JsonObject o, String... keys) {
        for (String k : keys) {
            if (o.has(k) && o.get(k).isJsonPrimitive()) {
                String s = o.get(k).getAsString();
                if (s != null && !s.isEmpty()) {
                    return s;
                }
            }
        }
        return null;
    }

    static final class UsernamePasswordJson {
        final String username;
        final String password;

        UsernamePasswordJson(String username, String password) {
            this.username = username;
            this.password = password;
        }
    }

    static final class SshJson {
        final String username;
        final String privateKey;
        final String passphrase;

        SshJson(String username, String privateKey, String passphrase) {
            this.username = username;
            this.privateKey = privateKey;
            this.passphrase = passphrase;
        }
    }
}
