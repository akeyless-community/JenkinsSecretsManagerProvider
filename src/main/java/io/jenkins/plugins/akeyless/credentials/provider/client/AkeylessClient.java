package io.jenkins.plugins.akeyless.credentials.provider.client;

import io.akeyless.client.ApiClient;
import io.akeyless.client.ApiException;
import io.akeyless.client.api.V2Api;
import io.akeyless.client.model.Auth;
import io.akeyless.client.model.AuthOutput;
import io.akeyless.client.model.GetSecretValue;
import io.akeyless.client.model.ListItems;
import io.akeyless.client.model.ListItemsInPathOutput;
import io.jenkins.plugins.akeyless.credentials.provider.auth.AuthMethod;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

public class AkeylessClient {

    private static final Logger LOG = Logger.getLogger(AkeylessClient.class.getName());
    private static final int MAX_RECURSION_DEPTH = 20;

    private final String basePath;
    private final String accessId;
    private final AuthMethod authMethod;
    private V2Api api;
    private String token;

    public AkeylessClient(@Nonnull String akeylessUrl, @Nullable String accessId, @Nonnull AuthMethod authMethod) {
        this.basePath = akeylessUrl.endsWith("/") ? akeylessUrl.substring(0, akeylessUrl.length() - 1) : akeylessUrl;
        this.accessId = accessId;
        this.authMethod = authMethod;
    }

    private synchronized V2Api api() {
        if (api == null) {
            ApiClient client = new ApiClient();
            client.setBasePath(basePath);
            api = new V2Api(client);
        }
        return api;
    }

    public synchronized String getToken() throws ApiException {
        if (token != null && !token.isEmpty()) {
            return token;
        }
        try {
            LOG.log(Level.INFO, "Akeyless: authenticating with method={0}, access_id={1}",
                    new Object[]{authMethod.getClass().getSimpleName(), accessId});
            Auth auth = authMethod.buildAuth(accessId);
            AuthOutput authOutput = api().auth(auth);
            token = authOutput != null ? authOutput.getToken() : null;
            if (token == null || token.isEmpty()) {
                throw new ApiException("Auth response had no token");
            }
            LOG.log(Level.INFO, "Akeyless: authenticated successfully with {0}", authMethod.getClass().getSimpleName());
            return token;
        } catch (ApiException e) {
            LOG.log(Level.WARNING, "Akeyless: authentication failed with {0}: {1}",
                    new Object[]{authMethod.getClass().getSimpleName(), e.getMessage()});
            throw e;
        } catch (Exception e) {
            LOG.log(Level.WARNING, "Akeyless: authentication failed with {0}: {1}",
                    new Object[]{authMethod.getClass().getSimpleName(), e.getMessage()});
            throw new ApiException("Authentication failed: " + e.getMessage());
        }
    }

    @Nonnull
    public List<AkeylessItem> listItems(String pathPrefix) throws ApiException {
        String pathForRequest = null;
        if (pathPrefix != null && !pathPrefix.isEmpty()) {
            pathForRequest = pathPrefix.trim().replaceAll("/+$", "");
        }
        LOG.log(Level.INFO, "Akeyless API: listItems recursive (pathPrefix={0})", pathForRequest != null ? pathForRequest : "<root>");
        List<AkeylessItem> allSecrets = new ArrayList<>();
        listItemsRecursive(pathForRequest, allSecrets, 0);
        LOG.log(Level.INFO, "Akeyless API: listItems recursive found {0} static secret(s) total", allSecrets.size());
        return allSecrets;
    }

    private void listItemsRecursive(String path, List<AkeylessItem> secrets, int depth) throws ApiException {
        if (depth > MAX_RECURSION_DEPTH) {
            LOG.log(Level.WARNING, "Akeyless list-items: max recursion depth reached at path={0}", path);
            return;
        }
        ListItems body = new ListItems();
        body.setToken(getToken());
        if (path != null && !path.isEmpty()) {
            body.setPath(path);
        }
        ListItemsInPathOutput out = api().listItems(body);
        if (out == null) return;

        if (out.getItems() != null) {
            for (Object itemObj : out.getItems()) {
                String name = reflectString(itemObj, "getItemName", "getName");
                String itemPath = reflectString(itemObj, "getItemPath", "getPath");
                String type = reflectString(itemObj, "getItemType", "getType");
                LOG.log(Level.INFO, "Akeyless list-items item: name={0} path={1} type={2}", new Object[]{name, itemPath, type});
                if (name == null) name = itemPath != null ? itemPath : "";
                if (itemPath == null) itemPath = name;
                if (!isStaticSecretType(type)) continue;
                secrets.add(new AkeylessItem(name, type != null ? type : "", itemPath));
            }
        }

        List<String> folders = out.getFolders();
        if (folders != null && !folders.isEmpty()) {
            LOG.log(Level.INFO, "Akeyless list-items (path={0}): {1} subfolder(s): {2}", new Object[]{path, folders.size(), folders});
            for (String folder : folders) {
                if (folder != null && !folder.trim().isEmpty()) {
                    listItemsRecursive(folder.trim(), secrets, depth + 1);
                }
            }
        }
    }

    @Nonnull
    public GetSecretValueResult getSecretValue(String name) throws ApiException {
        String pathForApi = name;
        if (pathForApi != null && !pathForApi.isEmpty() && !pathForApi.startsWith("/")) {
            pathForApi = "/" + pathForApi;
        }
        LOG.log(Level.INFO, "Akeyless: get-secret-value for path={0}", pathForApi);
        GetSecretValue body = new GetSecretValue();
        body.setToken(getToken());
        body.setNames(Collections.singletonList(pathForApi));
        Map<String, Object> out = api().getSecretValue(body);
        if (out == null || out.isEmpty()) {
            throw new ApiException("No value returned for secret: " + name);
        }
        Object value = out.get(pathForApi);
        if (value == null && out.size() == 1) {
            value = out.values().iterator().next();
        }
        if (value == null) {
            throw new ApiException("Empty value for secret: " + name);
        }
        if (value instanceof String) {
            return GetSecretValueResult.string((String) value);
        }
        if (value instanceof byte[]) {
            return GetSecretValueResult.binary((byte[]) value);
        }
        if (value instanceof Map) {
            @SuppressWarnings("unchecked")
            Map<String, Object> m = (Map<String, Object>) value;
            if (m.containsKey("value")) {
                Object v = m.get("value");
                if (v instanceof String) return GetSecretValueResult.string((String) v);
                if (v instanceof byte[]) return GetSecretValueResult.binary((byte[]) v);
            }
            return GetSecretValueResult.string(m.toString());
        }
        return GetSecretValueResult.string(value.toString());
    }

    @Nonnull
    public Map<String, String> getTags(String itemName) {
        try {
            return getTagsInternal(itemName);
        } catch (Exception e) {
            LOG.log(Level.FINE, "Could not get tags for " + itemName + ", using defaults", e);
            return Collections.emptyMap();
        }
    }

    private Map<String, String> getTagsInternal(String itemName) throws ApiException {
        try {
            Class<?> getTagsClass = Class.forName("io.akeyless.client.model.GetTags");
            Object body = getTagsClass.getDeclaredConstructor().newInstance();
            body.getClass().getMethod("setToken", String.class).invoke(body, getToken());
            body.getClass().getMethod("setName", String.class).invoke(body, itemName);
            java.lang.reflect.Method apiMethod = api().getClass().getMethod("getTags", getTagsClass);
            Object out = apiMethod.invoke(api(), body);
            if (out != null) {
                java.lang.reflect.Method getTags = out.getClass().getMethod("getTags");
                Object tagsObj = getTags.invoke(out);
                if (tagsObj instanceof Iterable) {
                    Map<String, String> map = new HashMap<>();
                    for (Object t : (Iterable<?>) tagsObj) {
                        Object k = t.getClass().getMethod("getKey").invoke(t);
                        Object v = t.getClass().getMethod("getValue").invoke(t);
                        if (k != null && v != null) map.put(k.toString(), v.toString());
                    }
                    return map;
                }
            }
        } catch (ClassNotFoundException ignored) {
        } catch (Exception e) {
            LOG.log(Level.FINE, "getTags reflection failed for " + itemName, e);
        }
        return Collections.emptyMap();
    }

    private static boolean isStaticSecretType(String type) {
        if (type == null || type.isEmpty()) return true;
        String n = type.replace('-', '_').replace(' ', '_');
        return "STATIC_SECRET".equalsIgnoreCase(n) || "STATICSECRET".equalsIgnoreCase(n);
    }

    private static String reflectString(Object obj, String... methodNames) {
        if (obj == null) return null;
        for (String m : methodNames) {
            try {
                java.lang.reflect.Method method = obj.getClass().getMethod(m);
                Object val = method.invoke(obj);
                if (val != null) {
                    String s = val.toString().trim();
                    if (!s.isEmpty()) return s;
                }
            } catch (NoSuchMethodException ignored) {
            } catch (Exception e) {
                LOG.log(Level.FINEST, "reflectString failed for " + m, e);
            }
        }
        return null;
    }

    public static final class AkeylessItem {
        private final String name;
        private final String itemType;
        private final String path;

        public AkeylessItem(String name, String itemType, String path) {
            this.name = name;
            this.itemType = itemType;
            this.path = path;
        }

        public String getName() { return name; }
        public String getItemType() { return itemType; }
        public String getPath() { return path; }
    }

    public static final class GetSecretValueResult {
        private final String stringValue;
        private final byte[] binaryValue;

        private GetSecretValueResult(String stringValue, byte[] binaryValue) {
            this.stringValue = stringValue;
            this.binaryValue = binaryValue;
        }

        public static GetSecretValueResult string(String s) {
            return new GetSecretValueResult(s, null);
        }

        public static GetSecretValueResult binary(byte[] b) {
            return new GetSecretValueResult(null, b);
        }

        public boolean isString() { return stringValue != null; }
        public String getStringValue() { return stringValue; }
        public byte[] getBinaryValue() { return binaryValue; }
    }
}
