package io.jenkins.plugins.akeyless.credentials.provider.client;

import com.google.gson.Gson;
import io.akeyless.client.ApiClient;
import io.akeyless.client.ApiException;
import io.akeyless.client.api.V2Api;
import io.akeyless.client.model.Auth;
import io.akeyless.client.model.AuthOutput;
import io.akeyless.client.model.DescribeItem;
import io.akeyless.client.model.GetCertificateValue;
import io.akeyless.client.model.GetCertificateValueOutput;
import io.akeyless.client.model.GetDynamicSecretValue;
import io.akeyless.client.model.GetRotatedSecretValue;
import io.akeyless.client.model.GetSecretValue;
import io.akeyless.client.model.Item;
import io.akeyless.client.model.ListItems;
import io.akeyless.client.model.ListItemsInPathOutput;
import io.jenkins.plugins.akeyless.credentials.provider.auth.AuthMethod;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

public class AkeylessClient {

    private static final Logger LOG = Logger.getLogger(AkeylessClient.class.getName());
    private static final Gson GSON = new Gson();

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

    /**
     * Resolves the secret value: {@code describe-item} first, then the fetch API that matches the item type
     * (static, dynamic, rotated, certificate). Missing items surface as failure (typically HTTP 404 from describe).
     */
    @Nonnull
    public GetSecretValueResult getSecretValue(String name) throws ApiException {
        Item item = describeItemStrict(name);
        String effectivePath = item.getItemName() != null && !item.getItemName().isBlank()
                ? normalizeItemPath(item.getItemName())
                : normalizeItemPath(name);
        return fetchPayloadForItem(item, effectivePath);
    }

    /**
     * Lists full item paths under a folder (recursive), using {@code list-items}. Used when only a folder path
     * is configured so Jenkins can expose credential IDs without a manual name list.
     */
    @Nonnull
    public List<String> listSecretItemPathsRecursive(@Nonnull String folderPath) throws ApiException {
        String root = normalizeItemPath(folderPath);
        List<String> paths = new ArrayList<>();
        Set<String> visitedFolders = new HashSet<>();
        Deque<String> folders = new ArrayDeque<>();
        folders.add(root);
        while (!folders.isEmpty()) {
            String path = folders.removeFirst();
            if (!visitedFolders.add(path)) {
                continue;
            }
            String paginationToken = null;
            while (true) {
                ListItems body = new ListItems();
                body.setToken(getToken());
                body.setPath(path);
                if (paginationToken != null && !paginationToken.isEmpty()) {
                    body.setPaginationToken(paginationToken);
                }
                ListItemsInPathOutput page = api().listItems(body);
                if (page.getItems() != null) {
                    for (Item it : page.getItems()) {
                        if (it.getItemName() != null && !it.getItemName().isBlank()) {
                            paths.add(normalizeItemPath(it.getItemName()));
                        }
                    }
                }
                if (page.getFolders() != null) {
                    for (String sub : page.getFolders()) {
                        if (sub != null && !sub.isBlank()) {
                            folders.addLast(normalizeItemPath(sub));
                        }
                    }
                }
                paginationToken = page.getNextPage();
                if (!Boolean.TRUE.equals(page.getHasNext()) || paginationToken == null || paginationToken.isEmpty()) {
                    break;
                }
            }
        }
        return paths;
    }

    @Nonnull
    private Item describeItemStrict(String name) throws ApiException {
        String n = normalizeItemPath(name);
        DescribeItem body = new DescribeItem();
        body.setToken(getToken());
        body.setName(n);
        try {
            Item item = api().describeItem(body);
            if (item == null) {
                throw new ApiException(404, "Item not found: " + n);
            }
            return item;
        } catch (ApiException e) {
            if (isNotFound(e)) {
                throw new ApiException(404, "Secret not found (404): " + n);
            }
            throw e;
        }
    }

    private static boolean isNotFound(ApiException e) {
        if (e.getCode() == 404) {
            return true;
        }
        String msg = e.getMessage();
        return msg != null && msg.toLowerCase(Locale.ROOT).contains("not found");
    }

    @Nonnull
    private GetSecretValueResult fetchPayloadForItem(Item item, String effectivePathAkeyless) throws ApiException {
        String itemType = safeLower(item.getItemType());
        String itemSubType = safeLower(item.getItemSubType());

        if (itemType.contains("dynamic")) {
            return fetchDynamic(effectivePathAkeyless);
        }
        if (itemType.contains("rotated")) {
            return fetchRotated(effectivePathAkeyless);
        }
        if (itemType.contains("certificate") || itemSubType.contains("certificate")) {
            return fetchCertificate(effectivePathAkeyless);
        }
        return fetchStaticSecret(effectivePathAkeyless);
    }

    private static String safeLower(@Nullable String s) {
        return s == null ? "" : s.toLowerCase(Locale.ROOT);
    }

    @Nonnull
    private GetSecretValueResult fetchStaticSecret(String pathForApi) throws ApiException {
        LOG.log(Level.INFO, "Akeyless: get-secret-value for path={0}", pathForApi);
        GetSecretValue body = new GetSecretValue();
        body.setToken(getToken());
        body.setNames(Collections.singletonList(pathForApi));
        Map<String, Object> out = api().getSecretValue(body);
        return mapOutputToResult(out, pathForApi);
    }

    @Nonnull
    private GetSecretValueResult fetchDynamic(String effectivePath) throws ApiException {
        LOG.log(Level.INFO, "Akeyless: get-dynamic-secret-value for name={0}", effectivePath);
        GetDynamicSecretValue body = new GetDynamicSecretValue();
        body.setToken(getToken());
        body.setName(trimLeadingSlash(effectivePath));
        body.setJson(true);
        Map<String, Object> out = api().getDynamicSecretValue(body);
        return mapToJsonResult(out);
    }

    @Nonnull
    private GetSecretValueResult fetchRotated(String effectivePath) throws ApiException {
        LOG.log(Level.INFO, "Akeyless: get-rotated-secret-value for names={0}", effectivePath);
        GetRotatedSecretValue body = new GetRotatedSecretValue();
        body.setToken(getToken());
        body.setNames(trimLeadingSlash(effectivePath));
        body.setJson(true);
        Map<String, Object> out = api().getRotatedSecretValue(body);
        return mapToJsonResult(out);
    }

    @Nonnull
    private GetSecretValueResult fetchCertificate(String effectivePath) throws ApiException {
        LOG.log(Level.INFO, "Akeyless: get-certificate-value for name={0}", effectivePath);
        GetCertificateValue body = new GetCertificateValue();
        body.setToken(getToken());
        body.setName(trimLeadingSlash(effectivePath));
        GetCertificateValueOutput out = api().getCertificateValue(body);
        if (out == null) {
            throw new ApiException("No certificate payload returned for: " + effectivePath);
        }
        String certPem = out.getCertificatePem();
        String keyPem = out.getPrivateKeyPem();
        if (certPem != null && keyPem != null
                && !certPem.isBlank() && !keyPem.isBlank()) {
            return GetSecretValueResult.pemCertificate(certPem, keyPem);
        }
        if (certPem != null && !certPem.isBlank()) {
            return GetSecretValueResult.string(certPem);
        }
        throw new ApiException("Certificate response had no PEM data for: " + effectivePath);
    }

    @Nonnull
    private static GetSecretValueResult mapToJsonResult(Map<String, Object> out) throws ApiException {
        if (out == null || out.isEmpty()) {
            throw new ApiException("Empty value from Akeyless");
        }
        return GetSecretValueResult.string(GSON.toJson(out));
    }

    @Nonnull
    private static GetSecretValueResult mapOutputToResult(Map<String, Object> out, String pathForApi) throws ApiException {
        if (out == null || out.isEmpty()) {
            throw new ApiException("No value returned for secret: " + pathForApi);
        }
        Object value = out.get(pathForApi);
        if (value == null && out.size() == 1) {
            value = out.values().iterator().next();
        }
        if (value == null) {
            throw new ApiException("Empty value for secret: " + pathForApi);
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
                if (v instanceof String) {
                    return GetSecretValueResult.string((String) v);
                }
                if (v instanceof byte[]) {
                    return GetSecretValueResult.binary((byte[]) v);
                }
            }
            return GetSecretValueResult.string(m.toString());
        }
        return GetSecretValueResult.string(value.toString());
    }

    private static String trimLeadingSlash(String path) {
        if (path == null || path.isEmpty()) {
            return path;
        }
        return path.startsWith("/") ? path.substring(1) : path;
    }

    /**
     * Reads item tags from Akeyless via {@code describe-item} (same keys as AWS Secrets Manager plugin:
     * {@code jenkins:credentials:type}, {@code jenkins:credentials:username}, etc.).
     * On failure returns an empty map so callers can fall back to defaults.
     */
    @Nonnull
    public Map<String, String> getItemTags(@Nonnull String itemPath) {
        String name = itemPath == null ? "" : itemPath.trim();
        if (name.isEmpty()) {
            return Collections.emptyMap();
        }
        if (!name.startsWith("/")) {
            name = "/" + name;
        }
        try {
            DescribeItem body = new DescribeItem();
            body.setToken(getToken());
            body.setName(name);
            Item item = api().describeItem(body);
            if (item == null || item.getItemTags() == null) {
                return Collections.emptyMap();
            }
            return new HashMap<>(ItemTagParser.parseItemTags(item.getItemTags()));
        } catch (ApiException e) {
            LOG.log(Level.WARNING, "Akeyless: describe-item failed for name={0}: {1}", new Object[]{name, e.getMessage()});
            return Collections.emptyMap();
        } catch (Exception e) {
            LOG.log(Level.WARNING, "Akeyless: describe-item error for name={0}: {1}", new Object[]{name, e.getMessage()});
            return Collections.emptyMap();
        }
    }

    /** Normalizes to a path with a leading {@code /} for Akeyless APIs. */
    public static String normalizeItemPath(String name) {
        String pathForApi = name == null ? "" : name.trim();
        if (pathForApi.isEmpty()) {
            return pathForApi;
        }
        if (!pathForApi.startsWith("/")) {
            pathForApi = "/" + pathForApi;
        }
        return pathForApi;
    }

    public static final class GetSecretValueResult {
        private final String stringValue;
        private final byte[] binaryValue;
        private final String certificatePem;
        private final String privateKeyPem;

        private GetSecretValueResult(String stringValue, byte[] binaryValue, String certificatePem, String privateKeyPem) {
            this.stringValue = stringValue;
            this.binaryValue = binaryValue;
            this.certificatePem = certificatePem;
            this.privateKeyPem = privateKeyPem;
        }

        public static GetSecretValueResult string(String s) {
            return new GetSecretValueResult(s, null, null, null);
        }

        public static GetSecretValueResult binary(byte[] b) {
            return new GetSecretValueResult(null, b, null, null);
        }

        public static GetSecretValueResult pemCertificate(String certificatePem, String privateKeyPem) {
            return new GetSecretValueResult(null, null, certificatePem, privateKeyPem);
        }

        public boolean isString() {
            return stringValue != null;
        }

        public boolean isPemCertificatePair() {
            return certificatePem != null && privateKeyPem != null;
        }

        public String getStringValue() {
            return stringValue;
        }

        public byte[] getBinaryValue() {
            return binaryValue;
        }

        public String getCertificatePem() {
            return certificatePem;
        }

        public String getPrivateKeyPem() {
            return privateKeyPem;
        }
    }
}
