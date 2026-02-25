package io.jenkins.plugins.akeyless.credentials.provider.supplier;

import com.cloudbees.plugins.credentials.common.StandardCredentials;
import io.akeyless.client.ApiException;
import io.jenkins.plugins.akeyless.credentials.provider.client.AkeylessClient;
import io.jenkins.plugins.akeyless.credentials.provider.config.AkeylessCredentialsProviderConfig;
import io.jenkins.plugins.akeyless.credentials.provider.factory.CredentialsFactory;
import io.jenkins.plugins.akeyless.credentials.provider.client.AkeylessClient.AkeylessItem;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;

/**
 * Supplies credentials by listing Akeyless items and mapping tagged items to Jenkins credentials.
 */
public class CredentialsSupplier {

    private static final Logger LOG = Logger.getLogger(CredentialsSupplier.class.getName());

    public static Collection<StandardCredentials> get(AkeylessCredentialsProviderConfig config) {
        if (config == null || !config.isConfigured()) {
            LOG.log(Level.FINE, "Akeyless Credentials Provider: config null or not configured (URL and credential ID required)");
            return Collections.emptyList();
        }
        try {
            AkeylessClient client = config.buildClient();
            if (client == null) {
                LOG.log(Level.WARNING, "Akeyless Credentials Provider: could not build client (check that the selected Akeyless credential exists and URL is correct)");
                return Collections.emptyList();
            }
            String pathPrefix = config.getPathPrefix();
            LOG.log(Level.INFO, "Akeyless Credentials Provider: listing secrets from Akeyless (pathPrefix={0})", pathPrefix != null ? pathPrefix : "");
            List<AkeylessItem> items = client.listItems(pathPrefix);
            List<StandardCredentials> result = new ArrayList<>();
            for (AkeylessItem item : items) {
                // Full path for get-secret-value (same as CLI: akeyless get-secret-value --name /CICD/jenkins/apikey)
                String akeylessPath = fullPathForApi(item);
                // Use full path for ID derivation so prefix stripping yields correct relative path
                String pathForId = akeylessPath != null ? akeylessPath : item.getName();
                // When path prefix is set, credential ID is relative to it (e.g. prefix /CICD/jenkins + path /CICD/jenkins/apikey -> id "apikey")
                String id = credentialIdFromPath(pathForId, pathPrefix);
                if (id == null) continue;
                Map<String, String> tags = client.getTags(akeylessPath);
                // Always use a mutable copy; getTags() may return an unmodifiable map (e.g. emptyMap()).
                Map<String, String> tagsForFactory = new HashMap<>(tags);
                if (tagsForFactory.getOrDefault(io.jenkins.plugins.akeyless.credentials.provider.factory.Tags.TYPE, "").isEmpty()) {
                    tagsForFactory.put(io.jenkins.plugins.akeyless.credentials.provider.factory.Tags.TYPE,
                            io.jenkins.plugins.akeyless.credentials.provider.factory.Type.STRING);
                }
                Optional<StandardCredentials> cred = CredentialsFactory.create(id, akeylessPath, item.getPath(), tagsForFactory);
                cred.ifPresent(result::add);
                // Register alternate ID forms so jobs can use any of:
                //   "test/test3/jenkinsai"  (relative, no leading /)
                //   "/test/test3/jenkinsai" (relative, with leading /)
                //   "/CICD/jenkins/test/test3/jenkinsai" (full path including prefix)
                //   "CICD/jenkins/test/test3/jenkinsai"  (full path without leading /)
                java.util.Set<String> registered = new java.util.HashSet<>();
                registered.add(id);
                String withSlash = id.startsWith("/") ? id : "/" + id;
                String withoutSlash = id.startsWith("/") ? id.substring(1) : id;
                for (String altId : new String[]{withSlash, withoutSlash}) {
                    if (registered.add(altId)) {
                        CredentialsFactory.create(altId, akeylessPath, item.getPath(), tagsForFactory).ifPresent(result::add);
                    }
                }
                // Full path forms (with prefix re-included)
                String fullPath = akeylessPath != null ? akeylessPath.replaceAll("^/+|/+$", "") : null;
                if (fullPath != null && !fullPath.isEmpty()) {
                    for (String altId : new String[]{fullPath, "/" + fullPath}) {
                        if (registered.add(altId)) {
                            CredentialsFactory.create(altId, akeylessPath, item.getPath(), tagsForFactory).ifPresent(result::add);
                        }
                    }
                }
                LOG.log(Level.INFO, "Akeyless Credentials Provider: registered IDs for {0}: {1}", new Object[]{akeylessPath, registered});
            }
            LOG.log(Level.INFO, "Akeyless Credentials Provider: listed {0} credential(s) from Akeyless", result.size());
            return result;
        } catch (ApiException e) {
            LOG.log(Level.WARNING, "Akeyless Credentials Provider: could not list credentials from Akeyless: " + e.getMessage(), e);
            return Collections.emptyList();
        } catch (Exception e) {
            LOG.log(Level.WARNING, "Error loading Akeyless credentials", e);
            return Collections.emptyList();
        }
    }

    /** Full Akeyless path for get-secret-value API (e.g. /CICD/jenkins/apikey). Prefer item path, then name; ensure leading /. */
    private static String fullPathForApi(AkeylessItem item) {
        String p = (item.getPath() != null && !item.getPath().isEmpty()) ? item.getPath() : item.getName();
        if (p == null || p.isEmpty()) return p;
        p = p.trim();
        return p.startsWith("/") ? p : "/" + p;
    }

    /**
     * Jenkins credential ID from path. If pathPrefix is set, the ID is relative to it so you can use
     * short IDs in jobs (e.g. prefix /CICD/jenkins + path /CICD/jenkins/apikey -> id "apikey").
     * Otherwise the full path is used (e.g. /CICD/jenkins/apikey -> CICD_jenkins_apikey).
     * IDs are sanitized to [a-zA-Z0-9_.-].
     */
    private static String credentialIdFromPath(String path, String pathPrefix) {
        if (path == null || path.isEmpty()) return null;
        String pathNorm = path.trim().replaceAll("/+$", "");
        String toUse = pathNorm;
        if (pathPrefix != null && !pathPrefix.isEmpty()) {
            String prefixNorm = pathPrefix.trim().replaceAll("/+$", "");
            if (!prefixNorm.isEmpty()) {
                String pathWithLead = pathNorm.startsWith("/") ? pathNorm : "/" + pathNorm;
                String prefixWithLead = prefixNorm.startsWith("/") ? prefixNorm : "/" + prefixNorm;
                if (pathWithLead.equals(prefixWithLead) || pathWithLead.startsWith(prefixWithLead + "/")) {
                    String suffix = pathWithLead.substring(prefixWithLead.length());
                    suffix = suffix.replaceAll("^/+|/+$", "");
                    toUse = suffix.isEmpty() ? pathNorm : suffix;
                }
            }
        }
        return credentialIdFromPath(toUse);
    }

    /**
     * Credential ID keeps the path structure with slashes (e.g. test/test3/jenkinsai).
     * Only strips leading/trailing slashes and removes unsafe characters.
     */
    private static String credentialIdFromPath(String path) {
        if (path == null || path.isEmpty()) return null;
        String trimmed = path.replaceAll("^/+|/+$", "");
        if (trimmed.isEmpty()) return null;
        if (!trimmed.matches("[a-zA-Z0-9/_.-]+")) {
            trimmed = trimmed.replaceAll("[^a-zA-Z0-9/_.-]", "_");
        }
        return trimmed.isEmpty() ? null : trimmed;
    }
}
