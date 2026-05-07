package io.jenkins.plugins.akeyless.credentials.provider.supplier;

import com.cloudbees.plugins.credentials.common.StandardCredentials;
import io.jenkins.plugins.akeyless.credentials.provider.client.AkeylessClient;
import io.jenkins.plugins.akeyless.credentials.provider.config.AkeylessCredentialsProviderConfig;
import io.jenkins.plugins.akeyless.credentials.provider.config.FolderPathRules;
import io.jenkins.plugins.akeyless.credentials.provider.factory.CredentialsFactory;
import io.jenkins.plugins.akeyless.credentials.provider.factory.Tags;
import io.jenkins.plugins.akeyless.credentials.provider.factory.Type;

import io.akeyless.client.ApiException;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;

/**
 * Supplies credentials from user-configured paths. Uses {@code describe-item} to read Akeyless item tags
 * (same convention as AWS Secrets Manager Credentials Provider). Secret values are fetched on demand via
 * {@code describe-item} then the appropriate API (static / dynamic / rotated / certificate) per item type.
 */
public class CredentialsSupplier {

    private static final Logger LOG = Logger.getLogger(CredentialsSupplier.class.getName());
    private static final Pattern PATH_SPLIT = Pattern.compile("[,\n\r]+");

    public static Collection<StandardCredentials> get(AkeylessCredentialsProviderConfig config) {
        if (config == null || !config.isConfigured()) {
            LOG.log(Level.INFO, "Akeyless Credentials Provider: not configured (URL and auth required)");
            return Collections.emptyList();
        }
        String folderPath = config.getFolderPath();
        String secretNamesInput = config.getSecretNames();
        String secretPathsInput = config.getSecretPaths();
        boolean hasSecretPaths = secretPathsInput != null && !secretPathsInput.isBlank();
        boolean hasFolderAndNames = folderPath != null && !folderPath.isBlank()
                && secretNamesInput != null && !secretNamesInput.isBlank();
        boolean hasFolderOnly = folderPath != null && !folderPath.isBlank()
                && !hasFolderAndNames
                && !hasSecretPaths;
        if (!hasFolderAndNames && !hasSecretPaths && !hasFolderOnly) {
            LOG.log(Level.INFO, "Akeyless Credentials Provider: set ''Folder path'' alone (discover secrets under the folder), or ''Folder path'' + ''Secret names'', or ''Secret paths'', in Manage Jenkins → Configure System.");
            return Collections.emptyList();
        }
        try {
            AkeylessClient client = config.buildClient();
            if (client == null) {
                LOG.log(Level.WARNING, "Akeyless Credentials Provider: could not build client (check URL and auth)");
                return Collections.emptyList();
            }

            Collection<StandardCredentials> result = new ArrayList<>();
            Set<String> usedCredentialIds = new HashSet<>();

            // 0) Folder path only: list-items under the folder (recursive) — credential id is usually the last path segment.
            if (hasFolderOnly) {
                String folderNorm = folderPath.trim().replaceAll("/+$", "");
                if (!folderNorm.startsWith("/")) {
                    folderNorm = "/" + folderNorm;
                }
                if (FolderPathRules.isForbiddenRootFolder(folderNorm)) {
                    LOG.log(Level.WARNING,
                            "Akeyless Credentials Provider: folder path is root ''/'' only — discovery disabled. Set a subfolder (e.g. /CICD/secrets).");
                    return result;
                }
                try {
                    List<String> discovered =
                            FolderListingCache.getOrLoad(client, folderNorm, config.isCache());
                    for (String fullPath : discovered) {
                        Map<String, String> tags = resolveTagsFromAkeyless(client, fullPath);
                        addOneCredentialForPath(result, usedCredentialIds, fullPath, tags);
                    }
                    LOG.log(Level.INFO, "Akeyless Credentials Provider: folder-only discovery found {0} item path(s) under {1}",
                            new Object[]{discovered.size(), folderNorm});
                } catch (ApiException e) {
                    LOG.log(Level.WARNING, "Akeyless Credentials Provider: list-items under folder={0} failed: {1}",
                            new Object[]{folderNorm, e.getMessage()});
                }
            }

            // 1) Folder path + secret names: full path = folderPath + "/" + secretName.
            //    Secret name is the credential id used in the pipeline (e.g. credentials('jenkinsai')).
            if (hasFolderAndNames) {
                String folderNorm = folderPath.trim().replaceAll("/+$", "");
                if (!folderNorm.startsWith("/")) {
                    folderNorm = "/" + folderNorm;
                }
                if (FolderPathRules.isForbiddenRootFolder(folderNorm)) {
                    LOG.log(Level.WARNING,
                            "Akeyless Credentials Provider: folder path is root ''/'' only — cannot resolve secrets under folder. Configure a subfolder.");
                    return result;
                }
                String[] names = PATH_SPLIT.split(secretNamesInput);
                for (String raw : names) {
                    String name = raw.trim();
                    if (name.isEmpty()) continue;
                    String fullPath = folderNorm + "/" + name.replaceAll("^/+", "");  // e.g. /CICD/jenkins/test/test3/jenkinsai
                    Map<String, String> tags = resolveTagsFromAkeyless(client, fullPath);
                    addOneCredentialForPath(result, usedCredentialIds, fullPath, tags);
                    LOG.log(Level.INFO, "Akeyless Credentials Provider: folder+name path={0} type={1}",
                            new Object[]{fullPath, tags.getOrDefault(Tags.TYPE, Type.STRING)});
                }
            }

            // 2) Explicit full secret paths (and pathPrefix fallback)
            if (hasSecretPaths) {
                String[] rawPaths = PATH_SPLIT.split(secretPathsInput);
                for (String raw : rawPaths) {
                    String path = raw.trim();
                    if (path.isEmpty()) continue;
                    String akeylessPath = path.startsWith("/") ? path : "/" + path;
                    Map<String, String> tags = resolveTagsFromAkeyless(client, akeylessPath);
                    addOneCredentialForPath(result, usedCredentialIds, akeylessPath, tags);
                }
            }

            if (!result.isEmpty()) {
                Set<String> ids = new HashSet<>();
                for (StandardCredentials c : result) ids.add(c.getId());
                LOG.log(Level.INFO, "Akeyless Credentials Provider: {0} credential(s), ids={1}", new Object[]{result.size(), ids});
            }
            return result;
        } catch (Exception e) {
            LOG.log(Level.WARNING, "Error loading Akeyless credentials", e);
            return Collections.emptyList();
        }
    }

    /**
     * One Jenkins credential per Akeyless path. Credential id is the last path segment (e.g. {@code jenkinsai}) when
     * that id is not already taken; otherwise the full normalized path (e.g. when two secrets share the same name
     * under different folders).
     */
    private static void addOneCredentialForPath(
            Collection<StandardCredentials> result,
            Set<String> usedCredentialIds,
            String akeylessPath,
            Map<String, String> defaultTags) {
        String full = AkeylessClient.normalizeItemPath(akeylessPath);
        String description = full;
        String lastSeg = lastPathSegment(full);
        String id;
        if (lastSeg != null && !usedCredentialIds.contains(lastSeg)) {
            id = lastSeg;
        } else if (!usedCredentialIds.contains(full)) {
            id = full;
        } else {
            LOG.log(Level.FINE, "Akeyless Credentials Provider: skip duplicate path {0}", full);
            return;
        }
        usedCredentialIds.add(id);
        CredentialsFactory.create(id, full, description, defaultTags).ifPresent(result::add);
    }

    /**
     * Loads tags from Akeyless ({@code describe-item}) and merges with defaults (same keys as AWS Secrets Manager plugin).
     * If describe-item fails or returns no type tag, defaults to {@link Type#STRING}.
     */
    private static Map<String, String> resolveTagsFromAkeyless(AkeylessClient client, String fullPath) {
        Map<String, String> tags = new HashMap<>(client.getItemTags(fullPath));
        tags.putIfAbsent(Tags.TYPE, Type.STRING);
        return tags;
    }

    /**
     * Credential ID from path: strips leading/trailing slashes and sanitizes to [a-zA-Z0-9/_.-].
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

    /** Last segment of path (e.g. /CICD/jenkins/test/test3/jenkinsai → jenkinsai) for use as short credential ID. */
    private static String lastPathSegment(String path) {
        if (path == null || path.isEmpty()) return null;
        String trimmed = path.replaceAll("/+$", "").trim();
        int last = trimmed.lastIndexOf('/');
        if (last < 0) return credentialIdFromPath(trimmed);
        String segment = trimmed.substring(last + 1);
        return segment.isEmpty() ? null : credentialIdFromPath(segment);
    }
}
