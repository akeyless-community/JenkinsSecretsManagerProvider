package io.jenkins.plugins.akeyless.credentials.provider.config;

import hudson.Extension;
import hudson.model.Descriptor;
import hudson.model.Descriptor.FormException;
import hudson.util.FormValidation;
import io.jenkins.plugins.akeyless.credentials.provider.auth.AuthMethod;
import io.jenkins.plugins.akeyless.credentials.provider.client.AkeylessClient;
import io.jenkins.plugins.akeyless.credentials.provider.supplier.FolderListingCache;
import jenkins.model.Jenkins;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.interceptor.RequirePOST;

import javax.annotation.Nullable;
import java.util.List;

@Extension
public class AkeylessCredentialsProviderConfig extends jenkins.model.GlobalConfiguration {

    public static AkeylessCredentialsProviderConfig get() {
        return jenkins.model.GlobalConfiguration.all().get(AkeylessCredentialsProviderConfig.class);
    }

    public AkeylessCredentialsProviderConfig() {
        load();
    }

    private String akeylessUrl;
    private String accessId;
    private AuthMethod authMethod;
    /** Folder path: secrets are at folderPath + "/" + secretName. No listing. */
    private String folderPath;
    /** Secret names under the folder (one per line). In the job use credentials('secretName'). */
    private String secretNames;
    /** Full secret paths (one per line). Alternative to folder + names; no listing. */
    private String secretPaths;
    /** @deprecated use folderPath or secretPaths; kept for backward compatibility */
    private String pathPrefix;

    /**
     * When true (default), recursive {@code list-items} results for folder-only discovery are cached
     * ({@link io.jenkins.plugins.akeyless.credentials.provider.supplier.FolderListingCache#DEFAULT_CACHE_TTL_SECONDS}
     * seconds, aligned with the AWS provider five-minute cache behavior). When false, each credentials refresh
     * triggers a fresh {@code list-items}.
     */
    private Boolean cache;

    public String getAkeylessUrl() { return akeylessUrl; }

    @DataBoundSetter
    public void setAkeylessUrl(String akeylessUrl) { this.akeylessUrl = akeylessUrl; }

    public String getAccessId() { return accessId; }

    @DataBoundSetter
    public void setAccessId(String accessId) { this.accessId = accessId; }

    public AuthMethod getAuthMethod() { return authMethod; }

    @DataBoundSetter
    public void setAuthMethod(AuthMethod authMethod) { this.authMethod = authMethod; }

    /** Folder path; when not set, pathPrefix is used (so old config works as folder path). */
    public String getFolderPath() {
        if (folderPath != null && !folderPath.isBlank()) return folderPath;
        if (pathPrefix != null && !pathPrefix.isBlank()) return pathPrefix;
        return folderPath;
    }

    @DataBoundSetter
    public void setFolderPath(String folderPath) { this.folderPath = folderPath; }

    public String getSecretNames() { return secretNames; }

    @DataBoundSetter
    public void setSecretNames(String secretNames) { this.secretNames = secretNames; }

    /** Full secret paths only (one per line). pathPrefix is not used here — it is used as folder path when Folder path is empty. */
    public String getSecretPaths() {
        return secretPaths;
    }

    @DataBoundSetter
    public void setSecretPaths(String secretPaths) { this.secretPaths = secretPaths; }

    /** @deprecated use folderPath or secretPaths */
    public String getPathPrefix() { return pathPrefix; }

    @DataBoundSetter
    public void setPathPrefix(String pathPrefix) { this.pathPrefix = pathPrefix; }

    public Boolean getCache() {
        return cache;
    }

    @DataBoundSetter
    public void setCache(Boolean cache) {
        this.cache = cache;
    }

    /** @return whether list-items discovery should use the in-memory cache (default {@code true}). */
    public boolean isCache() {
        return cache == null || cache;
    }

    @RequirePOST
    @SuppressWarnings("unused")
    public FormValidation doCheckFolderPath(@QueryParameter String folderPath,
                                            @QueryParameter String pathPrefix) {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        String fp = folderPath;
        if (fp == null || fp.isBlank()) {
            fp = pathPrefix;
        }
        if (FolderPathRules.isForbiddenRootFolder(fp)) {
            return FormValidation.error(
                    "Folder path cannot be '/' or '//' alone — that would list the entire vault. Use a concrete path "
                            + "(e.g. /CICD/jenkins/secrets).");
        }
        return FormValidation.ok();
    }

    public boolean isConfigured() {
        return akeylessUrl != null && !akeylessUrl.isBlank()
                && authMethod != null
                && authMethod.isConfigured(accessId);
    }

    @Nullable
    public AkeylessClient buildClient() {
        if (!isConfigured()) return null;
        String url = akeylessUrl.trim();
        return new AkeylessClient(url, accessId != null ? accessId.trim() : null, authMethod);
    }

    public List<Descriptor<AuthMethod>> getAuthMethodDescriptors() {
        return AuthMethod.all().stream()
                .map(d -> (Descriptor<AuthMethod>) d)
                .toList();
    }

    @Override
    public boolean configure(StaplerRequest req, JSONObject json) throws FormException {
        JSONObject section = json.optJSONObject("akeyless-credentials-provider");
        req.bindJSON(this, section != null ? section : json);
        String folderPathEff = getFolderPath();
        if (folderPathEff == null) {
            folderPathEff = "";
        }
        boolean hasNames = secretNames != null && !secretNames.isBlank();
        boolean hasPaths = secretPaths != null && !secretPaths.isBlank();
        boolean hasFolderAndNames = !folderPathEff.isBlank() && hasNames;
        boolean hasFolderOnly = !folderPathEff.isBlank() && !hasFolderAndNames && !hasPaths;
        if ((hasFolderOnly || hasFolderAndNames) && FolderPathRules.isForbiddenRootFolder(folderPathEff)) {
            throw new FormException(
                    "Folder path cannot be '/' or '//' alone — that would list the entire vault. "
                            + "Use a concrete folder (e.g. /CICD/jenkins/secrets), or use Secret paths only.",
                    "folderPath");
        }
        FolderListingCache.invalidate();
        save();
        return true;
    }
}
