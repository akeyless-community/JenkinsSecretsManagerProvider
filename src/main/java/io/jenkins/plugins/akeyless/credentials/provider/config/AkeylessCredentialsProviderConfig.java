package io.jenkins.plugins.akeyless.credentials.provider.config;

import hudson.Extension;
import hudson.model.Descriptor;
import io.jenkins.plugins.akeyless.credentials.provider.auth.AuthMethod;
import io.jenkins.plugins.akeyless.credentials.provider.client.AkeylessClient;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.StaplerRequest;

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
    private String pathPrefix;

    public String getAkeylessUrl() { return akeylessUrl; }

    @DataBoundSetter
    public void setAkeylessUrl(String akeylessUrl) { this.akeylessUrl = akeylessUrl; }

    public String getAccessId() { return accessId; }

    @DataBoundSetter
    public void setAccessId(String accessId) { this.accessId = accessId; }

    public AuthMethod getAuthMethod() { return authMethod; }

    @DataBoundSetter
    public void setAuthMethod(AuthMethod authMethod) { this.authMethod = authMethod; }

    public String getPathPrefix() { return pathPrefix; }

    @DataBoundSetter
    public void setPathPrefix(String pathPrefix) { this.pathPrefix = pathPrefix; }

    public boolean isConfigured() {
        return akeylessUrl != null && !akeylessUrl.isBlank()
                && authMethod != null
                && authMethod.isConfigured(accessId);
    }

    @Nullable
    public AkeylessClient buildClient() {
        if (!isConfigured()) return null;
        String url = akeylessUrl.trim();
        if (!url.endsWith("/api/v2") && !url.endsWith("/api/v2/")) {
            url = url.endsWith("/") ? url + "api/v2" : url + "/api/v2";
        }
        return new AkeylessClient(url, accessId != null ? accessId.trim() : null, authMethod);
    }

    public List<Descriptor<AuthMethod>> getAuthMethodDescriptors() {
        return AuthMethod.all().stream()
                .map(d -> (Descriptor<AuthMethod>) d)
                .toList();
    }

    @Override
    public boolean configure(StaplerRequest req, JSONObject json) {
        JSONObject section = json.optJSONObject("akeyless-credentials-provider");
        req.bindJSON(this, section != null ? section : json);
        save();
        return true;
    }
}
