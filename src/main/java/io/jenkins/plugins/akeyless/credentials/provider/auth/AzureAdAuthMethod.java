package io.jenkins.plugins.akeyless.credentials.provider.auth;

import hudson.Extension;
import hudson.model.Descriptor;
import io.akeyless.client.model.Auth;
import org.kohsuke.stapler.DataBoundConstructor;

import javax.annotation.Nullable;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Azure AD authentication. The cloud identity token is auto-generated from
 * the Azure Instance Metadata Service (IMDS) at authentication time.
 */
public class AzureAdAuthMethod extends AuthMethod {

    private static final Logger LOG = Logger.getLogger(AzureAdAuthMethod.class.getName());

    @DataBoundConstructor
    public AzureAdAuthMethod() {}

    @Override
    public Auth buildAuth(@Nullable String accessId) throws Exception {
        String cloudId;
        try {
            cloudId = CloudIdProvider.generateAzureCloudId();
        } catch (Exception e) {
            LOG.log(Level.SEVERE, "Failed to generate Azure cloud ID from IMDS", e);
            throw new Exception("Azure AD auth: could not obtain cloud identity. "
                    + "Ensure Jenkins is running on Azure with a managed identity. " + e.getMessage(), e);
        }
        Auth auth = new Auth();
        auth.setAccessId(accessId);
        auth.setAccessType("azure_ad");
        auth.setCloudId(cloudId);
        return auth;
    }

    @Override
    public boolean isConfigured(@Nullable String accessId) {
        return accessId != null && !accessId.isBlank();
    }

    @Extension
    public static class DescriptorImpl extends Descriptor<AuthMethod> {
        @Override
        public String getDisplayName() { return "Azure AD"; }
    }
}
