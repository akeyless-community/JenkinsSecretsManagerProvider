package io.jenkins.plugins.akeyless.credentials.provider.auth;

import hudson.Extension;
import hudson.model.Descriptor;
import io.akeyless.client.model.Auth;
import io.akeyless.cloudid.CloudIdProvider;
import io.akeyless.cloudid.CloudProviderFactory;
import org.kohsuke.stapler.DataBoundConstructor;

import javax.annotation.Nullable;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Azure AD authentication. Uses akeyless-java-cloud-id-lightweight to obtain
 * Managed Identity token from Azure IMDS.
 */
public class AzureAdAuthMethod extends AuthMethod {

    private static final Logger LOG = Logger.getLogger(AzureAdAuthMethod.class.getName());
    private static final String ACCESS_TYPE = "azure_ad";

    @DataBoundConstructor
    public AzureAdAuthMethod() {}

    @Override
    public Auth buildAuth(@Nullable String accessId) throws Exception {
        String cloudId;
        try {
            CloudIdProvider idProvider = CloudProviderFactory.getCloudIdProvider(ACCESS_TYPE);
            cloudId = idProvider.getCloudId();
        } catch (Exception e) {
            LOG.log(Level.SEVERE, "Failed to generate Azure cloud ID from IMDS", e);
            throw new Exception("Azure AD auth: could not obtain cloud identity. "
                    + "Ensure Jenkins is running on Azure with a managed identity. " + e.getMessage(), e);
        }
        Auth auth = new Auth();
        auth.setAccessId(accessId);
        auth.setAccessType(ACCESS_TYPE);
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
