package io.jenkins.plugins.akeyless.credentials.provider.auth;

import hudson.Extension;
import hudson.model.Descriptor;
import io.akeyless.client.model.Auth;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;

import javax.annotation.Nullable;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * GCP authentication. The identity token is auto-generated from the
 * GCP metadata service at authentication time.
 */
public class GcpAuthMethod extends AuthMethod {

    private static final Logger LOG = Logger.getLogger(GcpAuthMethod.class.getName());

    private String gcpAudience;

    @DataBoundConstructor
    public GcpAuthMethod() {}

    public String getGcpAudience() { return gcpAudience; }

    @DataBoundSetter
    public void setGcpAudience(String gcpAudience) { this.gcpAudience = gcpAudience; }

    @Override
    public Auth buildAuth(@Nullable String accessId) throws Exception {
        String cloudId;
        try {
            cloudId = CloudIdProvider.generateGcpCloudId(gcpAudience);
        } catch (Exception e) {
            LOG.log(Level.SEVERE, "Failed to generate GCP cloud ID from metadata", e);
            throw new Exception("GCP auth: could not obtain cloud identity. "
                    + "Ensure Jenkins is running on GCP with a service account. " + e.getMessage(), e);
        }
        Auth auth = new Auth();
        auth.setAccessId(accessId);
        auth.setAccessType("gcp");
        auth.setCloudId(cloudId);
        if (gcpAudience != null && !gcpAudience.isBlank()) {
            auth.setGcpAudience(gcpAudience);
        }
        return auth;
    }

    @Override
    public boolean isConfigured(@Nullable String accessId) {
        return accessId != null && !accessId.isBlank();
    }

    @Extension
    public static class DescriptorImpl extends Descriptor<AuthMethod> {
        @Override
        public String getDisplayName() { return "Google Cloud (GCP)"; }
    }
}
