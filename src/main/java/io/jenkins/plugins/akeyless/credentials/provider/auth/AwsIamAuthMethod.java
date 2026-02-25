package io.jenkins.plugins.akeyless.credentials.provider.auth;

import hudson.Extension;
import hudson.model.Descriptor;
import io.akeyless.client.model.Auth;
import org.kohsuke.stapler.DataBoundConstructor;

import javax.annotation.Nullable;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * AWS IAM authentication. The cloud identity is auto-generated from the
 * EC2/ECS/Lambda environment at authentication time.
 */
public class AwsIamAuthMethod extends AuthMethod {

    private static final Logger LOG = Logger.getLogger(AwsIamAuthMethod.class.getName());

    @DataBoundConstructor
    public AwsIamAuthMethod() {}

    @Override
    public Auth buildAuth(@Nullable String accessId) throws Exception {
        LOG.log(Level.INFO, "Akeyless AWS IAM auth: building auth for access_id={0}", accessId);
        String cloudId;
        try {
            cloudId = CloudIdProvider.generateAwsCloudId();
        } catch (Exception e) {
            LOG.log(Level.SEVERE, "Failed to generate AWS cloud ID from instance metadata", e);
            throw new Exception("AWS IAM auth: could not obtain cloud identity. "
                    + "Ensure Jenkins is running on AWS with an IAM role attached. " + e.getMessage(), e);
        }
        Auth auth = new Auth();
        auth.setAccessId(accessId);
        auth.setAccessType("aws_iam");
        auth.setCloudId(cloudId);
        LOG.log(Level.INFO, "Akeyless AWS IAM auth: sending auth request (access_id={0}, access_type=aws_iam, cloud_id_length={1})",
                new Object[]{accessId, cloudId.length()});
        return auth;
    }

    @Override
    public boolean isConfigured(@Nullable String accessId) {
        return accessId != null && !accessId.isBlank();
    }

    @Extension
    public static class DescriptorImpl extends Descriptor<AuthMethod> {
        @Override
        public String getDisplayName() { return "AWS IAM"; }
    }
}
