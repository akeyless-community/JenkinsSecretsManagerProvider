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
 * AWS IAM authentication. Uses akeyless-java-cloud-id-lightweight to obtain
 * cloud identity from EC2/ECS/env (SigV4-signed STS GetCallerIdentity).
 */
public class AwsIamAuthMethod extends AuthMethod {

    private static final Logger LOG = Logger.getLogger(AwsIamAuthMethod.class.getName());
    private static final String ACCESS_TYPE = "aws_iam";

    @DataBoundConstructor
    public AwsIamAuthMethod() {}

    @Override
    public Auth buildAuth(@Nullable String accessId) throws Exception {
        LOG.log(Level.INFO, "Akeyless AWS IAM auth: building auth for access_id={0}", accessId);
        String cloudId;
        try {
            CloudIdProvider idProvider = CloudProviderFactory.getCloudIdProvider(ACCESS_TYPE);
            cloudId = idProvider.getCloudId();
        } catch (Exception e) {
            LOG.log(Level.SEVERE, "Failed to generate AWS cloud ID", e);
            throw new Exception("AWS IAM auth: could not obtain cloud identity. "
                    + "Ensure Jenkins is running on AWS with an IAM role attached. " + e.getMessage(), e);
        }
        Auth auth = new Auth();
        auth.setAccessId(accessId);
        auth.setAccessType(ACCESS_TYPE);
        auth.setCloudId(cloudId);
        LOG.log(Level.INFO, "Akeyless AWS IAM auth: sending auth request (access_id={0}, cloud_id_length={1})",
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
