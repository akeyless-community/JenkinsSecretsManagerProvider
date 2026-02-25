package io.jenkins.plugins.akeyless.credentials.provider.credentials;

import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.util.ListBoxModel;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;

/**
 * Stores Akeyless Cloud Provider authentication configuration (AWS IAM, Azure AD, or GCP).
 * The cloud identity token is auto-generated at runtime from the cloud metadata service.
 */
public class AkeylessCloudProviderCredential extends BaseStandardCredentials {

    private String accessId;
    private String cloudProvider;

    @DataBoundConstructor
    public AkeylessCloudProviderCredential(CredentialsScope scope, String id, String description) {
        super(scope, id, description);
    }

    public String getAccessId() { return accessId; }

    @DataBoundSetter
    public void setAccessId(String accessId) { this.accessId = accessId; }

    public String getCloudProvider() { return cloudProvider; }

    @DataBoundSetter
    public void setCloudProvider(String cloudProvider) { this.cloudProvider = cloudProvider; }

    @Extension
    public static class DescriptorImpl extends BaseStandardCredentialsDescriptor {
        @Override
        @NonNull
        public String getDisplayName() { return "Akeyless Cloud Provider Credentials"; }

        public ListBoxModel doFillCloudProviderItems() {
            ListBoxModel items = new ListBoxModel();
            items.add("AWS IAM", "aws_iam");
            items.add("Azure AD", "azure_ad");
            items.add("Google Cloud (GCP)", "gcp");
            return items;
        }
    }
}
