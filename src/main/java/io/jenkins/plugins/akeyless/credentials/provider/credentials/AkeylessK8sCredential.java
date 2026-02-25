package io.jenkins.plugins.akeyless.credentials.provider.credentials;

import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;

/**
 * Stores Akeyless Kubernetes authentication configuration.
 * The service account token can be auto-read from the pod mount at runtime.
 */
public class AkeylessK8sCredential extends BaseStandardCredentials {

    private String accessId;
    private String k8sAuthConfigName;

    @DataBoundConstructor
    public AkeylessK8sCredential(CredentialsScope scope, String id, String description) {
        super(scope, id, description);
    }

    public String getAccessId() { return accessId; }

    @DataBoundSetter
    public void setAccessId(String accessId) { this.accessId = accessId; }

    public String getK8sAuthConfigName() { return k8sAuthConfigName; }

    @DataBoundSetter
    public void setK8sAuthConfigName(String k8sAuthConfigName) { this.k8sAuthConfigName = k8sAuthConfigName; }

    @Extension
    public static class DescriptorImpl extends BaseStandardCredentialsDescriptor {
        @Override
        @NonNull
        public String getDisplayName() { return "Akeyless Kubernetes Credentials"; }
    }
}
