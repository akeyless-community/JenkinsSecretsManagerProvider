package io.jenkins.plugins.akeyless.credentials.provider.auth;

import hudson.Extension;
import hudson.model.Descriptor;
import io.akeyless.client.model.Auth;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;

import javax.annotation.Nullable;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Kubernetes authentication with Akeyless.
 * Reads the pod service-account token automatically if not provided manually.
 */
public class KubernetesAuthMethod extends AuthMethod {

    private static final Logger LOG = Logger.getLogger(KubernetesAuthMethod.class.getName());
    private static final String SA_TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token";

    private String k8sAuthConfigName;
    private String k8sServiceAccountToken;

    @DataBoundConstructor
    public KubernetesAuthMethod() {}

    public String getK8sAuthConfigName() { return k8sAuthConfigName; }

    @DataBoundSetter
    public void setK8sAuthConfigName(String k8sAuthConfigName) { this.k8sAuthConfigName = k8sAuthConfigName; }

    public String getK8sServiceAccountToken() { return k8sServiceAccountToken; }

    @DataBoundSetter
    public void setK8sServiceAccountToken(String k8sServiceAccountToken) { this.k8sServiceAccountToken = k8sServiceAccountToken; }

    @Override
    public Auth buildAuth(@Nullable String accessId) throws Exception {
        String saToken = k8sServiceAccountToken;
        if (saToken == null || saToken.isBlank()) {
            Path p = Path.of(SA_TOKEN_PATH);
            if (Files.isReadable(p)) {
                saToken = Files.readString(p).trim();
                LOG.log(Level.FINE, "Read Kubernetes service account token from {0}", SA_TOKEN_PATH);
            } else {
                throw new Exception("Kubernetes auth: no service account token provided "
                        + "and " + SA_TOKEN_PATH + " is not readable");
            }
        }
        Auth auth = new Auth();
        auth.setAccessId(accessId);
        auth.setAccessType("k8s");
        auth.setK8sAuthConfigName(k8sAuthConfigName);
        auth.setK8sServiceAccountToken(saToken);
        return auth;
    }

    @Override
    public boolean isConfigured(@Nullable String accessId) {
        return accessId != null && !accessId.isBlank()
                && k8sAuthConfigName != null && !k8sAuthConfigName.isBlank();
    }

    @Extension
    public static class DescriptorImpl extends Descriptor<AuthMethod> {
        @Override
        public String getDisplayName() { return "Kubernetes"; }
    }
}
