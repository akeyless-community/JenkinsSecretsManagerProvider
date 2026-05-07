package io.jenkins.plugins.akeyless.credentials.provider;

import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsStore;
import com.cloudbees.plugins.credentials.CredentialsStoreAction;
import com.cloudbees.plugins.credentials.domains.Domain;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import hudson.model.ModelObject;
import hudson.security.Permission;
import jenkins.model.Jenkins;
import org.acegisecurity.Authentication;
import hudson.security.ACL;

import javax.annotation.Nonnull;
import java.util.Collections;
import java.util.List;

public class AkeylessCredentialsStore extends CredentialsStore {

    private final AkeylessCredentialsProvider provider;

    /** One action per store instance so {@link CredentialsStoreAction#isVisible()} identity checks match the bound URL action. */
    private transient CredentialsStoreAction storeAction;

    public AkeylessCredentialsStore(AkeylessCredentialsProvider provider) {
        super(AkeylessCredentialsProvider.class);
        this.provider = provider;
    }

    @Nonnull
    @Override
    public ModelObject getContext() {
        return Jenkins.get();
    }

    @Override
    public boolean hasPermission(@NonNull Authentication authentication, @NonNull Permission permission) {
        return CredentialsProvider.VIEW.equals(permission)
                && Jenkins.get().getACL().hasPermission(authentication, permission);
    }

    @Nonnull
    @Override
    public List<Credentials> getCredentials(@NonNull Domain domain) {
        if (Domain.global().equals(domain) && Jenkins.get().hasPermission(CredentialsProvider.VIEW)) {
            return provider.getCredentials(Credentials.class, Jenkins.get(), ACL.SYSTEM);
        }
        return Collections.emptyList();
    }

    @Override
    public boolean addCredentials(@Nonnull Domain domain, @Nonnull Credentials credentials) {
        throw new UnsupportedOperationException("Jenkins may not add credentials to Akeyless");
    }

    @Override
    public boolean removeCredentials(@NonNull Domain domain, @NonNull Credentials credentials) {
        throw new UnsupportedOperationException("Jenkins may not remove credentials from Akeyless");
    }

    @Override
    public boolean updateCredentials(@NonNull Domain domain, @NonNull Credentials current, @NonNull Credentials replacement) {
        throw new UnsupportedOperationException("Jenkins may not update credentials in Akeyless");
    }

    @Nullable
    @Override
    public synchronized CredentialsStoreAction getStoreAction() {
        if (storeAction == null) {
            storeAction = new AkeylessCredentialsStoreAction(this);
        }
        return storeAction;
    }

    /** Read-only Akeyless-backed store listing; visibility does not depend on Jenkins “add credential” descriptors. */
    public static class AkeylessCredentialsStoreAction extends CredentialsStoreAction {

        private final AkeylessCredentialsStore store;

        public AkeylessCredentialsStoreAction(AkeylessCredentialsStore store) {
            this.store = store;
        }

        @Override
        @NonNull
        public CredentialsStore getStore() {
            return store;
        }

        @Override
        public boolean isVisible() {
            CredentialsProvider p = store.getProvider();
            if (p == null || !p.isEnabled()) {
                return false;
            }
            // Do not delegate to superclass: default isVisible also requires non-empty getCredentialsDescriptors()
            // (can be filtered by admin restrictions) and expects getStoreAction() identity stability.
            return store.hasPermission(CredentialsProvider.VIEW);
        }

        @Override
        public String getIconFileName() {
            return null;
        }

        @Override
        public String getIconClassName() {
            return isVisible() ? "symbol-akeyless plugin-akeyless-credentials-provider" : null;
        }

        @Override
        public String getDisplayName() {
            return Messages.AkeylessCredentialsProvider_DisplayName();
        }
    }
}
