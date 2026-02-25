package io.jenkins.plugins.akeyless.credentials.provider;

import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsStore;
import com.cloudbees.plugins.credentials.common.StandardCredentials;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.model.ItemGroup;
import hudson.model.ModelObject;
import hudson.security.ACL;
import io.jenkins.plugins.akeyless.credentials.provider.config.AkeylessCredentialsProviderConfig;
import io.jenkins.plugins.akeyless.credentials.provider.supplier.CredentialsSupplier;
import jenkins.model.Jenkins;
import org.acegisecurity.Authentication;

import javax.annotation.Nonnull;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;

@Extension
public class AkeylessCredentialsProvider extends CredentialsProvider {

    private static final Logger LOG = Logger.getLogger(AkeylessCredentialsProvider.class.getName());

    @NonNull
    @Override
    public <C extends Credentials> List<C> getCredentials(@Nonnull Class<C> type,
                                                          @Nonnull ItemGroup itemGroup,
                                                          @Nonnull Authentication authentication) {
        LOG.log(Level.INFO, "Akeyless Credentials Provider: getCredentials called type={0} itemGroup={1}",
                new Object[]{type.getSimpleName(), itemGroup != null ? itemGroup.getClass().getSimpleName() : "null"});

        if (itemGroup != Jenkins.get()) {
            return Collections.emptyList();
        }
        if (!ACL.SYSTEM.equals(authentication) && !Jenkins.get().getACL().hasPermission(authentication, CredentialsProvider.VIEW)) {
            return Collections.emptyList();
        }
        AkeylessCredentialsProviderConfig config = AkeylessCredentialsProviderConfig.get();
        if (config == null || !config.isConfigured()) {
            LOG.log(Level.FINE, "Akeyless Credentials Provider: not configured");
            return Collections.emptyList();
        }
        Collection<StandardCredentials> all = CredentialsSupplier.get(config);
        List<C> filtered = all.stream()
                .filter(c -> type.isAssignableFrom(c.getClass()))
                .map(type::cast)
                .collect(Collectors.toList());
        LOG.log(Level.INFO, "Akeyless Credentials Provider: returning {0} credential(s) for type {1}", new Object[]{filtered.size(), type.getSimpleName()});
        return filtered;
    }

    @Override
    public CredentialsStore getStore(ModelObject object) {
        return object == Jenkins.get() ? new AkeylessCredentialsStore(this) : null;
    }

    @Override
    public String getIconClassName() {
        return "icon-akeyless-credentials-store";
    }
}
