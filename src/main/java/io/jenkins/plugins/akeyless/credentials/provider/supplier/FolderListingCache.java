package io.jenkins.plugins.akeyless.credentials.provider.supplier;

import io.akeyless.client.ApiException;
import io.jenkins.plugins.akeyless.credentials.provider.client.AkeylessClient;

import javax.annotation.Nonnull;
import javax.annotation.concurrent.GuardedBy;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Caches recursive {@code list-items} results for folder-only discovery to avoid hammering Akeyless on every
 * {@code CredentialsProvider#getCredentials} call.
 */
public final class FolderListingCache {

    /** When caching is enabled, list-items results are reused for this many seconds (not user-configurable). */
    /** Align with AWS Secrets Manager Credentials Provider cache wording/duration (5 minutes). */
    public static final int DEFAULT_CACHE_TTL_SECONDS = 300;

    private static final Logger LOG = Logger.getLogger(FolderListingCache.class.getName());

    private static final Object LOCK = new Object();

    @GuardedBy("LOCK")
    private static volatile String cachedFolderKey;

    @GuardedBy("LOCK")
    private static volatile int cachedTtlSeconds;

    @GuardedBy("LOCK")
    private static volatile long cachedAtNanos;

    @GuardedBy("LOCK")
    private static volatile List<String> cachedPaths = Collections.emptyList();

    private FolderListingCache() {}

    /** Clears the cache (used when config changes materially). */
    public static void invalidate() {
        synchronized (LOCK) {
            cachedFolderKey = null;
            cachedTtlSeconds = 0;
            cachedAtNanos = 0;
            cachedPaths = Collections.emptyList();
        }
    }

    /**
     * Loads folder contents, using the in-memory cache when {@code cacheEnabled} is true.
     */
    @Nonnull
    public static List<String> getOrLoad(
            @Nonnull AkeylessClient client,
            @Nonnull String folderNormalized,
            boolean cacheEnabled) throws ApiException {
        if (!cacheEnabled) {
            return client.listSecretItemPathsRecursive(folderNormalized);
        }

        int ttlSec = DEFAULT_CACHE_TTL_SECONDS;
        long ttlNanos = ttlSec * 1_000_000_000L;
        synchronized (LOCK) {
            long age = System.nanoTime() - cachedAtNanos;
            if (folderNormalized.equals(cachedFolderKey)
                    && ttlSec == cachedTtlSeconds
                    && cachedAtNanos != 0
                    && age >= 0
                    && age < ttlNanos) {
                LOG.log(Level.FINE, "Akeyless Credentials Provider: list-items cache hit for folder={0} (TTL {1}s)",
                        new Object[]{folderNormalized, ttlSec});
                return new ArrayList<>(cachedPaths);
            }
        }

        List<String> fresh = client.listSecretItemPathsRecursive(folderNormalized);
        synchronized (LOCK) {
            cachedFolderKey = folderNormalized;
            cachedTtlSeconds = ttlSec;
            cachedPaths = Collections.unmodifiableList(new ArrayList<>(fresh));
            cachedAtNanos = System.nanoTime();
        }
        LOG.log(Level.INFO, "Akeyless Credentials Provider: list-items refreshed for folder={0}, {1} path(s), cache TTL {2}s",
                new Object[]{folderNormalized, fresh.size(), ttlSec});
        return new ArrayList<>(fresh);
    }
}
