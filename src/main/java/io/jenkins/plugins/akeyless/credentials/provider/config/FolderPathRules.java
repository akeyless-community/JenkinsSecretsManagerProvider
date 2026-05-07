package io.jenkins.plugins.akeyless.credentials.provider.config;

import javax.annotation.Nullable;

/** Validation for folder-path configuration used with list-items discovery. */
public final class FolderPathRules {

    private FolderPathRules() {}

    /**
     * {@code '/'} alone (or repeated slashes only) resolves to listing the entire vault — disallowed on purpose.
     */
    public static boolean isForbiddenRootFolder(@Nullable String folderPathRaw) {
        if (folderPathRaw == null) {
            return false;
        }
        String t = folderPathRaw.trim();
        if (t.isEmpty()) {
            return false;
        }
        t = t.replaceAll("/+", "/");
        while (t.length() > 1 && t.endsWith("/")) {
            t = t.substring(0, t.length() - 1);
        }
        return "/".equals(t);
    }
}
