package com.example.fullscansecurity.model;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

public final class RemediationAction {
    public enum Type {
        NONE,
        APP_SETTINGS,
        UNKNOWN_APP_SOURCES,
        SECURITY_SETTINGS,
        DEVELOPMENT_SETTINGS,
        DEFAULT_APPS,
        OVERLAY_SETTINGS,
        NOTIFICATION_LISTENER_SETTINGS,
        ACCESSIBILITY_SETTINGS,
        PLAY_STORE_UPDATE,
        UNINSTALL
    }

    public final Type type;
    public final String packageName;
    public final String label;
    public final String uniqueKey;

    public RemediationAction(@NonNull Type type, @Nullable String packageName,
                             @NonNull String label, @NonNull String uniqueKey) {
        this.type = type;
        this.packageName = packageName == null ? "" : packageName;
        this.label = label;
        this.uniqueKey = uniqueKey;
    }
}
