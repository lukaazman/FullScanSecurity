package com.example.fullscansecurity.model;

import android.graphics.drawable.Drawable;

import androidx.annotation.Nullable;

public final class ThreatFinding {
    public final String title;
    public final String description;
    public final String attackType;
    public final String location;
    public final String whyFlagged;
    public final String remediationHint;
    public final String removablePackage;
    public final Drawable icon;
    public final boolean removable;
    public final boolean showAppIcon;
    public boolean selectedForRemoval;

    public ThreatFinding(String title, String description, String attackType, String location,
                         String whyFlagged, String remediationHint, @Nullable String removablePackage,
                         @Nullable Drawable icon, boolean removable, boolean showAppIcon) {
        this.title = title;
        this.description = description;
        this.attackType = attackType;
        this.location = location;
        this.whyFlagged = whyFlagged + "\n" + remediationHint;
        this.remediationHint = remediationHint;
        this.removablePackage = removablePackage;
        this.icon = icon;
        this.removable = removable;
        this.showAppIcon = showAppIcon;
        this.selectedForRemoval = removable && removablePackage != null;
    }
}
