package com.example.fullscansecurity.remediation;

import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.provider.Settings;
import android.text.TextUtils;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import com.example.fullscansecurity.R;
import com.example.fullscansecurity.model.RemediationAction;
import com.example.fullscansecurity.model.ThreatFinding;
import com.example.fullscansecurity.scan.ScanSupport;

/** Maps a finding to the settings screen or uninstall intent that fixes it. */
public final class RemediationPlanner extends ScanSupport {

    public RemediationPlanner(Context base) {
        super(base);
    }

    public boolean isThreatActionable(@NonNull ThreatFinding threat) {
        return buildRemediationAction(threat).type != RemediationAction.Type.NONE;
    }

    @NonNull
    public RemediationAction buildRemediationAction(@NonNull ThreatFinding threat) {
        String packageName = threat.removablePackage != null ? threat.removablePackage : threat.location;
        String reasonText = threat.whyFlagged == null ? "" : threat.whyFlagged;

        if (threat.attackType.equals(getString(R.string.attack_type_permissions))) {
            return new RemediationAction(
                    RemediationAction.Type.APP_SETTINGS,
                    packageName,
                    getString(R.string.action_open_app_settings),
                    RemediationAction.Type.APP_SETTINGS.name() + ":" + packageName
            );
        }

        if (threat.attackType.equals(getString(R.string.attack_type_install_trust))) {
            if (!TextUtils.isEmpty(packageName) && packageName.contains(".")) {
                return new RemediationAction(
                        RemediationAction.Type.UNKNOWN_APP_SOURCES,
                        packageName,
                        getString(R.string.action_review_unknown_installs),
                        RemediationAction.Type.UNKNOWN_APP_SOURCES.name() + ":" + packageName
                );
            }
            return new RemediationAction(
                    RemediationAction.Type.SECURITY_SETTINGS,
                    "",
                    getString(R.string.action_review_security_settings),
                    RemediationAction.Type.SECURITY_SETTINGS.name()
            );
        }

        if (threat.attackType.equals(getString(R.string.attack_type_default_handler))) {
            return new RemediationAction(
                    RemediationAction.Type.DEFAULT_APPS,
                    packageName,
                    getString(R.string.action_review_default_apps),
                    RemediationAction.Type.DEFAULT_APPS.name()
            );
        }

        if (threat.attackType.equals(getString(R.string.attack_type_persistence))) {
            if (reasonText.contains(getString(R.string.reason_accessibility_on))) {
                return new RemediationAction(
                        RemediationAction.Type.ACCESSIBILITY_SETTINGS,
                        packageName,
                        getString(R.string.action_review_accessibility),
                        RemediationAction.Type.ACCESSIBILITY_SETTINGS.name() + ":" + packageName
                );
            }
            if (reasonText.contains(getString(R.string.reason_notification_access))) {
                return new RemediationAction(
                        RemediationAction.Type.NOTIFICATION_LISTENER_SETTINGS,
                        packageName,
                        getString(R.string.action_review_notification_access),
                        RemediationAction.Type.NOTIFICATION_LISTENER_SETTINGS.name()
                );
            }
            if (reasonText.contains(getString(R.string.reason_overlay))
                    || reasonText.contains(getString(R.string.reason_overlay_access))) {
                return new RemediationAction(
                        RemediationAction.Type.OVERLAY_SETTINGS,
                        packageName,
                        getString(R.string.action_review_overlay),
                        RemediationAction.Type.OVERLAY_SETTINGS.name() + ":" + packageName
                );
            }
            if (reasonText.contains(getString(R.string.reason_battery_bypass))) {
                return new RemediationAction(
                        RemediationAction.Type.APP_SETTINGS,
                        packageName,
                        getString(R.string.action_open_app_settings),
                        RemediationAction.Type.APP_SETTINGS.name() + ":" + packageName
                );
            }
            return new RemediationAction(
                    RemediationAction.Type.APP_SETTINGS,
                    packageName,
                    getString(R.string.action_open_app_settings),
                    RemediationAction.Type.APP_SETTINGS.name() + ":" + packageName
            );
        }

        if (threat.attackType.equals(getString(R.string.attack_type_surveillance))
                || threat.attackType.equals(getString(R.string.attack_type_keylogger))
                || threat.attackType.equals(getString(R.string.attack_type_sensitive_service))
                || threat.attackType.equals(getString(R.string.attack_type_accessibility))) {
            return new RemediationAction(
                    RemediationAction.Type.APP_SETTINGS,
                    packageName,
                    getString(R.string.action_open_app_settings),
                    RemediationAction.Type.APP_SETTINGS.name() + ":" + packageName
            );
        }

        if (threat.attackType.equals(getString(R.string.attack_type_component_surface))) {
            return new RemediationAction(
                    RemediationAction.Type.PLAY_STORE_UPDATE,
                    packageName,
                    getString(R.string.action_check_for_update),
                    RemediationAction.Type.PLAY_STORE_UPDATE.name() + ":" + packageName
            );
        }

        if (threat.attackType.equals(getString(R.string.attack_type_sideload))) {
            return new RemediationAction(
                    RemediationAction.Type.PLAY_STORE_UPDATE,
                    packageName,
                    getString(R.string.action_verify_source_or_update),
                    RemediationAction.Type.PLAY_STORE_UPDATE.name() + ":" + packageName
            );
        }

        if (threat.attackType.equals(getString(R.string.attack_type_remote))) {
            return new RemediationAction(
                    RemediationAction.Type.DEVELOPMENT_SETTINGS,
                    "",
                    getString(R.string.action_review_developer_settings),
                    RemediationAction.Type.DEVELOPMENT_SETTINGS.name()
            );
        }

        if (threat.attackType.equals(getString(R.string.attack_type_hardening))) {
            return new RemediationAction(
                    RemediationAction.Type.SECURITY_SETTINGS,
                    "",
                    getString(R.string.action_review_security_settings),
                    RemediationAction.Type.SECURITY_SETTINGS.name()
            );
        }

        if (threat.removable && !TextUtils.isEmpty(threat.removablePackage)) {
            return new RemediationAction(
                    RemediationAction.Type.UNINSTALL,
                    threat.removablePackage,
                    getString(R.string.action_uninstall_app),
                    RemediationAction.Type.UNINSTALL.name() + ":" + threat.removablePackage
            );
        }

        return new RemediationAction(RemediationAction.Type.NONE, packageName, "", "none");
    }

    @Nullable
    public Intent buildRemediationIntent(@NonNull RemediationAction action) {
        switch (action.type) {
            case APP_SETTINGS: {
                if (!isValidPackageName(action.packageName)) {
                    return null;
                }
                Intent intent = new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS);
                intent.setData(Uri.parse("package:" + action.packageName));
                return intent;
            }
            case UNKNOWN_APP_SOURCES: {
                if (!isValidPackageName(action.packageName)) {
                    return null;
                }
                Intent intent = new Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES);
                intent.setData(Uri.parse("package:" + action.packageName));
                return intent;
            }
            case SECURITY_SETTINGS:
                return new Intent(Settings.ACTION_SECURITY_SETTINGS);
            case DEVELOPMENT_SETTINGS:
                return new Intent(Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS);
            case DEFAULT_APPS:
                return new Intent(Settings.ACTION_MANAGE_DEFAULT_APPS_SETTINGS);
            case OVERLAY_SETTINGS: {
                if (!isValidPackageName(action.packageName)) {
                    return null;
                }
                Intent intent = new Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION);
                intent.setData(Uri.parse("package:" + action.packageName));
                return intent;
            }
            case NOTIFICATION_LISTENER_SETTINGS:
                return new Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS);
            case ACCESSIBILITY_SETTINGS:
                return new Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS);
            case PLAY_STORE_UPDATE: {
                if (!isValidPackageName(action.packageName)) {
                    return null;
                }
                Intent marketIntent = new Intent(Intent.ACTION_VIEW, Uri.parse("market://details?id=" + action.packageName));
                marketIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                if (canResolveIntent(marketIntent)) {
                    return marketIntent;
                }
                Intent webIntent = new Intent(Intent.ACTION_VIEW,
                        Uri.parse("https://play.google.com/store/apps/details?id=" + action.packageName));
                webIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                return webIntent;
            }
            case UNINSTALL: {
                if (!isValidPackageName(action.packageName)) {
                    return null;
                }
                Intent uninstallIntent = new Intent(Intent.ACTION_UNINSTALL_PACKAGE);
                uninstallIntent.setData(Uri.parse("package:" + action.packageName));
                uninstallIntent.putExtra(Intent.EXTRA_RETURN_RESULT, true);
                return uninstallIntent;
            }
            case NONE:
            default:
                return null;
        }
    }

    public boolean canResolveIntent(@NonNull Intent intent) {
        PackageManager packageManager = getPackageManager();
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            return packageManager.resolveActivity(intent,
                    PackageManager.ResolveInfoFlags.of(PackageManager.MATCH_DEFAULT_ONLY)) != null;
        }
        return packageManager.resolveActivity(intent, PackageManager.MATCH_DEFAULT_ONLY) != null;
    }

    @NonNull
    public String getRecommendedActionLabel(@NonNull RemediationAction.Type actionType) {
        switch (actionType) {
            case APP_SETTINGS:
                return getString(R.string.action_open_app_settings);
            case UNKNOWN_APP_SOURCES:
                return getString(R.string.action_review_unknown_installs);
            case SECURITY_SETTINGS:
                return getString(R.string.action_review_security_settings);
            case DEVELOPMENT_SETTINGS:
                return getString(R.string.action_review_developer_settings);
            case DEFAULT_APPS:
                return getString(R.string.action_review_default_apps);
            case OVERLAY_SETTINGS:
                return getString(R.string.action_review_overlay);
            case NOTIFICATION_LISTENER_SETTINGS:
                return getString(R.string.action_review_notification_access);
            case ACCESSIBILITY_SETTINGS:
                return getString(R.string.action_review_accessibility);
            case PLAY_STORE_UPDATE:
                return getString(R.string.action_check_for_update);
            case UNINSTALL:
                return getString(R.string.action_uninstall_app);
            case NONE:
            default:
                return getString(R.string.action_manual_review);
        }
    }
}
