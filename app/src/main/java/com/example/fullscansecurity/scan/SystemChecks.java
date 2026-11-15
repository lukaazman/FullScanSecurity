package com.example.fullscansecurity.scan;

import android.Manifest;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.text.TextUtils;
import com.example.fullscansecurity.R;
import com.example.fullscansecurity.model.ScanSection;
import com.example.fullscansecurity.model.ThreatFinding;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

final class SystemChecks extends ScanSupport {

    SystemChecks(Context base) {
        super(base);
    }

    ScanSection scanAccessibilityAndAdminAbuse() {
        PackageManager packageManager = getPackageManager();
        List<ThreatFinding> findings = new ArrayList<>();
        Set<String> enabledAccessibilityPackages = getEnabledAccessibilityPackages();
        Set<String> activeAdminPackages = getActiveAdminPackages();
        Set<String> combined = new LinkedHashSet<>();
        combined.addAll(enabledAccessibilityPackages);
        combined.addAll(activeAdminPackages);

        for (String packageName : combined) {
            if (shouldSkipPackage(packageName)) {
                continue;
            }
            try {
                ApplicationInfo appInfo = packageManager.getApplicationInfo(packageName, 0);
                if (!isScannableUserApp(appInfo)) {
                    continue;
                }

                PackageInfo packageInfo = getPackageInfoCompat(packageName, PackageManager.GET_PERMISSIONS);
                List<String> requested = getRequestedPermissions(packageInfo);
                boolean accessibility = enabledAccessibilityPackages.contains(packageName);
                boolean admin = activeAdminPackages.contains(packageName);
                boolean overlay = requested.contains("android.permission.SYSTEM_ALERT_WINDOW");

                List<String> reasons = new ArrayList<>();
                if (accessibility) {
                    reasons.add(getString(R.string.reason_accessibility_on));
                }
                if (admin) {
                    reasons.add(getString(R.string.reason_admin_active));
                }
                if (overlay) {
                    reasons.add(getString(R.string.reason_overlay_access));
                }

                findings.add(new ThreatFinding(
                        packageManager.getApplicationLabel(appInfo).toString(),
                        getString(R.string.finding_accessibility_body),
                        getString(R.string.attack_type_accessibility),
                        packageName,
                        TextUtils.join(" | ", reasons),
                        getString(R.string.accessibility_hint),
                        packageName,
                        null,
                        true,
                        false
                ));
            } catch (Exception ignored) {
                // Ignore packages that cannot be resolved cleanly.
            }
        }

        String summary = combined.size() + " " + getString(R.string.summary_accessibility);
        return new ScanSection(getString(R.string.section_accessibility), summary, findings);
    }

    ScanSection scanNotificationAndOverlayAbuse() {
        PackageManager packageManager = getPackageManager();
        List<ThreatFinding> findings = new ArrayList<>();
        Set<String> listeners = getEnabledNotificationListenerPackages();

        for (ApplicationInfo appInfo : getInstalledApplicationsCompat()) {
            if (!isScannableUserApp(appInfo)) {
                continue;
            }
            try {
                PackageInfo packageInfo = getPackageInfoCompat(
                        appInfo.packageName,
                        PackageManager.GET_PERMISSIONS | PackageManager.GET_RECEIVERS
                );
                List<String> requested = getRequestedPermissions(packageInfo);
                boolean notificationListener = listeners.contains(appInfo.packageName);
                boolean overlay = requested.contains("android.permission.SYSTEM_ALERT_WINDOW");
                boolean bootPersistence = hasBootPersistenceReceiver(packageInfo, requested);
                boolean batteryBypass = isIgnoringBatteryOptimizations(appInfo.packageName);

                if (!notificationListener && !overlay && !bootPersistence && !batteryBypass) {
                    continue;
                }

                List<String> reasons = new ArrayList<>();
                if (notificationListener) {
                    reasons.add(getString(R.string.reason_notification_access));
                }
                if (overlay) {
                    reasons.add(getString(R.string.reason_overlay));
                }
                if (bootPersistence) {
                    reasons.add(getString(R.string.reason_boot_start));
                }
                if (batteryBypass) {
                    reasons.add(getString(R.string.reason_battery_bypass));
                }

                findings.add(new ThreatFinding(
                        packageManager.getApplicationLabel(appInfo).toString(),
                        getString(R.string.finding_persistence_body),
                        getString(R.string.attack_type_persistence),
                        appInfo.packageName,
                        TextUtils.join(", ", reasons),
                        getString(R.string.hint_disable_untrusted_persistence),
                        appInfo.packageName,
                        packageManager.getApplicationIcon(appInfo),
                        true,
                        true
                ));
            } catch (Exception ignored) {
                // Ignore packages with unavailable manifest metadata.
            }
        }

        return new ScanSection(getString(R.string.section_persistence), getString(R.string.summary_persistence), findings);
    }

    ScanSection scanDefaultAppRedirectionRisk() {
        PackageManager packageManager = getPackageManager();
        List<ThreatFinding> findings = new ArrayList<>();
        Set<String> accessibilityPackages = getEnabledAccessibilityPackages();

        findings.addAll(buildDefaultRoleFindings(packageManager, getString(R.string.role_default_sms), getDefaultSmsPackage(), accessibilityPackages));
        findings.addAll(buildDefaultRoleFindings(packageManager, getString(R.string.role_default_dialer), getDefaultDialerPackage(), accessibilityPackages));
        findings.addAll(buildDefaultRoleFindings(packageManager, getString(R.string.role_default_browser), getDefaultBrowserPackage(), accessibilityPackages));

        return new ScanSection(getString(R.string.section_browser_sms_call), getString(R.string.summary_browser_sms_call), findings);
    }

    ScanSection scanInputMethodRisk() {
        PackageManager packageManager = getPackageManager();
        List<ThreatFinding> findings = new ArrayList<>();
        Set<String> enabledInputMethods = getEnabledInputMethodPackages();
        String defaultInputMethod = getDefaultInputMethodPackage();

        for (String packageName : enabledInputMethods) {
            if (TextUtils.isEmpty(packageName) || shouldSkipPackage(packageName)) {
                continue;
            }
            try {
                ApplicationInfo appInfo = packageManager.getApplicationInfo(packageName, 0);
                if (!isScannableUserApp(appInfo)) {
                    continue;
                }
                PackageInfo packageInfo = getPackageInfoCompat(packageName, PackageManager.GET_PERMISSIONS);
                List<String> requested = getRequestedPermissions(packageInfo);
                boolean defaultIme = packageName.equals(defaultInputMethod);
                boolean internet = requested.contains(Manifest.permission.INTERNET);
                boolean contacts = requested.contains(Manifest.permission.READ_CONTACTS);
                boolean microphone = requested.contains(Manifest.permission.RECORD_AUDIO);
                boolean overlay = requested.contains("android.permission.SYSTEM_ALERT_WINDOW");

                List<String> reasons = new ArrayList<>();
                if (defaultIme) {
                    reasons.add(getString(R.string.reason_default_keyboard));
                }
                if (internet) {
                    reasons.add(getString(R.string.reason_network_access));
                }
                if (contacts) {
                    reasons.add(getString(R.string.reason_contacts_access));
                }
                if (microphone) {
                    reasons.add(getString(R.string.reason_microphone));
                }
                if (overlay) {
                    reasons.add(getString(R.string.reason_overlay));
                }

                if (defaultIme || contacts || microphone || overlay) {
                    findings.add(new ThreatFinding(
                            packageManager.getApplicationLabel(appInfo).toString(),
                            getString(R.string.finding_keyboard_risk_body),
                            getString(R.string.attack_type_keylogger),
                            packageName,
                            TextUtils.join(", ", reasons),
                            getString(R.string.hint_review_keyboard),
                            packageName,
                            packageManager.getApplicationIcon(appInfo),
                            true,
                            true
                    ));
                }
            } catch (Exception ignored) {
                // Ignore IMEs that cannot be fully resolved.
            }
        }

        return new ScanSection(getString(R.string.section_input_methods), getString(R.string.summary_input_methods), findings);
    }

    ScanSection scanSurveillanceRisk() {
        PackageManager packageManager = getPackageManager();
        List<ThreatFinding> findings = new ArrayList<>();
        int reviewed = 0;

        for (ApplicationInfo appInfo : getInstalledApplicationsCompat()) {
            if (!isScannableUserApp(appInfo)) {
                continue;
            }
            reviewed++;
            try {
                PackageInfo packageInfo = getPackageInfoCompat(appInfo.packageName, PackageManager.GET_PERMISSIONS);
                List<String> requested = getRequestedPermissions(packageInfo);
                List<String> matched = new ArrayList<>();

                maybeAddPermissionLabel(requested, Manifest.permission.RECORD_AUDIO, getString(R.string.label_mic), matched);
                maybeAddPermissionLabel(requested, Manifest.permission.CAMERA, getString(R.string.label_camera), matched);
                maybeAddPermissionLabel(requested, Manifest.permission.ACCESS_FINE_LOCATION, getString(R.string.label_location), matched);
                maybeAddPermissionLabel(requested, Manifest.permission.READ_CONTACTS, getString(R.string.label_contacts), matched);
                maybeAddPermissionLabel(requested, Manifest.permission.READ_SMS, getString(R.string.label_sms), matched);
                maybeAddPermissionLabel(requested, Manifest.permission.READ_CALL_LOG, getString(R.string.label_call_log), matched);
                maybeAddPermissionLabel(requested, Manifest.permission.QUERY_ALL_PACKAGES, getString(R.string.label_all_apps), matched);
                maybeAddPermissionLabel(requested, "android.permission.SYSTEM_ALERT_WINDOW", getString(R.string.reason_overlay), matched);

                if (matched.size() >= 4) {
                    findings.add(new ThreatFinding(
                            packageManager.getApplicationLabel(appInfo).toString(),
                            getString(R.string.finding_surveillance_body),
                            getString(R.string.attack_type_surveillance),
                            appInfo.packageName,
                            TextUtils.join(", ", matched),
                            getString(R.string.hint_review_surveillance_app),
                            appInfo.packageName,
                            packageManager.getApplicationIcon(appInfo),
                            true,
                            true
                    ));
                }
            } catch (Exception ignored) {
                // Ignore packages that fail metadata resolution.
            }
        }

        return new ScanSection(getString(R.string.section_surveillance), getString(R.string.summary_surveillance, reviewed), findings);
    }
}
