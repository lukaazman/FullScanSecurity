package com.example.fullscansecurity.scan;

import android.Manifest;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.graphics.drawable.Drawable;
import android.provider.Settings;
import android.text.TextUtils;
import com.example.fullscansecurity.R;
import com.example.fullscansecurity.model.ScanSection;
import com.example.fullscansecurity.model.ThreatFinding;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

final class AppChecks extends ScanSupport {

    AppChecks(Context base) {
        super(base);
    }

    ScanSection scanInstalledApps() {
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
                List<String> requestedPermissions = getRequestedPermissions(packageInfo);
                String installer = getInstallerPackage(appInfo.packageName);
                String label = packageManager.getApplicationLabel(appInfo).toString();
                Drawable icon = packageManager.getApplicationIcon(appInfo);
                int riskScore = 0;
                List<String> reasons = new ArrayList<>();

                if (TextUtils.isEmpty(installer) || installer.toLowerCase(Locale.US).contains("unknown")) {
                    riskScore += 2;
                    reasons.add(getString(R.string.reason_unknown_source));
                }

                if ((appInfo.flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0) {
                    riskScore += 2;
                    reasons.add(getString(R.string.reason_debug_build));
                }

                if (containsSuspiciousKeyword(label) || containsSuspiciousKeyword(appInfo.packageName)) {
                    riskScore += 1;
                    reasons.add(getString(R.string.reason_suspicious_name));
                }

                if (countHighRiskPermissions(requestedPermissions) >= 4) {
                    riskScore += 2;
                    reasons.add(getString(R.string.reason_high_risk_permissions));
                }

                if (riskScore >= 3) {
                    findings.add(new ThreatFinding(
                            label,
                            getString(R.string.finding_apps_body),
                            getString(R.string.attack_type_sideload),
                            appInfo.packageName,
                            getString(R.string.installer_prefix) + " " + safeInstallerLabel(installer),
                            TextUtils.join(", ", reasons),
                            appInfo.packageName,
                            icon,
                            true,
                            true
                    ));
                }
            } catch (Exception ignored) {
                // Skip packages with restricted metadata.
            }
        }

        String summary = reviewed + " " + getString(R.string.summary_installed_apps);
        return new ScanSection(getString(R.string.section_apps), summary, findings);
    }

    ScanSection scanPermissionExposure() {
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

                for (String permission : HIGH_RISK_PERMISSIONS) {
                    if (requested.contains(permission)) {
                        matched.add(shortPermissionName(permission));
                    }
                }

                boolean hasOverlay = requested.contains("android.permission.SYSTEM_ALERT_WINDOW");
                boolean hasInstallPackages = requested.contains(Manifest.permission.REQUEST_INSTALL_PACKAGES);
                boolean hasQueryAll = requested.contains(Manifest.permission.QUERY_ALL_PACKAGES);
                boolean hasSms = requested.contains(Manifest.permission.SEND_SMS)
                        || requested.contains(Manifest.permission.RECEIVE_SMS)
                        || requested.contains(Manifest.permission.READ_SMS);

                if ((hasOverlay && hasSms) || (hasInstallPackages && hasQueryAll) || matched.size() >= 5) {
                    findings.add(new ThreatFinding(
                            packageManager.getApplicationLabel(appInfo).toString(),
                            getString(R.string.finding_permissions_body),
                            getString(R.string.attack_type_permissions),
                            appInfo.packageName,
                            getString(R.string.permissions_prefix) + " " + TextUtils.join(", ", matched),
                            getString(R.string.permissions_hint),
                            appInfo.packageName,
                            packageManager.getApplicationIcon(appInfo),
                            true,
                            true
                    ));
                }
            } catch (Exception ignored) {
                // Ignore packages with unavailable permission metadata.
            }
        }

        String summary = reviewed + " " + getString(R.string.summary_permissions);
        return new ScanSection(getString(R.string.section_permissions), summary, findings);
    }

    ScanSection scanInstallTrust() {
        PackageManager packageManager = getPackageManager();
        List<ThreatFinding> findings = new ArrayList<>();
        int reviewed = 0;

        if (Settings.Global.getInt(getContentResolver(), "package_verifier_enable", 1) == 0) {
            findings.add(new ThreatFinding(
                    getString(R.string.finding_package_verifier_off_title),
                    getString(R.string.finding_package_verifier_off_body),
                    getString(R.string.attack_type_install_trust),
                    getString(R.string.location_system_settings),
                    getString(R.string.detail_package_verifier_off),
                    getString(R.string.hint_enable_install_verifier),
                    null,
                    null,
                    false,
                    false
            ));
        }

        if (Settings.Global.getInt(getContentResolver(), "verifier_verify_adb_installs", 1) == 0) {
            findings.add(new ThreatFinding(
                    getString(R.string.finding_adb_verifier_off_title),
                    getString(R.string.finding_adb_verifier_off_body),
                    getString(R.string.attack_type_install_trust),
                    getString(R.string.location_system_settings),
                    getString(R.string.detail_adb_verifier_off),
                    getString(R.string.hint_enable_adb_verifier),
                    null,
                    null,
                    false,
                    false
            ));
        }

        if (!isPackageInstalled("com.google.android.gms")) {
            findings.add(new ThreatFinding(
                    getString(R.string.finding_play_services_missing_title),
                    getString(R.string.finding_play_services_missing_body),
                    getString(R.string.attack_type_install_trust),
                    getString(R.string.location_google_services),
                    getString(R.string.detail_play_services_missing),
                    getString(R.string.hint_alt_trust_source),
                    null,
                    null,
                    false,
                    false
            ));
        }

        for (ApplicationInfo appInfo : getInstalledApplicationsCompat()) {
            if (!isScannableUserApp(appInfo)) {
                continue;
            }
            reviewed++;
            try {
                PackageInfo packageInfo = getPackageInfoCompat(appInfo.packageName, PackageManager.GET_PERMISSIONS);
                List<String> requested = getRequestedPermissions(packageInfo);
                if (!requested.contains(Manifest.permission.REQUEST_INSTALL_PACKAGES)) {
                    continue;
                }
                findings.add(new ThreatFinding(
                        packageManager.getApplicationLabel(appInfo).toString(),
                        getString(R.string.finding_unknown_install_app_body),
                        getString(R.string.attack_type_install_trust),
                        appInfo.packageName,
                        getString(R.string.detail_request_install_packages),
                        getString(R.string.hint_remove_untrusted_install_app),
                        appInfo.packageName,
                        packageManager.getApplicationIcon(appInfo),
                        true,
                        true
                ));
            } catch (Exception ignored) {
                // Ignore packages that cannot be fully resolved.
            }
        }

        return new ScanSection(getString(R.string.section_install_trust), getString(R.string.summary_install_trust, reviewed), findings);
    }

    ScanSection scanSensitiveServiceRisk() {
        PackageManager packageManager = getPackageManager();
        List<ThreatFinding> findings = new ArrayList<>();
        int reviewed = 0;

        for (ApplicationInfo appInfo : getInstalledApplicationsCompat()) {
            if (!isScannableUserApp(appInfo)) {
                continue;
            }
            reviewed++;
            try {
                PackageInfo packageInfo = getPackageInfoCompat(
                        appInfo.packageName,
                        PackageManager.GET_PERMISSIONS | PackageManager.GET_SERVICES | PackageManager.GET_RECEIVERS
                );
                List<String> requested = getRequestedPermissions(packageInfo);
                List<String> roles = collectSensitiveServiceRoles(packageInfo);
                if (roles.isEmpty()) {
                    continue;
                }

                String installer = getInstallerPackage(appInfo.packageName);
                boolean suspiciousInstaller = TextUtils.isEmpty(installer) || installer.toLowerCase(Locale.US).contains("unknown");
                boolean overlay = requested.contains("android.permission.SYSTEM_ALERT_WINDOW");
                boolean accessibility = requested.contains("android.permission.BIND_ACCESSIBILITY_SERVICE");
                boolean bootPersistence = hasBootPersistenceReceiver(packageInfo, requested);
                int highRisk = countHighRiskPermissions(requested);

                int riskSignals = 0;
                if (roles.size() >= 2) {
                    riskSignals++;
                }
                if (suspiciousInstaller) {
                    riskSignals++;
                }
                if (overlay) {
                    riskSignals++;
                }
                if (accessibility) {
                    riskSignals++;
                }
                if (bootPersistence) {
                    riskSignals++;
                }
                if (highRisk >= 3) {
                    riskSignals++;
                }
                if (containsSuspiciousKeyword(appInfo.packageName)
                        || containsSuspiciousKeyword(packageManager.getApplicationLabel(appInfo).toString())) {
                    riskSignals++;
                }

                if (riskSignals < 2) {
                    continue;
                }

                List<String> reasons = new ArrayList<>(roles);
                if (suspiciousInstaller) {
                    reasons.add(getString(R.string.reason_unknown_installer));
                }
                if (overlay) {
                    reasons.add(getString(R.string.reason_overlay));
                }
                if (accessibility) {
                    reasons.add(getString(R.string.reason_accessibility_on));
                }
                if (bootPersistence) {
                    reasons.add(getString(R.string.reason_boot_start));
                }
                if (highRisk >= 3) {
                    reasons.add(getString(R.string.reason_high_risk_permissions));
                }

                findings.add(new ThreatFinding(
                        packageManager.getApplicationLabel(appInfo).toString(),
                        getString(R.string.finding_sensitive_service_body),
                        getString(R.string.attack_type_sensitive_service),
                        appInfo.packageName,
                        TextUtils.join(", ", reasons),
                        getString(R.string.hint_review_sensitive_service_app),
                        appInfo.packageName,
                        packageManager.getApplicationIcon(appInfo),
                        true,
                        true
                ));
            } catch (Exception ignored) {
                // Ignore packages with incomplete service metadata.
            }
        }

        return new ScanSection(
                getString(R.string.section_sensitive_services),
                getString(R.string.summary_sensitive_services, reviewed),
                findings
        );
    }

    ScanSection scanExposedComponentRisk() {
        PackageManager packageManager = getPackageManager();
        List<ThreatFinding> findings = new ArrayList<>();
        int reviewed = 0;

        for (ApplicationInfo appInfo : getInstalledApplicationsCompat()) {
            if (!isScannableUserApp(appInfo)) {
                continue;
            }
            reviewed++;
            try {
                PackageInfo packageInfo = getPackageInfoCompat(
                        appInfo.packageName,
                        PackageManager.GET_PERMISSIONS
                                | PackageManager.GET_ACTIVITIES
                                | PackageManager.GET_SERVICES
                                | PackageManager.GET_RECEIVERS
                                | PackageManager.GET_PROVIDERS
                );
                List<String> requested = getRequestedPermissions(packageInfo);
                int exportedCount = countExportedComponents(packageInfo.activities)
                        + countExportedComponents(packageInfo.services)
                        + countExportedComponents(packageInfo.receivers)
                        + countExportedComponents(packageInfo.providers);
                int openCount = countUnprotectedExportedComponents(packageInfo.activities)
                        + countUnprotectedExportedComponents(packageInfo.services)
                        + countUnprotectedExportedComponents(packageInfo.receivers)
                        + countUnprotectedExportedComponents(packageInfo.providers);

                boolean overlay = requested.contains("android.permission.SYSTEM_ALERT_WINDOW");
                boolean queryAll = requested.contains(Manifest.permission.QUERY_ALL_PACKAGES);
                boolean bootPersistence = hasBootPersistenceReceiver(packageInfo, requested);
                int highRisk = countHighRiskPermissions(requested);

                int riskSignals = 0;
                if (exportedCount >= 8) {
                    riskSignals++;
                }
                if (openCount >= 4) {
                    riskSignals++;
                }
                if (overlay) {
                    riskSignals++;
                }
                if (queryAll) {
                    riskSignals++;
                }
                if (bootPersistence) {
                    riskSignals++;
                }
                if (highRisk >= 3) {
                    riskSignals++;
                }

                if (riskSignals < 3) {
                    continue;
                }

                findings.add(new ThreatFinding(
                        packageManager.getApplicationLabel(appInfo).toString(),
                        getString(R.string.finding_exposed_components_body),
                        getString(R.string.attack_type_component_surface),
                        appInfo.packageName,
                        getString(R.string.detail_exposed_components, exportedCount, openCount),
                        getString(R.string.hint_review_exposed_components_app),
                        appInfo.packageName,
                        packageManager.getApplicationIcon(appInfo),
                        true,
                        true
                ));
            } catch (Exception ignored) {
                // Ignore packages with restricted component metadata.
            }
        }

        return new ScanSection(
                getString(R.string.section_exposed_components),
                getString(R.string.summary_exposed_components, reviewed),
                findings
        );
    }
}
