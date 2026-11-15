package com.example.fullscansecurity.scan;

import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;
import android.text.TextUtils;
import androidx.core.app.NotificationManagerCompat;
import com.example.fullscansecurity.R;
import com.example.fullscansecurity.model.ScanSection;
import com.example.fullscansecurity.model.ThreatFinding;
import java.util.ArrayList;
import java.util.List;

final class DeviceChecks extends ScanSupport {

    DeviceChecks(Context base) {
        super(base);
    }

    ScanSection scanBootIntegrity() {
        PackageManager packageManager = getPackageManager();
        List<ThreatFinding> findings = new ArrayList<>();

        if (Build.TAGS != null && Build.TAGS.contains("test-keys")) {
            findings.add(new ThreatFinding(
                    getString(R.string.finding_test_keys_title),
                    getString(R.string.finding_test_keys_body),
                    getString(R.string.attack_type_integrity),
                    Build.FINGERPRINT,
                    getString(R.string.detail_test_keys),
                    getString(R.string.hint_lower_trust),
                    null,
                    null,
                    false,
                    false
            ));
        }

        if (isProbablyEmulator()) {
            findings.add(new ThreatFinding(
                    getString(R.string.finding_emulator_title),
                    getString(R.string.finding_emulator_body),
                    getString(R.string.attack_type_integrity),
                    Build.MODEL,
                    getString(R.string.detail_emulator_heuristics),
                    getString(R.string.hint_use_physical_device),
                    null,
                    null,
                    false,
                    false
            ));
        }

        if (hasRootBinary()) {
            findings.add(new ThreatFinding(
                    getString(R.string.finding_root_binary_title),
                    getString(R.string.finding_root_binary_body),
                    getString(R.string.attack_type_integrity),
                    getString(R.string.location_filesystem),
                    getString(R.string.detail_root_paths),
                    getString(R.string.hint_review_root_tooling),
                    null,
                    null,
                    false,
                    false
            ));
        }

        String bootState = getSystemPropertyCompat("ro.boot.vbmeta.device_state");
        String flashLocked = getSystemPropertyCompat("ro.boot.flash.locked");
        String verifiedBoot = getSystemPropertyCompat("ro.boot.verifiedbootstate");
        if ("unlocked".equalsIgnoreCase(bootState) || "0".equals(flashLocked)
                || (!TextUtils.isEmpty(verifiedBoot) && !"green".equalsIgnoreCase(verifiedBoot))) {
            findings.add(new ThreatFinding(
                    getString(R.string.finding_boot_integrity_title),
                    getString(R.string.finding_boot_integrity_body),
                    getString(R.string.attack_type_integrity),
                    getString(R.string.location_boot_chain),
                    getString(R.string.detail_boot_integrity_values,
                            safeValue(bootState),
                            safeValue(flashLocked),
                            safeValue(verifiedBoot)),
                    getString(R.string.hint_relock_boot_chain),
                    null,
                    null,
                    false,
                    false
            ));
        }

        for (String rootPackage : ROOT_PACKAGES) {
            if (shouldSkipPackage(rootPackage) || !isPackageInstalled(rootPackage)) {
                continue;
            }
            findings.add(buildPackageFinding(
                    rootPackage,
                    packageManager,
                    getString(R.string.finding_root_management_title),
                    getString(R.string.attack_type_integrity),
                    getString(R.string.finding_root_management_body),
                    getString(R.string.detail_root_management_signature),
                    getString(R.string.hint_remove_root_tooling),
                    true,
                    true
            ));
        }

        return new ScanSection(getString(R.string.section_integrity), getString(R.string.summary_integrity), findings);
    }

    ScanSection scanLivePosture() {
        List<ThreatFinding> findings = new ArrayList<>();

        if (!NotificationManagerCompat.from(this).areNotificationsEnabled()) {
            findings.add(new ThreatFinding(
                    getString(R.string.finding_alerts_muted_title),
                    getString(R.string.finding_alerts_muted_body),
                    getString(R.string.attack_type_live_posture),
                    getPackageName(),
                    getString(R.string.detail_notifications_disabled),
                    getString(R.string.hint_enable_notifications),
                    null,
                    null,
                    false,
                    false
            ));
        }

        if (!hasUsageStatsAccess()) {
            findings.add(new ThreatFinding(
                    getString(R.string.finding_usage_access_missing_title),
                    getString(R.string.finding_usage_access_missing_body),
                    getString(R.string.attack_type_live_posture),
                    getPackageName(),
                    getString(R.string.detail_usage_access_missing),
                    getString(R.string.hint_grant_usage_access),
                    null,
                    null,
                    false,
                    false
            ));
        }

        if (!isIgnoringBatteryOptimizations(getPackageName())) {
            findings.add(new ThreatFinding(
                    getString(R.string.finding_background_sleep_title),
                    getString(R.string.finding_background_sleep_body),
                    getString(R.string.attack_type_live_posture),
                    getPackageName(),
                    getString(R.string.detail_battery_optimized),
                    getString(R.string.hint_ignore_optimization_optional),
                    null,
                    null,
                    false,
                    false
            ));
        }

        return new ScanSection(getString(R.string.section_live_posture), getString(R.string.summary_live_posture), findings);
    }

    ScanSection scanDeviceSecurityPosture() {
        List<ThreatFinding> findings = new ArrayList<>();

        if (isDeveloperOptionsEnabled()) {
            findings.add(new ThreatFinding(
                    getString(R.string.finding_dev_options_title),
                    getString(R.string.finding_dev_options_body),
                    getString(R.string.attack_type_hardening),
                    getString(R.string.location_system),
                    getString(R.string.detail_dev_options),
                    getString(R.string.hardening_hint),
                    null,
                    null,
                    false,
                    false
            ));
        }

        if (isAdbEnabled()) {
            findings.add(new ThreatFinding(
                    getString(R.string.finding_adb_title),
                    getString(R.string.finding_adb_body),
                    getString(R.string.attack_type_remote),
                    getString(R.string.location_system),
                    getString(R.string.detail_adb),
                    getString(R.string.hardening_hint),
                    null,
                    null,
                    false,
                    false
            ));
        }

        if (!isDeviceSecure()) {
            findings.add(new ThreatFinding(
                    getString(R.string.finding_lock_title),
                    getString(R.string.finding_lock_body),
                    getString(R.string.attack_type_hardening),
                    getString(R.string.location_system),
                    getString(R.string.detail_lock),
                    getString(R.string.lock_hint),
                    null,
                    null,
                    false,
                    false
            ));
        }

        return new ScanSection(getString(R.string.section_device), getString(R.string.summary_device), findings);
    }
}
