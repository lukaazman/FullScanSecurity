package com.example.fullscansecurity.scan;

import android.content.Context;
import android.os.SystemClock;

import androidx.annotation.NonNull;
import androidx.annotation.StringRes;

import com.example.fullscansecurity.R;
import com.example.fullscansecurity.model.ScanSection;
import com.example.fullscansecurity.model.ThreatFinding;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;

/** Runs every check in order; a failing check becomes an "unavailable" finding instead of aborting the scan. */
public final class ScanEngine extends ScanSupport {

    public interface Progress {
        void onStep(int step, int total, @NonNull String label);
    }

    private static final long STEP_PAUSE_MS = 320;

    private static final class Check {
        @StringRes final int title;
        @StringRes final int degradedSummary;
        final Supplier<ScanSection> run;

        Check(@StringRes int title, @StringRes int degradedSummary, Supplier<ScanSection> run) {
            this.title = title;
            this.degradedSummary = degradedSummary;
            this.run = run;
        }
    }

    private final List<Check> checks = new ArrayList<>();

    public ScanEngine(Context base) {
        super(base);
        AppChecks apps = new AppChecks(base);
        SystemChecks system = new SystemChecks(base);
        NetworkChecks network = new NetworkChecks(base);
        DeviceChecks device = new DeviceChecks(base);
        StorageChecks storage = new StorageChecks(base);
        add(R.string.section_apps, R.string.summary_section_apps_degraded, apps::scanInstalledApps);
        add(R.string.section_permissions, R.string.summary_section_permissions_degraded, apps::scanPermissionExposure);
        add(R.string.section_accessibility, R.string.summary_section_accessibility_degraded, system::scanAccessibilityAndAdminAbuse);
        add(R.string.section_network, R.string.summary_section_network_degraded, network::scanNetworkSecurityPosture);
        add(R.string.section_install_trust, R.string.summary_section_install_trust_degraded, apps::scanInstallTrust);
        add(R.string.section_integrity, R.string.summary_section_integrity_degraded, device::scanBootIntegrity);
        add(R.string.section_persistence, R.string.summary_section_persistence_degraded, system::scanNotificationAndOverlayAbuse);
        add(R.string.section_browser_sms_call, R.string.summary_section_default_apps_degraded, system::scanDefaultAppRedirectionRisk);
        add(R.string.section_live_posture, R.string.summary_section_live_posture_degraded, device::scanLivePosture);
        add(R.string.section_input_methods, R.string.summary_section_input_methods_degraded, system::scanInputMethodRisk);
        add(R.string.section_surveillance, R.string.summary_section_surveillance_degraded, system::scanSurveillanceRisk);
        add(R.string.section_device, R.string.summary_section_device_degraded, device::scanDeviceSecurityPosture);
        add(R.string.section_storage, R.string.summary_section_storage_degraded, storage::scanReachableStorageSurfaces);
        add(R.string.section_sensitive_services, R.string.summary_section_sensitive_services_degraded, apps::scanSensitiveServiceRisk);
        add(R.string.section_exposed_components, R.string.summary_section_exposed_components_degraded, apps::scanExposedComponentRisk);
    }

    private void add(@StringRes int title, @StringRes int degraded, Supplier<ScanSection> run) {
        checks.add(new Check(title, degraded, run));
    }

    public int checkCount() {
        return checks.size();
    }

    /** Blocking; call off the main thread. */
    @NonNull
    public List<ScanSection> runAll(@NonNull Progress progress) {
        List<ScanSection> sections = new ArrayList<>();
        for (int i = 0; i < checks.size(); i++) {
            Check check = checks.get(i);
            String title = getString(check.title);
            progress.onStep(i + 1, checks.size(), title);
            sections.add(runSafely(title, getString(check.degradedSummary), check.run));
            SystemClock.sleep(STEP_PAUSE_MS);
        }
        return sections;
    }

    @NonNull
    private ScanSection runSafely(@NonNull String title, @NonNull String fallbackSummary, @NonNull Supplier<ScanSection> check) {
        try {
            return check.get();
        } catch (Throwable throwable) {
            logError("Scan section failed: " + title, throwable);
            List<ThreatFinding> findings = new ArrayList<>();
            findings.add(new ThreatFinding(
                    title + " unavailable",
                    getString(R.string.finding_scan_unavailable_body),
                    getString(R.string.attack_type_scan_stability),
                    title,
                    throwable.getClass().getSimpleName(),
                    getString(R.string.hint_scan_continued),
                    null,
                    null,
                    false,
                    false
            ));
            return new ScanSection(title, fallbackSummary, findings);
        }
    }

    @NonNull
    public static List<ThreatFinding> flattenFindings(@NonNull List<ScanSection> sections) {
        List<ThreatFinding> all = new ArrayList<>();
        for (ScanSection section : sections) {
            all.addAll(section.findings);
        }
        return all;
    }
}
