package com.example.fullscansecurity;

import android.Manifest;
import android.annotation.SuppressLint;
import android.app.AppOpsManager;
import android.app.KeyguardManager;
import android.app.admin.DevicePolicyManager;
import android.content.ActivityNotFoundException;
import android.content.ComponentName;
import android.content.ContentResolver;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.ProxyInfo;
import android.graphics.Typeface;
import android.graphics.drawable.Drawable;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.os.Handler;
import android.os.Looper;
import android.os.PowerManager;
import android.os.SystemClock;
import android.provider.MediaStore;
import android.provider.Settings;
import android.provider.Telephony;
import android.text.TextUtils;
import android.util.Log;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.CheckBox;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;

import androidx.activity.EdgeToEdge;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.NotificationManagerCompat;
import androidx.core.content.ContextCompat;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;
import androidx.core.widget.NestedScrollView;

import com.google.android.material.button.MaterialButton;
import com.google.android.material.dialog.MaterialAlertDialogBuilder;
import com.google.android.material.progressindicator.CircularProgressIndicator;
import com.google.android.material.progressindicator.LinearProgressIndicator;

import java.io.File;
import java.lang.reflect.Method;
import java.security.KeyStore;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class MainActivity extends AppCompatActivity {

    private static final String TAG = "FullScanSecurity";

    private static final int TOTAL_SCAN_STEPS = 13;

    private static final List<String> HIGH_RISK_PERMISSIONS = Arrays.asList(
            Manifest.permission.READ_SMS,
            Manifest.permission.RECEIVE_SMS,
            Manifest.permission.SEND_SMS,
            Manifest.permission.READ_CALL_LOG,
            Manifest.permission.WRITE_CALL_LOG,
            Manifest.permission.READ_CONTACTS,
            Manifest.permission.RECORD_AUDIO,
            Manifest.permission.CAMERA,
            Manifest.permission.REQUEST_DELETE_PACKAGES,
            Manifest.permission.REQUEST_INSTALL_PACKAGES,
            Manifest.permission.QUERY_ALL_PACKAGES,
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.BIND_ACCESSIBILITY_SERVICE"
    );

    private static final List<String> SUSPICIOUS_KEYWORDS = Arrays.asList(
            "trojan", "spy", "keylog", "inject", "overlay", "stealer",
            "hack", "mod", "cracker", "rat", "miner", "dropper", "loader"
    );

    private static final List<String> ROOT_PACKAGES = Arrays.asList(
            "com.topjohnwu.magisk",
            "eu.chainfire.supersu",
            "com.koushikdutta.superuser",
            "com.thirdparty.superuser",
            "com.kingroot.kinguser"
    );

    private static final List<String> ROOT_PATHS = Arrays.asList(
            "/system/bin/su",
            "/system/xbin/su",
            "/sbin/su",
            "/system/bin/.ext/su",
            "/system/usr/we-need-root/su",
            "/system/app/Superuser.apk",
            "/cache/magisk.log",
            "/data/adb/magisk"
    );

    private static final List<String> KNOWN_BROWSER_PACKAGES = Arrays.asList(
            "com.android.chrome",
            "org.mozilla.firefox",
            "com.microsoft.emmx",
            "com.brave.browser",
            "com.opera.browser",
            "com.sec.android.app.sbrowser",
            "com.duckduckgo.mobile.android",
            "com.vivaldi.browser"
    );

    private final ExecutorService scanExecutor = Executors.newSingleThreadExecutor();
    private final Handler mainHandler = new Handler(Looper.getMainLooper());
    private final ArrayDeque<String> removalQueue = new ArrayDeque<>();

    private LinearLayout homeScreen;
    private LinearLayout scanScreen;
    private NestedScrollView summaryScreen;
    private NestedScrollView reportScreen;
    private NestedScrollView removalScreen;
    private MaterialButton startScanButton;
    private MaterialButton viewReportButton;
    private MaterialButton reportPrimaryButton;
    private MaterialButton removeSelectedButton;
    private MaterialButton removalBackButton;
    private TextView currentScanLabel;
    private TextView scanCounter;
    private TextView scanFootnote;
    private LinearProgressIndicator linearProgress;
    private CircularProgressIndicator circularProgress;
    private TextView summaryTitle;
    private TextView summaryBody;
    private LinearLayout summaryFindingsContainer;
    private LinearLayout reportSectionsContainer;
    private LinearLayout removalThreatsContainer;

    private ActivityResultLauncher<String[]> permissionLauncher;
    private ActivityResultLauncher<Intent> usageAccessLauncher;
    private ActivityResultLauncher<Intent> uninstallLauncher;

    private boolean pendingScanRequest;
    private boolean scanInProgress;
    private List<ScanSection> lastSections = new ArrayList<>();
    private List<ThreatFinding> lastThreats = new ArrayList<>();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        EdgeToEdge.enable(this);
        setContentView(R.layout.activity_main);
        bindViews();
        setupWindowInsets();
        registerLaunchers();
        setupActions();
        showHomeScreen();
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (pendingScanRequest && !scanInProgress && hasUsageStatsAccess()) {
            startScan();
        }
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        scanExecutor.shutdownNow();
    }

    private void bindViews() {
        homeScreen = findViewById(R.id.homeScreen);
        scanScreen = findViewById(R.id.scanScreen);
        summaryScreen = findViewById(R.id.summaryScreen);
        reportScreen = findViewById(R.id.reportScreen);
        removalScreen = findViewById(R.id.removalScreen);
        startScanButton = findViewById(R.id.startScanButton);
        viewReportButton = findViewById(R.id.viewReportButton);
        reportPrimaryButton = findViewById(R.id.reportPrimaryButton);
        removeSelectedButton = findViewById(R.id.removeSelectedButton);
        removalBackButton = findViewById(R.id.removalBackButton);
        currentScanLabel = findViewById(R.id.currentScanLabel);
        scanCounter = findViewById(R.id.scanCounter);
        scanFootnote = findViewById(R.id.scanFootnote);
        linearProgress = findViewById(R.id.linearProgress);
        circularProgress = findViewById(R.id.circularProgress);
        summaryTitle = findViewById(R.id.summaryTitle);
        summaryBody = findViewById(R.id.summaryBody);
        summaryFindingsContainer = findViewById(R.id.summaryFindingsContainer);
        reportSectionsContainer = findViewById(R.id.reportSectionsContainer);
        removalThreatsContainer = findViewById(R.id.removalThreatsContainer);
    }

    private void setupWindowInsets() {
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main), (view, insets) -> {
            Insets systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars());
            view.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom);
            return insets;
        });
    }

    private void registerLaunchers() {
        permissionLauncher = registerForActivityResult(
                new ActivityResultContracts.RequestMultiplePermissions(),
                result -> continueAfterPermissionStep()
        );

        usageAccessLauncher = registerForActivityResult(
                new ActivityResultContracts.StartActivityForResult(),
                result -> {
                    if (pendingScanRequest && !scanInProgress) {
                        startScan();
                    }
                }
        );

        uninstallLauncher = registerForActivityResult(
                new ActivityResultContracts.StartActivityForResult(),
                result -> launchNextRemovalStep()
        );
    }

    private void setupActions() {
        startScanButton.setOnClickListener(v -> requestAccessAndStart());
        viewReportButton.setOnClickListener(v -> showDetailedReport());
        reportPrimaryButton.setOnClickListener(v -> {
            if (!hasRemovableThreats()) {
                showHomeScreen();
            } else {
                showRemovalScreen();
            }
        });
        removeSelectedButton.setOnClickListener(v -> startRemovalFlow());
        removalBackButton.setOnClickListener(v -> showDetailedReport());
    }

    private void requestAccessAndStart() {
        pendingScanRequest = true;
        String[] permissions = getRuntimePermissions();
        if (permissions.length > 0 && !hasAllRuntimePermissions(permissions)) {
            permissionLauncher.launch(permissions);
            return;
        }
        continueAfterPermissionStep();
    }

    private void continueAfterPermissionStep() {
        if (hasUsageStatsAccess()) {
            startScan();
            return;
        }

        new MaterialAlertDialogBuilder(this)
                .setTitle(R.string.permission_title)
                .setMessage(R.string.permission_message)
                .setPositiveButton(R.string.open_settings, (dialog, which) ->
                        usageAccessLauncher.launch(new Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS)))
                .setNegativeButton(R.string.continue_limited, (dialog, which) -> startScan())
                .show();
    }

    private void startScan() {
        if (scanInProgress) {
            return;
        }
        pendingScanRequest = false;
        scanInProgress = true;
        showScanScreen();
        scanExecutor.execute(() -> {
            List<ScanSection> sections = runFullScan();
            List<ThreatFinding> findings = flattenFindings(sections);
            mainHandler.post(() -> finishScan(sections, findings));
        });
    }

    private List<ScanSection> runFullScan() {
        List<ScanSection> sections = new ArrayList<>();
        int totalSteps = TOTAL_SCAN_STEPS;

        updateScanProgress(1, totalSteps, getString(R.string.section_apps));
        sections.add(runSectionSafely(getString(R.string.section_apps), "App scan degraded.", this::scanInstalledApps));
        SystemClock.sleep(320);

        updateScanProgress(2, totalSteps, getString(R.string.section_permissions));
        sections.add(runSectionSafely(getString(R.string.section_permissions), "Permission scan degraded.", this::scanPermissionExposure));
        SystemClock.sleep(320);

        updateScanProgress(3, totalSteps, getString(R.string.section_accessibility));
        sections.add(runSectionSafely(getString(R.string.section_accessibility), "Accessibility scan degraded.", this::scanAccessibilityAndAdminAbuse));
        SystemClock.sleep(320);

        updateScanProgress(4, totalSteps, "Network / DNS / VPN");
        sections.add(runSectionSafely("Network / DNS / VPN", "Network scan degraded.", this::scanNetworkSecurityPosture));
        SystemClock.sleep(320);

        updateScanProgress(5, totalSteps, "Install trust");
        sections.add(runSectionSafely("Install trust", "Install trust scan degraded.", this::scanInstallTrust));
        SystemClock.sleep(320);

        updateScanProgress(6, totalSteps, "Boot / integrity");
        sections.add(runSectionSafely("Boot / integrity", "Integrity scan degraded.", this::scanBootIntegrity));
        SystemClock.sleep(320);

        updateScanProgress(7, totalSteps, "Notification / overlay");
        sections.add(runSectionSafely("Notification / overlay", "Persistence scan degraded.", this::scanNotificationAndOverlayAbuse));
        SystemClock.sleep(320);

        updateScanProgress(8, totalSteps, "Browser / SMS / call");
        sections.add(runSectionSafely("Browser / SMS / call", "Default-app scan degraded.", this::scanDefaultAppRedirectionRisk));
        SystemClock.sleep(320);

        updateScanProgress(9, totalSteps, "Live posture");
        sections.add(runSectionSafely("Live posture", "Live posture scan degraded.", this::scanLivePosture));
        SystemClock.sleep(320);

        updateScanProgress(10, totalSteps, "Input methods");
        sections.add(runSectionSafely("Input methods", "Input-method scan degraded.", this::scanInputMethodRisk));
        SystemClock.sleep(320);

        updateScanProgress(11, totalSteps, "Surveillance risk");
        sections.add(runSectionSafely("Surveillance risk", "Surveillance scan degraded.", this::scanSurveillanceRisk));
        SystemClock.sleep(320);

        updateScanProgress(12, totalSteps, getString(R.string.section_device));
        sections.add(runSectionSafely(getString(R.string.section_device), "Device posture scan degraded.", this::scanDeviceSecurityPosture));
        SystemClock.sleep(320);

        updateScanProgress(13, totalSteps, getString(R.string.section_storage));
        sections.add(runSectionSafely(getString(R.string.section_storage), "Storage scan degraded.", this::scanReachableStorageSurfaces));
        SystemClock.sleep(380);

        return sections;
    }

    private void updateScanProgress(int step, int totalSteps, @NonNull String label) {
        mainHandler.post(() -> {
            currentScanLabel.setText(getString(R.string.currently_scanning_prefix) + " " + label);
            scanCounter.setText(step + " / " + totalSteps);
            linearProgress.setMax(totalSteps);
            linearProgress.setProgressCompat(step, true);
            scanFootnote.setText(R.string.scan_footer);
        });
    }

    private void finishScan(@NonNull List<ScanSection> sections, @NonNull List<ThreatFinding> threats) {
        scanInProgress = false;
        lastSections = sections;
        lastThreats = threats;
        renderSummary(threats);
        renderDetailedReport(sections, threats);
        renderRemovalList();
        showSummaryScreen(!threats.isEmpty());
    }

    private ScanSection scanInstalledApps() {
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
                    reasons.add("Unknown source");
                }

                if ((appInfo.flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0) {
                    riskScore += 2;
                    reasons.add("Debug build");
                }

                if (containsSuspiciousKeyword(label) || containsSuspiciousKeyword(appInfo.packageName)) {
                    riskScore += 1;
                    reasons.add("Suspicious name");
                }

                if (countHighRiskPermissions(requestedPermissions) >= 4) {
                    riskScore += 2;
                    reasons.add("High-risk permissions");
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

    private ScanSection scanPermissionExposure() {
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

    private ScanSection scanAccessibilityAndAdminAbuse() {
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
                    reasons.add("Accessibility on");
                }
                if (admin) {
                    reasons.add("Admin active");
                }
                if (overlay) {
                    reasons.add("Overlay access");
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

    private ScanSection scanNetworkSecurityPosture() {
        PackageManager packageManager = getPackageManager();
        List<ThreatFinding> findings = new ArrayList<>();

        try {
            String privateDnsMode = Settings.Global.getString(getContentResolver(), "private_dns_mode");
            String privateDnsHost = Settings.Global.getString(getContentResolver(), "private_dns_specifier");
            if (TextUtils.isEmpty(privateDnsMode) || "off".equalsIgnoreCase(privateDnsMode)) {
                findings.add(new ThreatFinding(
                        "Private DNS off",
                        "DNS traffic is not hardened.",
                        "DNS posture",
                        "Network settings",
                        "private_dns_mode=" + safeValue(privateDnsMode),
                        "Use automatic or a trusted provider.",
                        null,
                        null,
                        false,
                        false
                ));
            } else if ("hostname".equalsIgnoreCase(privateDnsMode) && !TextUtils.isEmpty(privateDnsHost)
                    && !isTrustedPrivateDnsHost(privateDnsHost)) {
                findings.add(new ThreatFinding(
                        "Custom Private DNS",
                        "A custom DNS host is active.",
                        "DNS posture",
                        privateDnsHost,
                        "Private DNS host is not in the trusted allowlist.",
                        "Verify the resolver owner.",
                        null,
                        null,
                        false,
                        false
                ));
            }
        } catch (Exception e) {
            Log.w(TAG, "Private DNS check failed", e);
        }

        try {
            int userCaCount = getUserInstalledCaCount();
            if (userCaCount > 0) {
                findings.add(new ThreatFinding(
                        "User CA certificates found",
                        "User-added CA certs can intercept traffic.",
                        "TLS trust surface",
                        "System trust store",
                        userCaCount + " user CA aliases detected.",
                        "Review user-installed credentials in security settings.",
                        null,
                        null,
                        false,
                        false
                ));
            }
        } catch (Exception e) {
            Log.w(TAG, "User CA scan failed", e);
        }

        try {
            ProxyInfo proxyInfo = getDefaultProxyInfo();
            if (proxyInfo != null && !TextUtils.isEmpty(proxyInfo.getHost())) {
                findings.add(new ThreatFinding(
                        "Proxy profile active",
                        "Traffic may be routed through a proxy.",
                        "Proxy posture",
                        proxyInfo.getHost() + ":" + proxyInfo.getPort(),
                        "Default proxy is configured.",
                        "Remove it if you did not set it.",
                        null,
                        null,
                        false,
                        false
                ));
            }
        } catch (Exception e) {
            Log.w(TAG, "Proxy check failed", e);
        }

        try {
            String alwaysOnVpnPackage = getAlwaysOnVpnPackage();
            if (!TextUtils.isEmpty(alwaysOnVpnPackage) && !shouldSkipPackage(alwaysOnVpnPackage)) {
                findings.add(buildPackageFinding(
                        alwaysOnVpnPackage,
                        packageManager,
                        "Always-on VPN active",
                        "VPN posture",
                        "An always-on VPN is configured.",
                        "Always-on VPN package: " + alwaysOnVpnPackage,
                        "Review this VPN if you did not choose it.",
                        true,
                        true
                ));
            } else if (isVpnActive()) {
                findings.add(new ThreatFinding(
                        "VPN transport active",
                        "A VPN is connected.",
                        "VPN posture",
                        "Active network",
                        "NetworkCapabilities reports VPN transport.",
                        "Verify the VPN provider.",
                        null,
                        null,
                        false,
                        false
                ));
            }
        } catch (Exception e) {
            Log.w(TAG, "VPN check failed", e);
        }

        return new ScanSection("Network / DNS / VPN", "Checked DNS, VPN, proxy and user trust store.", findings);
    }

    private ScanSection runSectionSafely(
            @NonNull String title,
            @NonNull String fallbackSummary,
            @NonNull ScanSectionSupplier supplier
    ) {
        try {
            return supplier.get();
        } catch (Throwable throwable) {
            Log.e(TAG, "Scan section failed: " + title, throwable);
            List<ThreatFinding> findings = new ArrayList<>();
            findings.add(new ThreatFinding(
                    title + " unavailable",
                    "This check could not finish on this device.",
                    "Scan stability",
                    title,
                    throwable.getClass().getSimpleName(),
                    "The app kept scanning the remaining sections.",
                    null,
                    null,
                    false,
                    false
            ));
            return new ScanSection(title, fallbackSummary, findings);
        }
    }

    private ScanSection scanInstallTrust() {
        PackageManager packageManager = getPackageManager();
        List<ThreatFinding> findings = new ArrayList<>();
        int reviewed = 0;

        if (Settings.Global.getInt(getContentResolver(), "package_verifier_enable", 1) == 0) {
            findings.add(new ThreatFinding(
                    "Package verifier off",
                    "Install verification is disabled.",
                    "Install trust",
                    "System settings",
                    "PACKAGE_VERIFIER_ENABLE=0",
                    "Turn install verification back on.",
                    null,
                    null,
                    false,
                    false
            ));
        }

        if (Settings.Global.getInt(getContentResolver(), "verifier_verify_adb_installs", 1) == 0) {
            findings.add(new ThreatFinding(
                    "ADB verifier off",
                    "ADB installs are not verified.",
                    "Install trust",
                    "System settings",
                    "verifier_verify_adb_installs=0",
                    "Re-enable ADB install verification.",
                    null,
                    null,
                    false,
                    false
            ));
        }

        if (!isPackageInstalled("com.google.android.gms")) {
            findings.add(new ThreatFinding(
                    "Play services missing",
                    "Play Protect state cannot be confirmed.",
                    "Install trust",
                    "Google services",
                    "com.google.android.gms not found.",
                    "Use another trust source if Play Protect is absent.",
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
                        "App can request unknown installs.",
                        "Install trust",
                        appInfo.packageName,
                        "REQUEST_INSTALL_PACKAGES present.",
                        "Remove it if you do not trust its install path.",
                        appInfo.packageName,
                        packageManager.getApplicationIcon(appInfo),
                        true,
                        true
                ));
            } catch (Exception ignored) {
                // Ignore packages that cannot be fully resolved.
            }
        }

        return new ScanSection("Install trust", reviewed + " apps checked for install trust signals.", findings);
    }

    private ScanSection scanBootIntegrity() {
        PackageManager packageManager = getPackageManager();
        List<ThreatFinding> findings = new ArrayList<>();

        if (Build.TAGS != null && Build.TAGS.contains("test-keys")) {
            findings.add(new ThreatFinding(
                    "Test-keys build",
                    "Firmware uses test-keys.",
                    "Integrity",
                    Build.FINGERPRINT,
                    "Build.TAGS contains test-keys.",
                    "Treat the device as lower trust.",
                    null,
                    null,
                    false,
                    false
            ));
        }

        if (isProbablyEmulator()) {
            findings.add(new ThreatFinding(
                    "Emulator detected",
                    "This device looks virtualized.",
                    "Integrity",
                    Build.MODEL,
                    "Build fingerprint and hardware match emulator heuristics.",
                    "Use a physical device for stronger assurance.",
                    null,
                    null,
                    false,
                    false
            ));
        }

        if (hasRootBinary()) {
            findings.add(new ThreatFinding(
                    "Root binary found",
                    "Root artifacts were detected.",
                    "Integrity",
                    "Filesystem",
                    "Known su or Magisk paths exist.",
                    "Review root tooling or firmware changes.",
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
                    "Boot integrity weakened",
                    "Bootloader or verified boot looks weakened.",
                    "Integrity",
                    "Boot chain",
                    "device_state=" + safeValue(bootState) + ", flash.locked=" + safeValue(flashLocked)
                            + ", verifiedbootstate=" + safeValue(verifiedBoot),
                    "Re-lock the boot chain if this is unexpected.",
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
                    "Root management app",
                    "Integrity",
                    "Known root management tooling is installed.",
                    "Installed package matches a root app signature.",
                    "Remove it if the device should stay stock.",
                    true,
                    true
            ));
        }

        return new ScanSection("Boot / integrity", "Checked root, emulator and verified-boot indicators.", findings);
    }

    private ScanSection scanNotificationAndOverlayAbuse() {
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
                    reasons.add("Notification access");
                }
                if (overlay) {
                    reasons.add("Overlay");
                }
                if (bootPersistence) {
                    reasons.add("Boot start");
                }
                if (batteryBypass) {
                    reasons.add("Battery bypass");
                }

                findings.add(new ThreatFinding(
                        packageManager.getApplicationLabel(appInfo).toString(),
                        "App holds persistence or interception privileges.",
                        "Persistence",
                        appInfo.packageName,
                        TextUtils.join(", ", reasons),
                        "Disable the risky capabilities if the app is not trusted.",
                        appInfo.packageName,
                        packageManager.getApplicationIcon(appInfo),
                        true,
                        true
                ));
            } catch (Exception ignored) {
                // Ignore packages with unavailable manifest metadata.
            }
        }

        return new ScanSection("Notification / overlay", "Checked listeners, overlays, boot start and battery bypass.", findings);
    }

    private ScanSection scanDefaultAppRedirectionRisk() {
        PackageManager packageManager = getPackageManager();
        List<ThreatFinding> findings = new ArrayList<>();
        Set<String> accessibilityPackages = getEnabledAccessibilityPackages();

        findings.addAll(buildDefaultRoleFindings(packageManager, "Default SMS", getDefaultSmsPackage(), accessibilityPackages));
        findings.addAll(buildDefaultRoleFindings(packageManager, "Default dialer", getDefaultDialerPackage(), accessibilityPackages));
        findings.addAll(buildDefaultRoleFindings(packageManager, "Default browser", getDefaultBrowserPackage(), accessibilityPackages));

        return new ScanSection("Browser / SMS / call", "Checked default communication and browsing handlers.", findings);
    }

    private ScanSection scanLivePosture() {
        List<ThreatFinding> findings = new ArrayList<>();

        if (!NotificationManagerCompat.from(this).areNotificationsEnabled()) {
            findings.add(new ThreatFinding(
                    "Alerts muted",
                    "This app cannot post security alerts.",
                    "Live posture",
                    getPackageName(),
                    "Notifications are disabled for the app.",
                    "Enable notifications if you want ongoing warnings.",
                    null,
                    null,
                    false,
                    false
            ));
        }

        if (!hasUsageStatsAccess()) {
            findings.add(new ThreatFinding(
                    "Usage access missing",
                    "Live posture checks are reduced.",
                    "Live posture",
                    getPackageName(),
                    "Usage stats access is not granted.",
                    "Grant usage access for broader posture checks.",
                    null,
                    null,
                    false,
                    false
            ));
        }

        if (!isIgnoringBatteryOptimizations(getPackageName())) {
            findings.add(new ThreatFinding(
                    "Background checks may sleep",
                    "Battery optimization can delay live checks.",
                    "Live posture",
                    getPackageName(),
                    "App is still battery optimized.",
                    "Ignore optimization only if you want stronger background alerts.",
                    null,
                    null,
                    false,
                    false
            ));
        }

        return new ScanSection("Live posture", "Checked whether live guard rails can keep warning you.", findings);
    }

    private ScanSection scanInputMethodRisk() {
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
                    reasons.add("Default keyboard");
                }
                if (internet) {
                    reasons.add("Network access");
                }
                if (contacts) {
                    reasons.add("Contacts access");
                }
                if (microphone) {
                    reasons.add("Microphone");
                }
                if (overlay) {
                    reasons.add("Overlay");
                }

                if (defaultIme || contacts || microphone || overlay) {
                    findings.add(new ThreatFinding(
                            packageManager.getApplicationLabel(appInfo).toString(),
                            "Keyboard app has elevated data access.",
                            "Keylogger risk",
                            packageName,
                            TextUtils.join(", ", reasons),
                            "Review or replace the keyboard if you do not trust it.",
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

        return new ScanSection("Input methods", "Checked enabled keyboards and default input method.", findings);
    }

    private ScanSection scanSurveillanceRisk() {
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

                maybeAddPermissionLabel(requested, Manifest.permission.RECORD_AUDIO, "Mic", matched);
                maybeAddPermissionLabel(requested, Manifest.permission.CAMERA, "Camera", matched);
                maybeAddPermissionLabel(requested, Manifest.permission.ACCESS_FINE_LOCATION, "Location", matched);
                maybeAddPermissionLabel(requested, Manifest.permission.READ_CONTACTS, "Contacts", matched);
                maybeAddPermissionLabel(requested, Manifest.permission.READ_SMS, "SMS", matched);
                maybeAddPermissionLabel(requested, Manifest.permission.READ_CALL_LOG, "Call log", matched);
                maybeAddPermissionLabel(requested, Manifest.permission.QUERY_ALL_PACKAGES, "All apps", matched);
                maybeAddPermissionLabel(requested, "android.permission.SYSTEM_ALERT_WINDOW", "Overlay", matched);

                if (matched.size() >= 4) {
                    findings.add(new ThreatFinding(
                            packageManager.getApplicationLabel(appInfo).toString(),
                            "App has a stalkingware-like data profile.",
                            "Surveillance risk",
                            appInfo.packageName,
                            TextUtils.join(", ", matched),
                            "Review the app if it does not clearly need this access.",
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

        return new ScanSection("Surveillance risk", reviewed + " apps checked for stalkingware-style access.", findings);
    }

    private ScanSection scanDeviceSecurityPosture() {
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

    private ScanSection scanReachableStorageSurfaces() {
        List<ThreatFinding> findings = new ArrayList<>();
        int inspectedEntries = 0;

        File downloadsDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS);
        if (downloadsDir != null && downloadsDir.exists() && downloadsDir.canRead()) {
            inspectedEntries += inspectDirectory(downloadsDir, findings, 2);
        }

        File[] externalDirs = getExternalFilesDirs(null);
        if (externalDirs != null) {
            for (File dir : externalDirs) {
                if (dir != null && dir.exists() && dir.canRead()) {
                    inspectedEntries += inspectDirectory(dir, findings, 1);
                }
            }
        }

        inspectedEntries += inspectMediaStoreDownloads(findings);
        String summary = inspectedEntries + " " + getString(R.string.summary_storage);
        return new ScanSection(getString(R.string.section_storage), summary, findings);
    }

    private int inspectDirectory(@NonNull File directory, @NonNull List<ThreatFinding> findings, int depth) {
        if (depth < 0) {
            return 0;
        }
        File[] files = directory.listFiles();
        if (files == null) {
            return 0;
        }

        int inspected = 0;
        for (File file : files) {
            inspected++;
            if (file.isDirectory()) {
                inspected += inspectDirectory(file, findings, depth - 1);
                continue;
            }

            String lowerName = file.getName().toLowerCase(Locale.US);
            if (lowerName.endsWith(".apk") || lowerName.endsWith(".xapk") || lowerName.endsWith(".apks")
                    || lowerName.endsWith(".jar") || lowerName.endsWith(".dex") || lowerName.endsWith(".sh")) {
                findings.add(new ThreatFinding(
                        file.getName(),
                        getString(R.string.finding_storage_body),
                        getString(R.string.attack_type_storage),
                        file.getAbsolutePath(),
                        file.getAbsolutePath(),
                        getString(R.string.storage_hint),
                        null,
                        null,
                        false,
                        false
                ));
            }
        }
        return inspected;
    }

    private int inspectMediaStoreDownloads(@NonNull List<ThreatFinding> findings) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            return 0;
        }

        ContentResolver resolver = getContentResolver();
        String[] projection = {
                MediaStore.Downloads.DISPLAY_NAME,
                MediaStore.Downloads.RELATIVE_PATH
        };
        int inspected = 0;

        try (android.database.Cursor cursor = resolver.query(
                MediaStore.Downloads.EXTERNAL_CONTENT_URI,
                projection,
                null,
                null,
                null
        )) {
            if (cursor == null) {
                return 0;
            }

            int nameIndex = cursor.getColumnIndexOrThrow(MediaStore.Downloads.DISPLAY_NAME);
            int pathIndex = cursor.getColumnIndexOrThrow(MediaStore.Downloads.RELATIVE_PATH);
            while (cursor.moveToNext()) {
                inspected++;
                String name = cursor.getString(nameIndex);
                String path = cursor.getString(pathIndex);
                String lowerName = name == null ? "" : name.toLowerCase(Locale.US);
                if (lowerName.endsWith(".apk") || lowerName.endsWith(".xapk") || lowerName.endsWith(".jar")) {
                    findings.add(new ThreatFinding(
                            name,
                            getString(R.string.finding_download_body),
                            getString(R.string.attack_type_downloads),
                            path,
                            path,
                            getString(R.string.downloads_hint),
                            null,
                            null,
                            false,
                            false
                    ));
                }
            }
        } catch (SecurityException ignored) {
            // Scoped storage may limit visibility.
        }

        return inspected;
    }

    private List<ApplicationInfo> getInstalledApplicationsCompat() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            return getPackageManager().getInstalledApplications(
                    PackageManager.ApplicationInfoFlags.of(PackageManager.GET_META_DATA));
        }
        return getPackageManager().getInstalledApplications(PackageManager.GET_META_DATA);
    }

    private PackageInfo getPackageInfoCompat(@NonNull String packageName, long flags)
            throws PackageManager.NameNotFoundException {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            return getPackageManager().getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(flags));
        }
        return getPackageManager().getPackageInfo(packageName, (int) flags);
    }

    private boolean isScannableUserApp(@NonNull ApplicationInfo appInfo) {
        boolean system = (appInfo.flags & ApplicationInfo.FLAG_SYSTEM) != 0;
        boolean updatedSystem = (appInfo.flags & ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0;
        if (shouldSkipPackage(appInfo.packageName)) {
            return false;
        }
        if (system || updatedSystem) {
            return isBrowserPackage(appInfo.packageName);
        }
        return true;
    }

    private boolean shouldSkipPackage(@Nullable String packageName) {
        return packageName == null || getPackageName().equals(packageName);
    }

    private List<String> getRequestedPermissions(@NonNull PackageInfo packageInfo) {
        if (packageInfo.requestedPermissions == null) {
            return Collections.emptyList();
        }
        return Arrays.asList(packageInfo.requestedPermissions);
    }

    private int countHighRiskPermissions(@NonNull List<String> requestedPermissions) {
        int count = 0;
        for (String permission : HIGH_RISK_PERMISSIONS) {
            if (requestedPermissions.contains(permission)) {
                count++;
            }
        }
        return count;
    }

    private boolean containsSuspiciousKeyword(@NonNull String value) {
        String normalized = value.toLowerCase(Locale.US);
        for (String keyword : SUSPICIOUS_KEYWORDS) {
            if (normalized.contains(keyword)) {
                return true;
            }
        }
        return false;
    }

    private String getInstallerPackage(@NonNull String packageName) {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                String installer = getPackageManager().getInstallSourceInfo(packageName).getInstallingPackageName();
                return installer == null ? "unknown" : installer;
            }
            String installer = getPackageManager().getInstallerPackageName(packageName);
            return installer == null ? "unknown" : installer;
        } catch (Exception ignored) {
            return "unknown";
        }
    }

    private String safeInstallerLabel(@Nullable String installer) {
        if (TextUtils.isEmpty(installer)) {
            return getString(R.string.label_unknown);
        }
        if ("com.android.vending".equals(installer)) {
            return "Google Play";
        }
        return installer;
    }

    private String safeValue(@Nullable String value) {
        return TextUtils.isEmpty(value) ? "unknown" : value;
    }

    private boolean isTrustedPrivateDnsHost(@NonNull String host) {
        String normalized = host.toLowerCase(Locale.US);
        return normalized.contains("dns.google")
                || normalized.contains("one.one.one.one")
                || normalized.contains("cloudflare")
                || normalized.contains("quad9")
                || normalized.contains("nextdns");
    }

    private int getUserInstalledCaCount() {
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidCAStore");
            keyStore.load(null);
            int count = 0;
            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                if (alias != null && alias.startsWith("user:")) {
                    count++;
                }
            }
            return count;
        } catch (Exception ignored) {
            return 0;
        }
    }

    @Nullable
    private ProxyInfo getDefaultProxyInfo() {
        ConnectivityManager connectivityManager = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
        if (connectivityManager == null) {
            return null;
        }
        return connectivityManager.getDefaultProxy();
    }

    private boolean isVpnActive() {
        ConnectivityManager connectivityManager = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
        if (connectivityManager == null) {
            return false;
        }
        Network network = connectivityManager.getActiveNetwork();
        if (network == null) {
            return false;
        }
        NetworkCapabilities capabilities = connectivityManager.getNetworkCapabilities(network);
        return capabilities != null && capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN);
    }

    @Nullable
    private String getAlwaysOnVpnPackage() {
        return Settings.Secure.getString(getContentResolver(), "always_on_vpn_app");
    }

    private boolean isPackageInstalled(@NonNull String packageName) {
        try {
            getPackageManager().getPackageInfo(packageName, 0);
            return true;
        } catch (Exception ignored) {
            return false;
        }
    }

    private boolean isBrowserPackage(@Nullable String packageName) {
        if (TextUtils.isEmpty(packageName)) {
            return false;
        }
        if (KNOWN_BROWSER_PACKAGES.contains(packageName)) {
            return true;
        }
        String defaultBrowser = getDefaultBrowserPackage();
        if (packageName.equals(defaultBrowser)) {
            return true;
        }
        String lower = packageName.toLowerCase(Locale.US);
        return lower.contains("browser") || lower.contains("chrome") || lower.contains("firefox");
    }

    private boolean hasRootBinary() {
        for (String path : ROOT_PATHS) {
            if (new File(path).exists()) {
                return true;
            }
        }
        return false;
    }

    private boolean isProbablyEmulator() {
        return Build.FINGERPRINT.startsWith("generic")
                || Build.FINGERPRINT.toLowerCase(Locale.US).contains("emulator")
                || Build.MODEL.toLowerCase(Locale.US).contains("sdk")
                || Build.HARDWARE.toLowerCase(Locale.US).contains("ranchu")
                || Build.HARDWARE.toLowerCase(Locale.US).contains("goldfish")
                || Build.PRODUCT.toLowerCase(Locale.US).contains("sdk");
    }

    private String getSystemPropertyCompat(@NonNull String key) {
        try {
            Class<?> systemProperties = Class.forName("android.os.SystemProperties");
            Method getMethod = systemProperties.getMethod("get", String.class, String.class);
            Object value = getMethod.invoke(null, key, "");
            return value instanceof String ? (String) value : "";
        } catch (Exception ignored) {
            return "";
        }
    }

    private Set<String> getEnabledNotificationListenerPackages() {
        String enabled = Settings.Secure.getString(getContentResolver(),
                "enabled_notification_listeners");
        if (TextUtils.isEmpty(enabled)) {
            return Collections.emptySet();
        }
        Set<String> packages = new LinkedHashSet<>();
        TextUtils.SimpleStringSplitter splitter = new TextUtils.SimpleStringSplitter(':');
        splitter.setString(enabled);
        while (splitter.hasNext()) {
            ComponentName component = ComponentName.unflattenFromString(splitter.next());
            if (component != null) {
                packages.add(component.getPackageName());
            }
        }
        return packages;
    }

    private boolean hasBootPersistenceReceiver(@NonNull PackageInfo packageInfo, @NonNull List<String> requestedPermissions) {
        return requestedPermissions.contains(Manifest.permission.RECEIVE_BOOT_COMPLETED)
                || (packageInfo.receivers != null && packageInfo.receivers.length > 0);
    }

    private boolean isIgnoringBatteryOptimizations(@NonNull String packageName) {
        PowerManager powerManager = (PowerManager) getSystemService(Context.POWER_SERVICE);
        if (powerManager == null) {
            return false;
        }
        try {
            return powerManager.isIgnoringBatteryOptimizations(packageName);
        } catch (Exception ignored) {
            return false;
        }
    }

    private Set<String> getEnabledInputMethodPackages() {
        String enabled = Settings.Secure.getString(getContentResolver(), Settings.Secure.ENABLED_INPUT_METHODS);
        if (TextUtils.isEmpty(enabled)) {
            return Collections.emptySet();
        }
        Set<String> packages = new LinkedHashSet<>();
        TextUtils.SimpleStringSplitter splitter = new TextUtils.SimpleStringSplitter(':');
        splitter.setString(enabled);
        while (splitter.hasNext()) {
            ComponentName component = ComponentName.unflattenFromString(splitter.next());
            if (component != null) {
                packages.add(component.getPackageName());
            }
        }
        return packages;
    }

    @Nullable
    private String getDefaultInputMethodPackage() {
        String value = Settings.Secure.getString(getContentResolver(), Settings.Secure.DEFAULT_INPUT_METHOD);
        if (TextUtils.isEmpty(value)) {
            return null;
        }
        ComponentName component = ComponentName.unflattenFromString(value);
        return component == null ? null : component.getPackageName();
    }

    private void maybeAddPermissionLabel(
            @NonNull List<String> requested,
            @NonNull String permission,
            @NonNull String label,
            @NonNull List<String> output
    ) {
        if (requested.contains(permission)) {
            output.add(label);
        }
    }

    private List<ThreatFinding> buildDefaultRoleFindings(
            @NonNull PackageManager packageManager,
            @NonNull String roleName,
            @Nullable String packageName,
            @NonNull Set<String> accessibilityPackages
    ) {
        if (TextUtils.isEmpty(packageName) || shouldSkipPackage(packageName)) {
            return Collections.emptyList();
        }

        try {
            ApplicationInfo appInfo = packageManager.getApplicationInfo(packageName, 0);
            if (!isScannableUserApp(appInfo)) {
                return Collections.emptyList();
            }
            PackageInfo packageInfo = getPackageInfoCompat(packageName, PackageManager.GET_PERMISSIONS);
            List<String> requested = getRequestedPermissions(packageInfo);
            String installer = getInstallerPackage(packageName);
            int riskScore = countHighRiskPermissions(requested);
            boolean accessibility = accessibilityPackages.contains(packageName);
            boolean suspiciousInstaller = TextUtils.isEmpty(installer) || installer.toLowerCase(Locale.US).contains("unknown");
            boolean messagingSensitive = requested.contains(Manifest.permission.SEND_SMS)
                    || requested.contains(Manifest.permission.READ_SMS)
                    || requested.contains(Manifest.permission.READ_CALL_LOG)
                    || requested.contains(Manifest.permission.READ_CONTACTS);

            if (!suspiciousInstaller && !accessibility && !messagingSensitive && riskScore < 3
                    && !containsSuspiciousKeyword(packageName)) {
                return Collections.emptyList();
            }

            List<String> reasons = new ArrayList<>();
            if (suspiciousInstaller) {
                reasons.add("Unknown installer");
            }
            if (accessibility) {
                reasons.add("Accessibility on");
            }
            if (messagingSensitive) {
                reasons.add("Sensitive comms access");
            }
            if (riskScore >= 3) {
                reasons.add("High-risk permissions");
            }

            ThreatFinding finding = new ThreatFinding(
                    packageManager.getApplicationLabel(appInfo).toString(),
                    roleName + " app looks risky.",
                    "Default handler risk",
                    packageName,
                    TextUtils.join(", ", reasons),
                    "Review or replace the default app if you do not trust it.",
                    packageName,
                    packageManager.getApplicationIcon(appInfo),
                    true,
                    true
            );
            return Collections.singletonList(finding);
        } catch (Exception ignored) {
            return Collections.emptyList();
        }
    }

    @Nullable
    private String getDefaultSmsPackage() {
        return Telephony.Sms.getDefaultSmsPackage(this);
    }

    @Nullable
    private String getDefaultDialerPackage() {
        Object telecom = getSystemService(Context.TELECOM_SERVICE);
        if (!(telecom instanceof android.telecom.TelecomManager)) {
            return null;
        }
        return ((android.telecom.TelecomManager) telecom).getDefaultDialerPackage();
    }

    @Nullable
    private String getDefaultBrowserPackage() {
        Intent intent = new Intent(Intent.ACTION_VIEW, Uri.parse("https://openai.com"));
        PackageManager.ResolveInfoFlags flags = null;
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                android.content.pm.ResolveInfo info = getPackageManager().resolveActivity(
                        intent,
                        PackageManager.ResolveInfoFlags.of(PackageManager.MATCH_DEFAULT_ONLY)
                );
                return info == null || info.activityInfo == null ? null : info.activityInfo.packageName;
            }
        } catch (Exception ignored) {
            // Fallback below.
        }
        android.content.pm.ResolveInfo info = getPackageManager().resolveActivity(intent, PackageManager.MATCH_DEFAULT_ONLY);
        return info == null || info.activityInfo == null ? null : info.activityInfo.packageName;
    }

    private ThreatFinding buildPackageFinding(
            @NonNull String packageName,
            @NonNull PackageManager packageManager,
            @NonNull String titleOverride,
            @NonNull String attackType,
            @NonNull String description,
            @NonNull String whyFlagged,
            @NonNull String remediationHint,
            boolean removable,
            boolean showIcon
    ) {
        try {
            ApplicationInfo appInfo = packageManager.getApplicationInfo(packageName, 0);
            return new ThreatFinding(
                    titleOverride + ": " + packageManager.getApplicationLabel(appInfo),
                    description,
                    attackType,
                    packageName,
                    whyFlagged,
                    remediationHint,
                    removable ? packageName : null,
                    showIcon ? packageManager.getApplicationIcon(appInfo) : null,
                    removable,
                    showIcon
            );
        } catch (Exception ignored) {
            return new ThreatFinding(
                    titleOverride,
                    description,
                    attackType,
                    packageName,
                    whyFlagged,
                    remediationHint,
                    removable ? packageName : null,
                    null,
                    removable,
                    false
            );
        }
    }

    private Set<String> getEnabledAccessibilityPackages() {
        String enabled = Settings.Secure.getString(getContentResolver(),
                Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES);
        if (TextUtils.isEmpty(enabled)) {
            return Collections.emptySet();
        }

        Set<String> packages = new LinkedHashSet<>();
        TextUtils.SimpleStringSplitter splitter = new TextUtils.SimpleStringSplitter(':');
        splitter.setString(enabled);
        while (splitter.hasNext()) {
            String componentName = splitter.next();
            ComponentName component = ComponentName.unflattenFromString(componentName);
            if (component != null) {
                packages.add(component.getPackageName());
            }
        }
        return packages;
    }

    private Set<String> getActiveAdminPackages() {
        DevicePolicyManager manager = (DevicePolicyManager) getSystemService(Context.DEVICE_POLICY_SERVICE);
        if (manager == null) {
            return Collections.emptySet();
        }

        List<ComponentName> admins = manager.getActiveAdmins();
        if (admins == null) {
            return Collections.emptySet();
        }

        Set<String> packages = new LinkedHashSet<>();
        for (ComponentName admin : admins) {
            packages.add(admin.getPackageName());
        }
        return packages;
    }

    private boolean isDeveloperOptionsEnabled() {
        return Settings.Global.getInt(getContentResolver(),
                Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) == 1;
    }

    private boolean isAdbEnabled() {
        return Settings.Global.getInt(getContentResolver(), Settings.Global.ADB_ENABLED, 0) == 1;
    }

    private boolean isDeviceSecure() {
        KeyguardManager keyguardManager = (KeyguardManager) getSystemService(Context.KEYGUARD_SERVICE);
        return keyguardManager != null && keyguardManager.isDeviceSecure();
    }

    @SuppressLint("WrongConstant")
    private boolean hasUsageStatsAccess() {
        AppOpsManager appOpsManager = (AppOpsManager) getSystemService(Context.APP_OPS_SERVICE);
        if (appOpsManager == null) {
            return false;
        }

        int mode;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            mode = appOpsManager.unsafeCheckOpNoThrow(
                    AppOpsManager.OPSTR_GET_USAGE_STATS, android.os.Process.myUid(), getPackageName());
        } else {
            mode = appOpsManager.checkOpNoThrow(
                    AppOpsManager.OPSTR_GET_USAGE_STATS, android.os.Process.myUid(), getPackageName());
        }
        return mode == AppOpsManager.MODE_ALLOWED;
    }

    private String[] getRuntimePermissions() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            return new String[]{
                    Manifest.permission.READ_MEDIA_IMAGES,
                    Manifest.permission.READ_MEDIA_VIDEO,
                    Manifest.permission.READ_MEDIA_AUDIO
            };
        }
        return new String[]{Manifest.permission.READ_EXTERNAL_STORAGE};
    }

    private boolean hasAllRuntimePermissions(@NonNull String[] permissions) {
        for (String permission : permissions) {
            if (ContextCompat.checkSelfPermission(this, permission) != PackageManager.PERMISSION_GRANTED) {
                return false;
            }
        }
        return true;
    }

    private List<ThreatFinding> flattenFindings(@NonNull List<ScanSection> sections) {
        List<ThreatFinding> all = new ArrayList<>();
        for (ScanSection section : sections) {
            all.addAll(section.findings);
        }
        return all;
    }

    private void renderSummary(@NonNull List<ThreatFinding> threats) {
        boolean hasThreats = !threats.isEmpty();
        summaryScreen.setBackgroundResource(hasThreats ? R.drawable.bg_summary_danger : R.drawable.bg_summary_safe);
        summaryTitle.setText(hasThreats ? R.string.summary_danger_title : R.string.summary_safe_title);
        summaryBody.setText(hasThreats ? R.string.summary_danger_body : R.string.summary_safe_body);
        summaryFindingsContainer.removeAllViews();

        if (!hasThreats) {
            summaryFindingsContainer.addView(createSummaryPill(lastSections.size() + " areas checked. No threat match."));
            return;
        }

        Map<String, Integer> grouped = new LinkedHashMap<>();
        for (ThreatFinding threat : threats) {
            Integer current = grouped.get(threat.attackType);
            grouped.put(threat.attackType, current == null ? 1 : current + 1);
        }
        for (Map.Entry<String, Integer> entry : grouped.entrySet()) {
            summaryFindingsContainer.addView(createSummaryPill(entry.getKey() + " | " + entry.getValue()));
        }
    }

    private void renderDetailedReport(@NonNull List<ScanSection> sections, @NonNull List<ThreatFinding> threats) {
        reportSectionsContainer.removeAllViews();
        for (ScanSection section : sections) {
            reportSectionsContainer.addView(createSectionCard(section));
        }
        reportPrimaryButton.setText(hasRemovableThreats(threats) ? R.string.remove_malware : R.string.go_home);
    }

    private void renderRemovalList() {
        removalThreatsContainer.removeAllViews();
        for (ThreatFinding threat : lastThreats) {
            if (!threat.removable) {
                continue;
            }
            removalThreatsContainer.addView(createRemovalOption(threat));
        }
        removeSelectedButton.setEnabled(hasSelectedThreats());
        removeSelectedButton.setAlpha(hasSelectedThreats() ? 1f : 0.55f);
    }

    private View createSectionCard(@NonNull ScanSection section) {
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setBackgroundResource(R.drawable.bg_glass_panel);
        card.setPadding(dp(18), dp(18), dp(18), dp(18));

        LinearLayout.LayoutParams cardParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        cardParams.bottomMargin = dp(16);
        card.setLayoutParams(cardParams);

        TextView title = new TextView(this);
        title.setText(section.title);
        title.setTextColor(ContextCompat.getColor(this, R.color.ink_primary));
        title.setTextSize(TypedValue.COMPLEX_UNIT_SP, 20);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        card.addView(title);

        TextView subtitle = new TextView(this);
        subtitle.setText(section.summary);
        subtitle.setTextColor(ContextCompat.getColor(this, R.color.ink_secondary));
        subtitle.setTextSize(TypedValue.COMPLEX_UNIT_SP, 14);
        LinearLayout.LayoutParams subtitleParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        subtitleParams.topMargin = dp(8);
        subtitle.setLayoutParams(subtitleParams);
        card.addView(subtitle);

        TextView status = new TextView(this);
        status.setText(section.findings.isEmpty() ? getString(R.string.status_clean) : getString(R.string.status_warning));
        status.setTextColor(ContextCompat.getColor(this, R.color.ink_primary));
        status.setBackgroundResource(section.findings.isEmpty() ? R.drawable.bg_status_safe : R.drawable.bg_status_danger);
        status.setPadding(dp(12), dp(8), dp(12), dp(8));
        LinearLayout.LayoutParams statusParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        statusParams.topMargin = dp(14);
        status.setLayoutParams(statusParams);
        card.addView(status);

        if (section.findings.isEmpty()) {
            TextView clean = new TextView(this);
            clean.setText(R.string.section_clear);
            clean.setTextColor(ContextCompat.getColor(this, R.color.ink_secondary));
            LinearLayout.LayoutParams cleanParams = new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
            cleanParams.topMargin = dp(14);
            clean.setLayoutParams(cleanParams);
            card.addView(clean);
            return card;
        }

        for (ThreatFinding finding : section.findings) {
            card.addView(createFindingRow(finding));
        }
        return card;
    }

    private View createFindingRow(@NonNull ThreatFinding finding) {
        LinearLayout container = new LinearLayout(this);
        container.setOrientation(LinearLayout.VERTICAL);
        container.setBackgroundResource(R.drawable.bg_inner_glass);
        container.setPadding(dp(14), dp(14), dp(14), dp(14));

        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        params.topMargin = dp(16);
        container.setLayoutParams(params);

        LinearLayout titleRow = new LinearLayout(this);
        titleRow.setOrientation(LinearLayout.HORIZONTAL);
        titleRow.setGravity(Gravity.CENTER_VERTICAL);
        container.addView(titleRow);

        if (finding.showAppIcon && finding.icon != null) {
            ImageView iconView = new ImageView(this);
            iconView.setImageDrawable(finding.icon);
            LinearLayout.LayoutParams iconParams = new LinearLayout.LayoutParams(dp(26), dp(26));
            iconParams.rightMargin = dp(10);
            iconView.setLayoutParams(iconParams);
            titleRow.addView(iconView);
        }

        TextView title = new TextView(this);
        title.setText(finding.title);
        title.setTextColor(ContextCompat.getColor(this, R.color.ink_primary));
        title.setTextSize(TypedValue.COMPLEX_UNIT_SP, 16);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        LinearLayout.LayoutParams titleParams = new LinearLayout.LayoutParams(
                0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        title.setLayoutParams(titleParams);
        titleRow.addView(title);

        TextView body = new TextView(this);
        body.setText(finding.description);
        body.setTextColor(ContextCompat.getColor(this, R.color.ink_secondary));
        body.setTextSize(TypedValue.COMPLEX_UNIT_SP, 14);
        LinearLayout.LayoutParams bodyParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        bodyParams.topMargin = dp(8);
        body.setLayoutParams(bodyParams);
        container.addView(body);

        MaterialButton detailsButton = new MaterialButton(this, null,
                com.google.android.material.R.attr.materialButtonOutlinedStyle);
        detailsButton.setText(R.string.details);
        detailsButton.setTextColor(ContextCompat.getColor(this, R.color.ink_primary));
        detailsButton.setStrokeColor(ContextCompat.getColorStateList(this, R.color.glass_stroke));
        detailsButton.setOnClickListener(v -> showThreatDetails(finding));
        LinearLayout.LayoutParams buttonParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        buttonParams.topMargin = dp(10);
        detailsButton.setLayoutParams(buttonParams);
        container.addView(detailsButton);

        return container;
    }

    private View createRemovalOption(@NonNull ThreatFinding threat) {
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.HORIZONTAL);
        card.setGravity(Gravity.CENTER_VERTICAL);
        card.setBackgroundResource(R.drawable.bg_glass_panel);
        card.setPadding(dp(14), dp(14), dp(14), dp(14));

        LinearLayout.LayoutParams cardParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        cardParams.bottomMargin = dp(12);
        card.setLayoutParams(cardParams);

        CheckBox checkBox = new CheckBox(this);
        checkBox.setChecked(threat.selectedForRemoval);
        checkBox.setOnCheckedChangeListener((buttonView, isChecked) -> {
            threat.selectedForRemoval = isChecked;
            removeSelectedButton.setEnabled(hasSelectedThreats());
            removeSelectedButton.setAlpha(hasSelectedThreats() ? 1f : 0.55f);
        });
        card.addView(checkBox);

        if (threat.icon != null) {
            ImageView iconView = new ImageView(this);
            iconView.setImageDrawable(threat.icon);
            LinearLayout.LayoutParams iconParams = new LinearLayout.LayoutParams(dp(28), dp(28));
            iconParams.rightMargin = dp(12);
            iconView.setLayoutParams(iconParams);
            card.addView(iconView);
        }

        LinearLayout textWrap = new LinearLayout(this);
        textWrap.setOrientation(LinearLayout.VERTICAL);
        LinearLayout.LayoutParams wrapParams = new LinearLayout.LayoutParams(
                0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        textWrap.setLayoutParams(wrapParams);
        card.addView(textWrap);

        TextView title = new TextView(this);
        title.setText(threat.title);
        title.setTextColor(ContextCompat.getColor(this, R.color.ink_primary));
        title.setTextSize(TypedValue.COMPLEX_UNIT_SP, 16);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        textWrap.addView(title);

        TextView subtitle = new TextView(this);
        subtitle.setText(threat.attackType);
        subtitle.setTextColor(ContextCompat.getColor(this, R.color.ink_secondary));
        subtitle.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13);
        LinearLayout.LayoutParams subParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        subParams.topMargin = dp(4);
        subtitle.setLayoutParams(subParams);
        textWrap.addView(subtitle);

        return card;
    }

    private TextView createSummaryPill(@NonNull String text) {
        TextView pill = new TextView(this);
        pill.setText(text);
        pill.setTextColor(ContextCompat.getColor(this, R.color.ink_primary));
        pill.setBackgroundResource(R.drawable.bg_chip);
        pill.setPadding(dp(16), dp(12), dp(16), dp(12));
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        params.bottomMargin = dp(10);
        pill.setLayoutParams(params);
        return pill;
    }

    private void showThreatDetails(@NonNull ThreatFinding finding) {
        StringBuilder message = new StringBuilder();
        message.append(getString(R.string.details_attack)).append(" ").append(finding.attackType).append("\n\n");
        message.append(getString(R.string.details_location)).append(" ").append(finding.location).append("\n\n");
        message.append(getString(R.string.details_reason)).append(" ").append(finding.whyFlagged);
        if (finding.removablePackage != null) {
            message.append("\n\n").append(getString(R.string.details_package)).append(" ").append(finding.removablePackage);
        }

        new MaterialAlertDialogBuilder(this)
                .setTitle(finding.title)
                .setMessage(message.toString())
                .setPositiveButton(R.string.ok, null)
                .show();
    }

    private void showHomeScreen() {
        homeScreen.setVisibility(View.VISIBLE);
        scanScreen.setVisibility(View.GONE);
        summaryScreen.setVisibility(View.GONE);
        reportScreen.setVisibility(View.GONE);
        removalScreen.setVisibility(View.GONE);
    }

    private void showScanScreen() {
        homeScreen.setVisibility(View.GONE);
        scanScreen.setVisibility(View.VISIBLE);
        summaryScreen.setVisibility(View.GONE);
        reportScreen.setVisibility(View.GONE);
        removalScreen.setVisibility(View.GONE);
        circularProgress.show();
        linearProgress.setProgressCompat(0, false);
        scanCounter.setText("0 / " + TOTAL_SCAN_STEPS);
        currentScanLabel.setText(R.string.preparing_scan);
    }

    private void showSummaryScreen(boolean danger) {
        homeScreen.setVisibility(View.GONE);
        scanScreen.setVisibility(View.GONE);
        summaryScreen.setVisibility(View.VISIBLE);
        reportScreen.setVisibility(View.GONE);
        removalScreen.setVisibility(View.GONE);
        summaryScreen.fullScroll(View.FOCUS_UP);
        summaryBody.setTextColor(ContextCompat.getColor(this, R.color.summary_text));
        summaryTitle.setTextColor(ContextCompat.getColor(this, R.color.summary_text));
        summaryFindingsContainer.setAlpha(danger ? 1f : 0.9f);
    }

    private void showDetailedReport() {
        homeScreen.setVisibility(View.GONE);
        scanScreen.setVisibility(View.GONE);
        summaryScreen.setVisibility(View.GONE);
        reportScreen.setVisibility(View.VISIBLE);
        removalScreen.setVisibility(View.GONE);
        reportScreen.fullScroll(View.FOCUS_UP);
    }

    private void showRemovalScreen() {
        homeScreen.setVisibility(View.GONE);
        scanScreen.setVisibility(View.GONE);
        summaryScreen.setVisibility(View.GONE);
        reportScreen.setVisibility(View.GONE);
        removalScreen.setVisibility(View.VISIBLE);
        renderRemovalList();
        removalScreen.fullScroll(View.FOCUS_UP);
    }

    private void startRemovalFlow() {
        if (!hasSelectedThreats()) {
            return;
        }

        removalQueue.clear();
        Set<String> queuedPackages = new LinkedHashSet<>();
        for (ThreatFinding threat : lastThreats) {
            if (threat.removable && threat.selectedForRemoval && threat.removablePackage != null
                    && queuedPackages.add(threat.removablePackage)) {
                removalQueue.add(threat.removablePackage);
            }
        }
        launchNextRemovalStep();
    }

    private void launchNextRemovalStep() {
        String nextPackage = removalQueue.poll();
        if (nextPackage == null) {
            showHomeScreen();
            return;
        }

        Intent uninstallIntent = new Intent(Intent.ACTION_UNINSTALL_PACKAGE);
        uninstallIntent.setData(Uri.parse("package:" + nextPackage));
        uninstallIntent.putExtra(Intent.EXTRA_RETURN_RESULT, true);
        uninstallLauncher.launch(uninstallIntent);
    }

    private boolean hasRemovableThreats() {
        return hasRemovableThreats(lastThreats);
    }

    private boolean hasRemovableThreats(@NonNull List<ThreatFinding> threats) {
        for (ThreatFinding threat : threats) {
            if (threat.removable && threat.removablePackage != null) {
                return true;
            }
        }
        return false;
    }

    private boolean hasSelectedThreats() {
        for (ThreatFinding threat : lastThreats) {
            if (threat.removable && threat.selectedForRemoval && threat.removablePackage != null) {
                return true;
            }
        }
        return false;
    }

    private int dp(int value) {
        return Math.round(TypedValue.applyDimension(
                TypedValue.COMPLEX_UNIT_DIP, value, getResources().getDisplayMetrics()));
    }

    private String shortPermissionName(@NonNull String permission) {
        int index = permission.lastIndexOf('.');
        return index >= 0 ? permission.substring(index + 1) : permission;
    }

    private static final class ScanSection {
        final String title;
        final String summary;
        final List<ThreatFinding> findings;

        ScanSection(String title, String summary, List<ThreatFinding> findings) {
            this.title = title;
            this.summary = summary;
            this.findings = findings;
        }
    }

    private interface ScanSectionSupplier {
        ScanSection get();
    }

    private static final class ThreatFinding {
        final String title;
        final String description;
        final String attackType;
        final String location;
        final String whyFlagged;
        final String remediationHint;
        final String removablePackage;
        final Drawable icon;
        final boolean removable;
        final boolean showAppIcon;
        boolean selectedForRemoval;

        ThreatFinding(String title, String description, String attackType, String location,
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
}
