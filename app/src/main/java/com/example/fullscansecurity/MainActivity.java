package com.example.fullscansecurity;

import android.Manifest;
import android.annotation.SuppressLint;
import android.app.AppOpsManager;
import android.app.KeyguardManager;
import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.ContentResolver;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.graphics.Typeface;
import android.graphics.drawable.Drawable;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.provider.MediaStore;
import android.provider.Settings;
import android.text.TextUtils;
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
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class MainActivity extends AppCompatActivity {

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

    private final ExecutorService scanExecutor = Executors.newSingleThreadExecutor();
    private final Handler mainHandler = new Handler(Looper.getMainLooper());
    private final ArrayDeque<ThreatFinding> removalQueue = new ArrayDeque<>();

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
        int totalSteps = 5;

        updateScanProgress(1, totalSteps, getString(R.string.section_apps));
        sections.add(scanInstalledApps());
        SystemClock.sleep(320);

        updateScanProgress(2, totalSteps, getString(R.string.section_permissions));
        sections.add(scanPermissionExposure());
        SystemClock.sleep(320);

        updateScanProgress(3, totalSteps, getString(R.string.section_accessibility));
        sections.add(scanAccessibilityAndAdminAbuse());
        SystemClock.sleep(320);

        updateScanProgress(4, totalSteps, getString(R.string.section_device));
        sections.add(scanDeviceSecurityPosture());
        SystemClock.sleep(320);

        updateScanProgress(5, totalSteps, getString(R.string.section_storage));
        sections.add(scanReachableStorageSurfaces());
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
        return (!system || updatedSystem) && !shouldSkipPackage(appInfo.packageName);
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
            summaryFindingsContainer.addView(createSummaryPill(getString(R.string.summary_clean_chip)));
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
        scanCounter.setText("0 / 5");
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
        for (ThreatFinding threat : lastThreats) {
            if (threat.removable && threat.selectedForRemoval && threat.removablePackage != null) {
                removalQueue.add(threat);
            }
        }
        launchNextRemovalStep();
    }

    private void launchNextRemovalStep() {
        ThreatFinding next = removalQueue.poll();
        if (next == null) {
            showHomeScreen();
            return;
        }

        Intent uninstallIntent = new Intent(Intent.ACTION_UNINSTALL_PACKAGE);
        uninstallIntent.setData(Uri.parse("package:" + next.removablePackage));
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
