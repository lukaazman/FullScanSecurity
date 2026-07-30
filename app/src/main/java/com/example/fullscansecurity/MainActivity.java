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
import android.content.SharedPreferences;
import android.content.res.Configuration;
import android.content.pm.ApplicationInfo;
import android.content.pm.ComponentInfo;
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
import android.view.WindowManager;
import android.view.accessibility.AccessibilityManager;
import android.animation.ValueAnimator;
import android.widget.CheckBox;
import android.widget.ImageView;
import android.widget.ImageButton;
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

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.File;
import java.lang.reflect.Method;
import java.security.KeyStore;
import java.text.DateFormat;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
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
    private static final String PREFS_NAME = "full_scan_security_prefs";
    private static final String KEY_LANGUAGE = "selected_language";
    private static final String KEY_ACTIVE_SCREEN = "active_screen";
    private static final String KEY_ACTIVE_SCAN = "active_scan";
    private static final String KEY_SCAN_HISTORY = "scan_history";
    private static final String DEFAULT_LANGUAGE = "en";
    private static final String SCREEN_HOME = "home";
    private static final String SCREEN_SUMMARY = "summary";
    private static final String SCREEN_REPORT = "report";
    private static final String SCREEN_REMOVAL = "removal";
    private static final int MAX_HISTORY_ENTRIES = 12;
    private static final String PACKAGE_NAME_PATTERN = "^[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+$";

    private static final int TOTAL_SCAN_STEPS = 15;

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
    private final ArrayDeque<RemediationAction> remediationQueue = new ArrayDeque<>();

    private NestedScrollView homeScreen;
    private NestedScrollView accessCenterScreen;
    private LinearLayout scanScreen;
    private LinearLayout homeContent;
    private LinearLayout homeHeroCard;
    private LinearLayout scanningPanel;
    private NestedScrollView summaryScreen;
    private NestedScrollView reportScreen;
    private NestedScrollView removalScreen;
    private ImageButton languageToggleButton;
    private LinearLayout languageDropdown;
    private MaterialButton englishLanguageButton;
    private MaterialButton spanishLanguageButton;
    private MaterialButton germanLanguageButton;
    private MaterialButton chineseLanguageButton;
    private MaterialButton slovenianLanguageButton;
    private MaterialButton startScanButton;
    private MaterialButton reviewAccessButton;
    private MaterialButton viewReportButton;
    private MaterialButton reportPrimaryButton;
    private MaterialButton removeSelectedButton;
    private MaterialButton removalBackButton;
    private MaterialButton clearHistoryButton;
    private MaterialButton accessCenterBackButton;
    private TextView homeTitle;
    private TextView scanTitle;
    private TextView accessCenterTitle;
    private TextView reportTitle;
    private TextView removalTitle;
    private TextView currentScanLabel;
    private TextView scanCounter;
    private TextView scanFootnote;
    private TextView removalSelectionSummary;
    private LinearProgressIndicator linearProgress;
    private CircularProgressIndicator circularProgress;
    private TextView summaryTitle;
    private TextView summaryBody;
    private LinearLayout historySection;
    private LinearLayout historyContainer;
    private LinearLayout accessCenterContainer;
    private LinearLayout summaryFindingsContainer;
    private LinearLayout reportSectionsContainer;
    private LinearLayout removalThreatsContainer;

    private ActivityResultLauncher<String[]> permissionLauncher;
    private ActivityResultLauncher<Intent> usageAccessLauncher;
    private ActivityResultLauncher<Intent> remediationLauncher;

    private boolean pendingScanRequest;
    private boolean scanInProgress;
    private boolean highContrastMode;
    private boolean reducedMotionMode;
    private List<ScanHistoryEntry> scanHistory = new ArrayList<>();
    private List<ScanSection> lastSections = new ArrayList<>();
    private List<ThreatFinding> lastThreats = new ArrayList<>();

    @Override
    protected void attachBaseContext(Context newBase) {
        super.attachBaseContext(wrapContextWithLocale(newBase, getStoredLanguage(newBase)));
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        EdgeToEdge.enable(this);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        setContentView(R.layout.activity_main);
        bindViews();
        setupWindowInsets();
        registerLaunchers();
        setupActions();
        setupAccessibility();
        restorePersistedState();
    }

    @Override
    protected void onResume() {
        super.onResume();
        refreshAccessibilityState();
        if (accessCenterScreen.getVisibility() == View.VISIBLE) {
            renderAccessCenter();
        }
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
        accessCenterScreen = findViewById(R.id.accessCenterScreen);
        scanScreen = findViewById(R.id.scanScreen);
        homeContent = findViewById(R.id.homeContent);
        homeHeroCard = findViewById(R.id.homeHeroCard);
        scanningPanel = findViewById(R.id.scanningPanel);
        summaryScreen = findViewById(R.id.summaryScreen);
        reportScreen = findViewById(R.id.reportScreen);
        removalScreen = findViewById(R.id.removalScreen);
        languageToggleButton = findViewById(R.id.languageToggleButton);
        languageDropdown = findViewById(R.id.languageDropdown);
        englishLanguageButton = findViewById(R.id.englishLanguageButton);
        spanishLanguageButton = findViewById(R.id.spanishLanguageButton);
        germanLanguageButton = findViewById(R.id.germanLanguageButton);
        chineseLanguageButton = findViewById(R.id.chineseLanguageButton);
        slovenianLanguageButton = findViewById(R.id.slovenianLanguageButton);
        startScanButton = findViewById(R.id.startScanButton);
        reviewAccessButton = findViewById(R.id.reviewAccessButton);
        viewReportButton = findViewById(R.id.viewReportButton);
        reportPrimaryButton = findViewById(R.id.reportPrimaryButton);
        removeSelectedButton = findViewById(R.id.removeSelectedButton);
        removalBackButton = findViewById(R.id.removalBackButton);
        clearHistoryButton = findViewById(R.id.clearHistoryButton);
        accessCenterBackButton = findViewById(R.id.accessCenterBackButton);
        homeTitle = findViewById(R.id.homeTitle);
        scanTitle = findViewById(R.id.scanTitle);
        accessCenterTitle = findViewById(R.id.accessCenterTitle);
        reportTitle = findViewById(R.id.reportTitle);
        removalTitle = findViewById(R.id.removalTitle);
        currentScanLabel = findViewById(R.id.currentScanLabel);
        scanCounter = findViewById(R.id.scanCounter);
        scanFootnote = findViewById(R.id.scanFootnote);
        removalSelectionSummary = findViewById(R.id.removalSelectionSummary);
        linearProgress = findViewById(R.id.linearProgress);
        circularProgress = findViewById(R.id.circularProgress);
        summaryTitle = findViewById(R.id.summaryTitle);
        summaryBody = findViewById(R.id.summaryBody);
        historySection = findViewById(R.id.historySection);
        historyContainer = findViewById(R.id.historyContainer);
        accessCenterContainer = findViewById(R.id.accessCenterContainer);
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

        remediationLauncher = registerForActivityResult(
                new ActivityResultContracts.StartActivityForResult(),
                result -> launchNextRemediationStep()
        );
    }

    private void setupActions() {
        languageToggleButton.setOnClickListener(v -> toggleLanguageDropdown());
        englishLanguageButton.setOnClickListener(v -> selectLanguage(DEFAULT_LANGUAGE));
        spanishLanguageButton.setOnClickListener(v -> selectLanguage("es"));
        germanLanguageButton.setOnClickListener(v -> selectLanguage("de"));
        chineseLanguageButton.setOnClickListener(v -> selectLanguage("zh"));
        slovenianLanguageButton.setOnClickListener(v -> selectLanguage("sl"));
        startScanButton.setOnClickListener(v -> requestAccessAndStart());
        reviewAccessButton.setOnClickListener(v -> showAccessCenterScreen());
        viewReportButton.setOnClickListener(v -> showDetailedReport());
        reportPrimaryButton.setOnClickListener(v -> {
            if (!hasActionableThreats()) {
                showHomeScreen();
            } else {
                showRemovalScreen();
            }
        });
        removeSelectedButton.setOnClickListener(v -> startRemovalFlow());
        removalBackButton.setOnClickListener(v -> showDetailedReport());
        clearHistoryButton.setOnClickListener(v -> confirmClearHistory());
        accessCenterBackButton.setOnClickListener(v -> showHomeScreen());
        refreshLanguageSelectionState();
    }

    private void setupAccessibility() {
        refreshAccessibilityState();
        languageToggleButton.setFocusable(true);
        currentScanLabel.setAccessibilityLiveRegion(View.ACCESSIBILITY_LIVE_REGION_POLITE);
        scanCounter.setAccessibilityLiveRegion(View.ACCESSIBILITY_LIVE_REGION_POLITE);
        summaryTitle.setAccessibilityLiveRegion(View.ACCESSIBILITY_LIVE_REGION_POLITE);
        removalSelectionSummary.setAccessibilityLiveRegion(View.ACCESSIBILITY_LIVE_REGION_POLITE);
        ViewCompat.setAccessibilityHeading(homeTitle, true);
        ViewCompat.setAccessibilityHeading(scanTitle, true);
        ViewCompat.setAccessibilityHeading(accessCenterTitle, true);
        ViewCompat.setAccessibilityHeading(summaryTitle, true);
        ViewCompat.setAccessibilityHeading(reportTitle, true);
        ViewCompat.setAccessibilityHeading(removalTitle, true);
        updateLanguageToggleDescription(languageDropdown.getVisibility() == View.VISIBLE);
        updateRemovalSelectionSummary(false);
    }

    private void refreshAccessibilityState() {
        boolean newHighContrast = isHighContrastEnabled();
        boolean newReducedMotion = Build.VERSION.SDK_INT >= Build.VERSION_CODES.O
                ? !ValueAnimator.areAnimatorsEnabled()
                : false;
        boolean needsRefresh = newHighContrast != highContrastMode || newReducedMotion != reducedMotionMode;
        highContrastMode = newHighContrast;
        reducedMotionMode = newReducedMotion;
        if (needsRefresh) {
            applyAccessibilityVisualMode();
            renderHistorySection();
            if (!lastSections.isEmpty()) {
                renderSummary(lastThreats);
                renderDetailedReport(lastSections, lastThreats);
                renderRemovalList();
            }
        } else {
            applyAccessibilityVisualMode();
        }
    }

    private void toggleLanguageDropdown() {
        if (homeScreen.getVisibility() != View.VISIBLE) {
            return;
        }
        boolean expanded = languageDropdown.getVisibility() != View.VISIBLE;
        languageDropdown.setVisibility(expanded ? View.VISIBLE : View.GONE);
        updateLanguageToggleDescription(expanded);
        announceForAccessibility(expanded
                ? getString(R.string.a11y_language_menu_expanded)
                : getString(R.string.a11y_language_menu_collapsed));
    }

    private void selectLanguage(@NonNull String languageCode) {
        if (languageCode.equals(getSelectedLanguage())) {
            languageDropdown.setVisibility(View.GONE);
            refreshLanguageSelectionState();
            return;
        }

        SharedPreferences preferences = getSharedPreferences(PREFS_NAME, MODE_PRIVATE);
        preferences.edit().putString(KEY_LANGUAGE, languageCode).apply();
        recreate();
    }

    private void refreshLanguageSelectionState() {
        String selected = getSelectedLanguage();
        bindLanguageButtonState(englishLanguageButton, DEFAULT_LANGUAGE.equals(selected));
        bindLanguageButtonState(spanishLanguageButton, "es".equals(selected));
        bindLanguageButtonState(germanLanguageButton, "de".equals(selected));
        bindLanguageButtonState(chineseLanguageButton, "zh".equals(selected));
        bindLanguageButtonState(slovenianLanguageButton, "sl".equals(selected));
    }

    private void bindLanguageButtonState(@NonNull MaterialButton button, boolean selected) {
        button.setAlpha(selected ? 1f : 0.72f);
        button.setStrokeWidth(selected ? dp(2) : dp(1));
    }

    @NonNull
    private String getSelectedLanguage() {
        return getStoredLanguage(this);
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
        sections.add(runSectionSafely(getString(R.string.section_apps), getString(R.string.summary_section_apps_degraded), this::scanInstalledApps));
        SystemClock.sleep(320);

        updateScanProgress(2, totalSteps, getString(R.string.section_permissions));
        sections.add(runSectionSafely(getString(R.string.section_permissions), getString(R.string.summary_section_permissions_degraded), this::scanPermissionExposure));
        SystemClock.sleep(320);

        updateScanProgress(3, totalSteps, getString(R.string.section_accessibility));
        sections.add(runSectionSafely(getString(R.string.section_accessibility), getString(R.string.summary_section_accessibility_degraded), this::scanAccessibilityAndAdminAbuse));
        SystemClock.sleep(320);

        updateScanProgress(4, totalSteps, getString(R.string.section_network));
        sections.add(runSectionSafely(getString(R.string.section_network), getString(R.string.summary_section_network_degraded), this::scanNetworkSecurityPosture));
        SystemClock.sleep(320);

        updateScanProgress(5, totalSteps, getString(R.string.section_install_trust));
        sections.add(runSectionSafely(getString(R.string.section_install_trust), getString(R.string.summary_section_install_trust_degraded), this::scanInstallTrust));
        SystemClock.sleep(320);

        updateScanProgress(6, totalSteps, getString(R.string.section_integrity));
        sections.add(runSectionSafely(getString(R.string.section_integrity), getString(R.string.summary_section_integrity_degraded), this::scanBootIntegrity));
        SystemClock.sleep(320);

        updateScanProgress(7, totalSteps, getString(R.string.section_persistence));
        sections.add(runSectionSafely(getString(R.string.section_persistence), getString(R.string.summary_section_persistence_degraded), this::scanNotificationAndOverlayAbuse));
        SystemClock.sleep(320);

        updateScanProgress(8, totalSteps, getString(R.string.section_browser_sms_call));
        sections.add(runSectionSafely(getString(R.string.section_browser_sms_call), getString(R.string.summary_section_default_apps_degraded), this::scanDefaultAppRedirectionRisk));
        SystemClock.sleep(320);

        updateScanProgress(9, totalSteps, getString(R.string.section_live_posture));
        sections.add(runSectionSafely(getString(R.string.section_live_posture), getString(R.string.summary_section_live_posture_degraded), this::scanLivePosture));
        SystemClock.sleep(320);

        updateScanProgress(10, totalSteps, getString(R.string.section_input_methods));
        sections.add(runSectionSafely(getString(R.string.section_input_methods), getString(R.string.summary_section_input_methods_degraded), this::scanInputMethodRisk));
        SystemClock.sleep(320);

        updateScanProgress(11, totalSteps, getString(R.string.section_surveillance));
        sections.add(runSectionSafely(getString(R.string.section_surveillance), getString(R.string.summary_section_surveillance_degraded), this::scanSurveillanceRisk));
        SystemClock.sleep(320);

        updateScanProgress(12, totalSteps, getString(R.string.section_device));
        sections.add(runSectionSafely(getString(R.string.section_device), getString(R.string.summary_section_device_degraded), this::scanDeviceSecurityPosture));
        SystemClock.sleep(320);

        updateScanProgress(13, totalSteps, getString(R.string.section_storage));
        sections.add(runSectionSafely(getString(R.string.section_storage), getString(R.string.summary_section_storage_degraded), this::scanReachableStorageSurfaces));
        SystemClock.sleep(320);

        updateScanProgress(14, totalSteps, getString(R.string.section_sensitive_services));
        sections.add(runSectionSafely(getString(R.string.section_sensitive_services), getString(R.string.summary_section_sensitive_services_degraded), this::scanSensitiveServiceRisk));
        SystemClock.sleep(320);

        updateScanProgress(15, totalSteps, getString(R.string.section_exposed_components));
        sections.add(runSectionSafely(getString(R.string.section_exposed_components), getString(R.string.summary_section_exposed_components_degraded), this::scanExposedComponentRisk));
        SystemClock.sleep(380);

        return sections;
    }

    private void updateScanProgress(int step, int totalSteps, @NonNull String label) {
        mainHandler.post(() -> {
            currentScanLabel.setText(getString(R.string.currently_scanning_prefix) + " " + label);
            scanCounter.setText(getString(R.string.scan_counter_value, step, totalSteps));
            linearProgress.setMax(totalSteps);
            linearProgress.setProgressCompat(step, !reducedMotionMode);
            scanFootnote.setText(R.string.scan_footer);
            announceForAccessibility(getString(R.string.a11y_scan_step_announcement, label, step, totalSteps));
        });
    }

    private void finishScan(@NonNull List<ScanSection> sections, @NonNull List<ThreatFinding> threats) {
        scanInProgress = false;
        lastSections = sections;
        lastThreats = threats;
        appendScanToHistory(sections);
        renderSummary(threats);
        renderDetailedReport(sections, threats);
        renderRemovalList();
        renderHistorySection();
        persistActiveSnapshot(SCREEN_SUMMARY);
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

    private ScanSection scanNetworkSecurityPosture() {
        PackageManager packageManager = getPackageManager();
        List<ThreatFinding> findings = new ArrayList<>();

        try {
            String privateDnsMode = Settings.Global.getString(getContentResolver(), "private_dns_mode");
            String privateDnsHost = Settings.Global.getString(getContentResolver(), "private_dns_specifier");
            if (TextUtils.isEmpty(privateDnsMode) || "off".equalsIgnoreCase(privateDnsMode)) {
                findings.add(new ThreatFinding(
                        getString(R.string.finding_private_dns_off_title),
                        getString(R.string.finding_private_dns_off_body),
                        getString(R.string.attack_type_dns_posture),
                        getString(R.string.location_network_settings),
                        getString(R.string.detail_private_dns_mode) + " " + safeValue(privateDnsMode),
                        getString(R.string.hint_trusted_dns),
                        null,
                        null,
                        false,
                        false
                ));
            } else if ("hostname".equalsIgnoreCase(privateDnsMode) && !TextUtils.isEmpty(privateDnsHost)
                    && !isTrustedPrivateDnsHost(privateDnsHost)) {
                findings.add(new ThreatFinding(
                        getString(R.string.finding_custom_private_dns_title),
                        getString(R.string.finding_custom_private_dns_body),
                        getString(R.string.attack_type_dns_posture),
                        privateDnsHost,
                        getString(R.string.detail_untrusted_private_dns),
                        getString(R.string.hint_verify_resolver),
                        null,
                        null,
                        false,
                        false
                ));
            }
        } catch (Exception e) {
            logWarn("Private DNS check failed", e);
        }

        try {
            int userCaCount = getUserInstalledCaCount();
            if (userCaCount > 0) {
                findings.add(new ThreatFinding(
                        getString(R.string.finding_user_ca_title),
                        getString(R.string.finding_user_ca_body),
                        getString(R.string.attack_type_tls_surface),
                        getString(R.string.location_trust_store),
                        getString(R.string.detail_user_ca_count, userCaCount),
                        getString(R.string.hint_review_credentials),
                        null,
                        null,
                        false,
                        false
                ));
            }
        } catch (Exception e) {
            logWarn("User CA scan failed", e);
        }

        try {
            ProxyInfo proxyInfo = getDefaultProxyInfo();
            if (proxyInfo != null && !TextUtils.isEmpty(proxyInfo.getHost())) {
                findings.add(new ThreatFinding(
                        getString(R.string.finding_proxy_active_title),
                        getString(R.string.finding_proxy_active_body),
                        getString(R.string.attack_type_proxy_posture),
                        proxyInfo.getHost() + ":" + proxyInfo.getPort(),
                        getString(R.string.detail_default_proxy_configured),
                        getString(R.string.hint_remove_unexpected_proxy),
                        null,
                        null,
                        false,
                        false
                ));
            }
        } catch (Exception e) {
            logWarn("Proxy check failed", e);
        }

        try {
            String alwaysOnVpnPackage = getAlwaysOnVpnPackage();
            if (!TextUtils.isEmpty(alwaysOnVpnPackage) && !shouldSkipPackage(alwaysOnVpnPackage)) {
                findings.add(buildPackageFinding(
                        alwaysOnVpnPackage,
                        packageManager,
                        getString(R.string.finding_always_on_vpn_title),
                        getString(R.string.attack_type_vpn_posture),
                        getString(R.string.finding_always_on_vpn_body),
                        getString(R.string.detail_always_on_vpn_package) + " " + alwaysOnVpnPackage,
                        getString(R.string.hint_review_vpn),
                        true,
                        true
                ));
            } else if (isVpnActive()) {
                findings.add(new ThreatFinding(
                        getString(R.string.finding_vpn_transport_title),
                        getString(R.string.finding_vpn_transport_body),
                        getString(R.string.attack_type_vpn_posture),
                        getString(R.string.location_active_network),
                        getString(R.string.detail_vpn_transport),
                        getString(R.string.hint_verify_vpn),
                        null,
                        null,
                        false,
                        false
                ));
            }
        } catch (Exception e) {
            logWarn("VPN check failed", e);
        }

        return new ScanSection(getString(R.string.section_network), getString(R.string.summary_network), findings);
    }

    private ScanSection runSectionSafely(
            @NonNull String title,
            @NonNull String fallbackSummary,
            @NonNull ScanSectionSupplier supplier
    ) {
        try {
            return supplier.get();
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

    private ScanSection scanInstallTrust() {
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

    private ScanSection scanBootIntegrity() {
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

    private ScanSection scanDefaultAppRedirectionRisk() {
        PackageManager packageManager = getPackageManager();
        List<ThreatFinding> findings = new ArrayList<>();
        Set<String> accessibilityPackages = getEnabledAccessibilityPackages();

        findings.addAll(buildDefaultRoleFindings(packageManager, getString(R.string.role_default_sms), getDefaultSmsPackage(), accessibilityPackages));
        findings.addAll(buildDefaultRoleFindings(packageManager, getString(R.string.role_default_dialer), getDefaultDialerPackage(), accessibilityPackages));
        findings.addAll(buildDefaultRoleFindings(packageManager, getString(R.string.role_default_browser), getDefaultBrowserPackage(), accessibilityPackages));

        return new ScanSection(getString(R.string.section_browser_sms_call), getString(R.string.summary_browser_sms_call), findings);
    }

    private ScanSection scanLivePosture() {
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

    private ScanSection scanSensitiveServiceRisk() {
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

    private ScanSection scanExposedComponentRisk() {
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

    @NonNull
    private List<String> collectSensitiveServiceRoles(@NonNull PackageInfo packageInfo) {
        Set<String> roles = new LinkedHashSet<>();

        if (packageInfo.services != null) {
            for (android.content.pm.ServiceInfo serviceInfo : packageInfo.services) {
                String permission = serviceInfo.permission;
                String label = getSensitiveServiceLabel(permission);
                if (label != null) {
                    roles.add(label);
                }
            }
        }

        if (packageInfo.receivers != null) {
            for (android.content.pm.ActivityInfo receiverInfo : packageInfo.receivers) {
                if ("android.permission.BIND_DEVICE_ADMIN".equals(receiverInfo.permission)) {
                    roles.add(getString(R.string.role_device_admin));
                }
            }
        }

        return new ArrayList<>(roles);
    }

    @Nullable
    private String getSensitiveServiceLabel(@Nullable String permission) {
        if (TextUtils.isEmpty(permission)) {
            return null;
        }
        if ("android.permission.BIND_ACCESSIBILITY_SERVICE".equals(permission)) {
            return getString(R.string.role_accessibility_service);
        }
        if ("android.permission.BIND_NOTIFICATION_LISTENER_SERVICE".equals(permission)) {
            return getString(R.string.role_notification_listener);
        }
        if ("android.permission.BIND_AUTOFILL_SERVICE".equals(permission)) {
            return getString(R.string.role_autofill_service);
        }
        if ("android.permission.BIND_INPUT_METHOD".equals(permission)) {
            return getString(R.string.role_input_method);
        }
        if ("android.permission.BIND_VPN_SERVICE".equals(permission)) {
            return getString(R.string.role_vpn_service);
        }
        return null;
    }

    private int countExportedComponents(@Nullable ComponentInfo[] components) {
        if (components == null) {
            return 0;
        }
        int count = 0;
        for (ComponentInfo component : components) {
            if (component != null && component.exported) {
                count++;
            }
        }
        return count;
    }

    private int countUnprotectedExportedComponents(@Nullable ComponentInfo[] components) {
        if (components == null) {
            return 0;
        }
        int count = 0;
        for (ComponentInfo component : components) {
            if (component != null && component.exported && TextUtils.isEmpty(getComponentPermission(component))) {
                count++;
            }
        }
        return count;
    }

    @Nullable
    private String getComponentPermission(@NonNull ComponentInfo component) {
        if (component instanceof android.content.pm.ActivityInfo) {
            return ((android.content.pm.ActivityInfo) component).permission;
        }
        if (component instanceof android.content.pm.ServiceInfo) {
            return ((android.content.pm.ServiceInfo) component).permission;
        }
        if (component instanceof android.content.pm.ProviderInfo) {
            android.content.pm.ProviderInfo providerInfo = (android.content.pm.ProviderInfo) component;
            if (!TextUtils.isEmpty(providerInfo.readPermission)) {
                return providerInfo.readPermission;
            }
            return providerInfo.writePermission;
        }
        return null;
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
            return getString(R.string.label_google_play);
        }
        return installer;
    }

    private String safeValue(@Nullable String value) {
        return TextUtils.isEmpty(value) ? getString(R.string.label_unknown) : value;
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
                reasons.add(getString(R.string.reason_unknown_installer));
            }
            if (accessibility) {
                reasons.add(getString(R.string.reason_accessibility_on));
            }
            if (messagingSensitive) {
                reasons.add(getString(R.string.reason_sensitive_comms));
            }
            if (riskScore >= 3) {
                reasons.add(getString(R.string.reason_high_risk_permissions));
            }

            ThreatFinding finding = new ThreatFinding(
                    packageManager.getApplicationLabel(appInfo).toString(),
                    getString(R.string.finding_default_handler_body, roleName),
                    getString(R.string.attack_type_default_handler),
                    packageName,
                    TextUtils.join(", ", reasons),
                    getString(R.string.hint_review_default_handler),
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
        summaryTitle.setContentDescription(summaryTitle.getText());
        summaryFindingsContainer.removeAllViews();

        if (!hasThreats) {
            summaryFindingsContainer.addView(createSummaryPill(
                    getString(R.string.summary_clean_chip_dynamic, lastSections.size())));
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
        reportPrimaryButton.setText(hasActionableThreats(threats) ? R.string.remove_malware : R.string.go_home);
    }

    private void renderRemovalList() {
        removalThreatsContainer.removeAllViews();
        for (ThreatFinding threat : lastThreats) {
            if (!isThreatActionable(threat)) {
                continue;
            }
            removalThreatsContainer.addView(createRemovalOption(threat));
        }
        removeSelectedButton.setText(R.string.apply_selected_actions);
        removeSelectedButton.setEnabled(hasSelectedThreats());
        removeSelectedButton.setAlpha(hasSelectedThreats() ? 1f : 0.55f);
        updateRemovalSelectionSummary(false);
    }

    private View createSectionCard(@NonNull ScanSection section) {
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setBackgroundResource(getPanelBackgroundRes());
        card.setFocusable(true);
        card.setPadding(dp(18), dp(18), dp(18), dp(18));

        LinearLayout.LayoutParams cardParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        cardParams.bottomMargin = dp(16);
        card.setLayoutParams(cardParams);

        TextView title = new TextView(this);
        title.setText(section.title);
        title.setTextColor(getPrimaryTextColor());
        title.setTextSize(TypedValue.COMPLEX_UNIT_SP, 20);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        ViewCompat.setAccessibilityHeading(title, true);
        card.addView(title);

        TextView subtitle = new TextView(this);
        subtitle.setText(section.summary);
        subtitle.setTextColor(getSecondaryTextColor());
        subtitle.setTextSize(TypedValue.COMPLEX_UNIT_SP, 14);
        LinearLayout.LayoutParams subtitleParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        subtitleParams.topMargin = dp(8);
        subtitle.setLayoutParams(subtitleParams);
        card.addView(subtitle);

        TextView status = new TextView(this);
        status.setText(section.findings.isEmpty() ? getString(R.string.status_clean) : getString(R.string.status_warning));
        status.setTextColor(getPrimaryTextColor());
        status.setBackgroundResource(getStatusBackgroundRes(section.findings.isEmpty()));
        status.setPadding(dp(12), dp(8), dp(12), dp(8));
        LinearLayout.LayoutParams statusParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        statusParams.topMargin = dp(14);
        status.setLayoutParams(statusParams);
        card.addView(status);

        if (section.findings.isEmpty()) {
            TextView clean = new TextView(this);
            clean.setText(R.string.section_clear);
            clean.setTextColor(getSecondaryTextColor());
            LinearLayout.LayoutParams cleanParams = new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
            cleanParams.topMargin = dp(14);
            clean.setLayoutParams(cleanParams);
            card.addView(clean);
            card.setContentDescription(section.title + ". " + section.summary + ". " + getString(R.string.section_clear));
            return card;
        }

        for (ThreatFinding finding : section.findings) {
            card.addView(createFindingRow(finding));
        }
        card.setContentDescription(getString(R.string.a11y_section_summary, section.title, section.summary, section.findings.size()));
        return card;
    }

    private View createFindingRow(@NonNull ThreatFinding finding) {
        LinearLayout container = new LinearLayout(this);
        container.setOrientation(LinearLayout.VERTICAL);
        container.setBackgroundResource(getInnerBackgroundRes());
        container.setFocusable(true);
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
            iconView.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);
            LinearLayout.LayoutParams iconParams = new LinearLayout.LayoutParams(dp(26), dp(26));
            iconParams.rightMargin = dp(10);
            iconView.setLayoutParams(iconParams);
            titleRow.addView(iconView);
        }

        TextView title = new TextView(this);
        title.setText(finding.title);
        title.setTextColor(getPrimaryTextColor());
        title.setTextSize(TypedValue.COMPLEX_UNIT_SP, 16);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        LinearLayout.LayoutParams titleParams = new LinearLayout.LayoutParams(
                0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        title.setLayoutParams(titleParams);
        titleRow.addView(title);

        TextView body = new TextView(this);
        body.setText(finding.description);
        body.setTextColor(getSecondaryTextColor());
        body.setTextSize(TypedValue.COMPLEX_UNIT_SP, 14);
        LinearLayout.LayoutParams bodyParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        bodyParams.topMargin = dp(8);
        body.setLayoutParams(bodyParams);
        container.addView(body);

        MaterialButton detailsButton = new MaterialButton(this, null,
                com.google.android.material.R.attr.materialButtonOutlinedStyle);
        detailsButton.setText(R.string.details);
        detailsButton.setTextColor(getPrimaryTextColor());
        detailsButton.setStrokeColor(ContextCompat.getColorStateList(this, R.color.glass_stroke));
        detailsButton.setMinHeight(dp(48));
        detailsButton.setContentDescription(getString(R.string.a11y_details_for, finding.title));
        detailsButton.setOnClickListener(v -> showThreatDetails(finding));
        LinearLayout.LayoutParams buttonParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        buttonParams.topMargin = dp(10);
        detailsButton.setLayoutParams(buttonParams);
        container.addView(detailsButton);
        container.setContentDescription(getString(
                R.string.a11y_finding_item,
                finding.title,
                finding.attackType,
                finding.description));

        return container;
    }

    private View createRemovalOption(@NonNull ThreatFinding threat) {
        RemediationAction action = buildRemediationAction(threat);

        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.HORIZONTAL);
        card.setGravity(Gravity.CENTER_VERTICAL);
        card.setBackgroundResource(getPanelBackgroundRes());
        card.setFocusable(true);
        card.setClickable(true);
        card.setPadding(dp(14), dp(14), dp(14), dp(14));

        LinearLayout.LayoutParams cardParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        cardParams.bottomMargin = dp(12);
        card.setLayoutParams(cardParams);

        CheckBox checkBox = new CheckBox(this);
        checkBox.setChecked(threat.selectedForRemoval);
        checkBox.setMinHeight(dp(48));
        checkBox.setOnCheckedChangeListener((buttonView, isChecked) -> {
            threat.selectedForRemoval = isChecked;
            removeSelectedButton.setEnabled(hasSelectedThreats());
            removeSelectedButton.setAlpha(hasSelectedThreats() ? 1f : 0.55f);
            updateRemovalSelectionSummary(true);
            updateRemovalCardDescription(card, threat);
            persistActiveSnapshot(SCREEN_REMOVAL);
        });
        card.addView(checkBox);

        if (threat.icon != null) {
            ImageView iconView = new ImageView(this);
            iconView.setImageDrawable(threat.icon);
            iconView.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);
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
        title.setText(getRemovalPrimaryLabel(threat));
        title.setTextColor(getPrimaryTextColor());
        title.setTextSize(TypedValue.COMPLEX_UNIT_SP, 16);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        textWrap.addView(title);

        TextView subtitle = new TextView(this);
        subtitle.setText(getRemovalSecondaryLabel(threat, action));
        subtitle.setTextColor(getSecondaryTextColor());
        subtitle.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13);
        LinearLayout.LayoutParams subParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        subParams.topMargin = dp(4);
        subtitle.setLayoutParams(subParams);
        textWrap.addView(subtitle);
        card.setOnClickListener(v -> checkBox.toggle());
        updateRemovalCardDescription(card, threat);

        return card;
    }

    private TextView createSummaryPill(@NonNull String text) {
        TextView pill = new TextView(this);
        pill.setText(text);
        pill.setTextColor(getPrimaryTextColor());
        pill.setBackgroundResource(getChipBackgroundRes());
        pill.setPadding(dp(16), dp(12), dp(16), dp(12));
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        params.bottomMargin = dp(10);
        pill.setLayoutParams(params);
        return pill;
    }

    private void showThreatDetails(@NonNull ThreatFinding finding) {
        StringBuilder message = new StringBuilder();
        message.append(finding.description).append("\n\n");
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
        accessCenterScreen.setVisibility(View.GONE);
        scanScreen.setVisibility(View.GONE);
        summaryScreen.setVisibility(View.GONE);
        reportScreen.setVisibility(View.GONE);
        removalScreen.setVisibility(View.GONE);
        languageDropdown.setVisibility(View.GONE);
        updateLanguageToggleDescription(false);
        renderHistorySection();
        persistScreenState(SCREEN_HOME);
        focusAndAnnounce(homeTitle, getString(R.string.a11y_home_opened));
    }

    private void showAccessCenterScreen() {
        homeScreen.setVisibility(View.GONE);
        accessCenterScreen.setVisibility(View.VISIBLE);
        scanScreen.setVisibility(View.GONE);
        summaryScreen.setVisibility(View.GONE);
        reportScreen.setVisibility(View.GONE);
        removalScreen.setVisibility(View.GONE);
        languageDropdown.setVisibility(View.GONE);
        renderAccessCenter();
        accessCenterScreen.fullScroll(View.FOCUS_UP);
        focusAndAnnounce(accessCenterTitle, getString(R.string.access_center_title));
    }

    private void showScanScreen() {
        homeScreen.setVisibility(View.GONE);
        accessCenterScreen.setVisibility(View.GONE);
        scanScreen.setVisibility(View.VISIBLE);
        summaryScreen.setVisibility(View.GONE);
        reportScreen.setVisibility(View.GONE);
        removalScreen.setVisibility(View.GONE);
        languageDropdown.setVisibility(View.GONE);
        circularProgress.show();
        linearProgress.setProgressCompat(0, false);
        scanCounter.setText(getString(R.string.scan_counter_value, 0, TOTAL_SCAN_STEPS));
        currentScanLabel.setText(R.string.preparing_scan);
        focusAndAnnounce(scanTitle, getString(R.string.scan_progress_label));
    }

    private void showSummaryScreen(boolean danger) {
        homeScreen.setVisibility(View.GONE);
        accessCenterScreen.setVisibility(View.GONE);
        scanScreen.setVisibility(View.GONE);
        summaryScreen.setVisibility(View.VISIBLE);
        reportScreen.setVisibility(View.GONE);
        removalScreen.setVisibility(View.GONE);
        languageDropdown.setVisibility(View.GONE);
        summaryScreen.fullScroll(View.FOCUS_UP);
        summaryBody.setTextColor(ContextCompat.getColor(this, R.color.summary_text));
        summaryTitle.setTextColor(ContextCompat.getColor(this, R.color.summary_text));
        summaryFindingsContainer.setAlpha(danger ? 1f : 0.9f);
        persistActiveSnapshot(SCREEN_SUMMARY);
        focusAndAnnounce(summaryTitle, getString(danger
                ? R.string.a11y_scan_complete_danger
                : R.string.a11y_scan_complete_safe));
    }

    private void showDetailedReport() {
        homeScreen.setVisibility(View.GONE);
        accessCenterScreen.setVisibility(View.GONE);
        scanScreen.setVisibility(View.GONE);
        summaryScreen.setVisibility(View.GONE);
        reportScreen.setVisibility(View.VISIBLE);
        removalScreen.setVisibility(View.GONE);
        languageDropdown.setVisibility(View.GONE);
        reportScreen.fullScroll(View.FOCUS_UP);
        persistActiveSnapshot(SCREEN_REPORT);
        focusAndAnnounce(reportTitle, getString(R.string.a11y_report_opened));
    }

    private void showRemovalScreen() {
        homeScreen.setVisibility(View.GONE);
        accessCenterScreen.setVisibility(View.GONE);
        scanScreen.setVisibility(View.GONE);
        summaryScreen.setVisibility(View.GONE);
        reportScreen.setVisibility(View.GONE);
        removalScreen.setVisibility(View.VISIBLE);
        languageDropdown.setVisibility(View.GONE);
        renderRemovalList();
        removalScreen.fullScroll(View.FOCUS_UP);
        persistActiveSnapshot(SCREEN_REMOVAL);
        focusAndAnnounce(removalTitle, getString(R.string.a11y_removal_opened));
    }

    private void startRemovalFlow() {
        if (!hasSelectedThreats()) {
            return;
        }

        persistActiveSnapshot(SCREEN_REMOVAL);

        remediationQueue.clear();
        Set<String> queuedActions = new LinkedHashSet<>();
        for (ThreatFinding threat : lastThreats) {
            if (!isThreatActionable(threat) || !threat.selectedForRemoval) {
                continue;
            }
            RemediationAction action = buildRemediationAction(threat);
            if (action.type == RemediationActionType.NONE) {
                continue;
            }
            if (queuedActions.add(action.uniqueKey)) {
                remediationQueue.add(action);
            }
        }
        launchNextRemediationStep();
    }

    private void launchNextRemediationStep() {
        RemediationAction nextAction = remediationQueue.poll();
        if (nextAction == null) {
            showHomeScreen();
            return;
        }

        Intent intent = buildRemediationIntent(nextAction);
        if (intent == null || !canResolveIntent(intent)) {
            announceForAccessibility(getString(R.string.action_unavailable));
            launchNextRemediationStep();
            return;
        }
        try {
            remediationLauncher.launch(intent);
        } catch (ActivityNotFoundException ignored) {
            announceForAccessibility(getString(R.string.action_unavailable));
            launchNextRemediationStep();
        }
    }

    private boolean hasActionableThreats() {
        return hasActionableThreats(lastThreats);
    }

    private boolean hasActionableThreats(@NonNull List<ThreatFinding> threats) {
        for (ThreatFinding threat : threats) {
            if (isThreatActionable(threat)) {
                return true;
            }
        }
        return false;
    }

    private boolean hasSelectedThreats() {
        for (ThreatFinding threat : lastThreats) {
            if (isThreatActionable(threat) && threat.selectedForRemoval) {
                return true;
            }
        }
        return false;
    }

    private void updateRemovalSelectionSummary(boolean announce) {
        int selectedCount = 0;
        for (ThreatFinding threat : lastThreats) {
            if (isThreatActionable(threat) && threat.selectedForRemoval) {
                selectedCount++;
            }
        }
        String summary = selectedCount == 0
                ? getString(R.string.a11y_no_selected_threats)
                : getString(R.string.a11y_selected_threats, selectedCount);
        removalSelectionSummary.setText(summary);
        if (announce) {
            announceForAccessibility(summary);
        }
    }

    private void updateLanguageToggleDescription(boolean expanded) {
        languageToggleButton.setContentDescription(getString(
                expanded ? R.string.a11y_language_menu_expanded : R.string.a11y_language_menu_collapsed));
    }

    private void updateRemovalCardDescription(@NonNull View card, @NonNull ThreatFinding threat) {
        RemediationAction action = buildRemediationAction(threat);
        card.setContentDescription(getString(
                R.string.a11y_removal_item,
                getRemovalPrimaryLabel(threat),
                getRemovalSecondaryLabel(threat, action),
                getString(threat.selectedForRemoval ? R.string.a11y_selected_yes : R.string.a11y_selected_no)));
    }

    @NonNull
    private String getRemovalPrimaryLabel(@NonNull ThreatFinding threat) {
        if (threat.showAppIcon && !TextUtils.isEmpty(threat.attackType)) {
            return threat.attackType;
        }
        return threat.title;
    }

    @NonNull
    private String getRemovalSecondaryLabel(@NonNull ThreatFinding threat, @NonNull RemediationAction action) {
        String actionLabel = getRecommendedActionLabel(action.type);
        if (threat.showAppIcon && !TextUtils.isEmpty(threat.title)) {
            return threat.title + " | " + actionLabel;
        }
        return actionLabel;
    }

    private void restorePersistedState() {
        scanHistory = readHistoryFromPrefs();
        renderHistorySection();

        ScanHistoryEntry activeEntry = readActiveScanFromPrefs();
        if (activeEntry == null || activeEntry.sections.isEmpty()) {
            showHomeScreen();
            return;
        }

        lastSections = deepCopySections(activeEntry.sections);
        lastThreats = flattenFindings(lastSections);
        renderSummary(lastThreats);
        renderDetailedReport(lastSections, lastThreats);
        renderRemovalList();

        String activeScreen = getPreferences().getString(KEY_ACTIVE_SCREEN, SCREEN_HOME);
        if (SCREEN_SUMMARY.equals(activeScreen)) {
            showSummaryScreen(!lastThreats.isEmpty());
        } else if (SCREEN_REPORT.equals(activeScreen)) {
            showDetailedReport();
        } else if (SCREEN_REMOVAL.equals(activeScreen)) {
            showRemovalScreen();
        } else {
            showHomeScreen();
        }
    }

    private void renderHistorySection() {
        historyContainer.removeAllViews();
        if (scanHistory.isEmpty()) {
            historySection.setVisibility(View.GONE);
            updateHomeLayoutForHistory(false);
            return;
        }

        historySection.setVisibility(View.VISIBLE);
        updateHomeLayoutForHistory(true);
        for (ScanHistoryEntry entry : scanHistory) {
            historyContainer.addView(createHistoryCard(entry));
        }
    }

    private void renderAccessCenter() {
        accessCenterContainer.removeAllViews();
        accessCenterContainer.addView(createAccessStatusCard(
                getString(R.string.access_usage_title),
                hasUsageStatsAccess() ? getString(R.string.access_status_ready) : getString(R.string.access_status_needs_review),
                hasUsageStatsAccess() ? getString(R.string.access_usage_ready_body) : getString(R.string.access_usage_missing_body),
                hasUsageStatsAccess() ? null : () -> usageAccessLauncher.launch(new Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS))
        ));
        accessCenterContainer.addView(createAccessStatusCard(
                getString(R.string.access_media_title),
                hasAllRuntimePermissions(getRuntimePermissions()) ? getString(R.string.access_status_ready) : getString(R.string.access_status_needs_review),
                hasAllRuntimePermissions(getRuntimePermissions())
                        ? getString(R.string.access_media_ready_body)
                        : getString(R.string.access_media_missing_body),
                hasAllRuntimePermissions(getRuntimePermissions()) ? null : this::openAppDetailsSettings
        ));
        accessCenterContainer.addView(createAccessStatusCard(
                getString(R.string.access_lock_title),
                isDeviceSecure() ? getString(R.string.access_status_ready) : getString(R.string.access_status_needs_review),
                isDeviceSecure() ? getString(R.string.access_lock_ready_body) : getString(R.string.access_lock_missing_body),
                isDeviceSecure() ? null : () -> openSystemIntent(new Intent(Settings.ACTION_SECURITY_SETTINGS))
        ));

        boolean privateDnsEnabled = isPrivateDnsEnabled();
        accessCenterContainer.addView(createAccessStatusCard(
                getString(R.string.access_dns_title),
                privateDnsEnabled ? getString(R.string.access_status_ready) : getString(R.string.access_status_needs_review),
                privateDnsEnabled ? getString(R.string.access_dns_ready_body) : getString(R.string.access_dns_missing_body),
                privateDnsEnabled ? null : () -> openSystemIntent(new Intent(Settings.ACTION_WIRELESS_SETTINGS))
        ));
    }

    @NonNull
    private View createAccessStatusCard(
            @NonNull String titleText,
            @NonNull String statusText,
            @NonNull String bodyText,
            @Nullable Runnable action
    ) {
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setBackgroundResource(getPanelBackgroundRes());
        card.setPadding(dp(16), dp(16), dp(16), dp(16));

        LinearLayout.LayoutParams cardParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        cardParams.bottomMargin = dp(12);
        card.setLayoutParams(cardParams);

        LinearLayout header = new LinearLayout(this);
        header.setOrientation(LinearLayout.HORIZONTAL);
        header.setGravity(Gravity.CENTER_VERTICAL);
        card.addView(header);

        TextView title = new TextView(this);
        title.setText(titleText);
        title.setTextColor(getPrimaryTextColor());
        title.setTextSize(TypedValue.COMPLEX_UNIT_SP, 16);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        LinearLayout.LayoutParams titleParams = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        title.setLayoutParams(titleParams);
        header.addView(title);

        TextView status = new TextView(this);
        status.setText(statusText);
        status.setTextColor(getPrimaryTextColor());
        status.setBackgroundResource(getChipBackgroundRes());
        status.setPadding(dp(12), dp(8), dp(12), dp(8));
        header.addView(status);

        TextView body = new TextView(this);
        body.setText(bodyText);
        body.setTextColor(getSecondaryTextColor());
        body.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13);
        LinearLayout.LayoutParams bodyParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        bodyParams.topMargin = dp(8);
        body.setLayoutParams(bodyParams);
        card.addView(body);

        if (action != null) {
            MaterialButton button = new MaterialButton(this, null,
                    com.google.android.material.R.attr.materialButtonOutlinedStyle);
            button.setText(R.string.open_settings);
            button.setTextColor(getPrimaryTextColor());
            button.setStrokeColor(ContextCompat.getColorStateList(this, R.color.glass_stroke));
            button.setMinHeight(dp(44));
            button.setOnClickListener(v -> action.run());
            LinearLayout.LayoutParams buttonParams = new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
            buttonParams.topMargin = dp(10);
            button.setLayoutParams(buttonParams);
            card.addView(button);
        }

        return card;
    }

    private void confirmClearHistory() {
        new MaterialAlertDialogBuilder(this)
                .setTitle(R.string.clear_history)
                .setMessage(R.string.clear_history_message)
                .setPositiveButton(R.string.clear_history, (dialog, which) -> {
                    scanHistory = new ArrayList<>();
                    getPreferences().edit().remove(KEY_SCAN_HISTORY).apply();
                    renderHistorySection();
                })
                .setNegativeButton(android.R.string.cancel, null)
                .show();
    }

    private void openAppDetailsSettings() {
        Intent intent = new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS);
        intent.setData(Uri.parse("package:" + getPackageName()));
        openSystemIntent(intent);
    }

    private void openSystemIntent(@NonNull Intent intent) {
        if (canResolveIntent(intent)) {
            startActivity(intent);
        } else {
            announceForAccessibility(getString(R.string.action_unavailable));
        }
    }

    private boolean isPrivateDnsEnabled() {
        String privateDnsMode = Settings.Global.getString(getContentResolver(), "private_dns_mode");
        return !TextUtils.isEmpty(privateDnsMode) && !"off".equalsIgnoreCase(privateDnsMode);
    }

    private void updateHomeLayoutForHistory(boolean hasHistory) {
        ViewGroup.LayoutParams layoutParams = homeContent.getLayoutParams();
        layoutParams.height = hasHistory ? ViewGroup.LayoutParams.WRAP_CONTENT : ViewGroup.LayoutParams.MATCH_PARENT;
        homeContent.setLayoutParams(layoutParams);
        homeContent.setGravity(hasHistory ? Gravity.TOP | Gravity.CENTER_HORIZONTAL : Gravity.CENTER);
    }

    @NonNull
    private View createHistoryCard(@NonNull ScanHistoryEntry entry) {
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setBackgroundResource(getInnerBackgroundRes());
        card.setClickable(true);
        card.setFocusable(true);
        card.setPadding(dp(14), dp(14), dp(14), dp(14));

        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        params.bottomMargin = dp(10);
        card.setLayoutParams(params);

        TextView title = new TextView(this);
        title.setText(formatHistoryTimestamp(entry.timestamp));
        title.setTextColor(getPrimaryTextColor());
        title.setTextSize(TypedValue.COMPLEX_UNIT_SP, 16);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        card.addView(title);

        TextView subtitle = new TextView(this);
        subtitle.setText(getString(R.string.history_item_threats, flattenFindings(entry.sections).size()));
        subtitle.setTextColor(getSecondaryTextColor());
        subtitle.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13);
        LinearLayout.LayoutParams subtitleParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        subtitleParams.topMargin = dp(4);
        subtitle.setLayoutParams(subtitleParams);
        card.addView(subtitle);

        String contentDescription = getString(
                R.string.history_item_content_description,
                title.getText(),
                flattenFindings(entry.sections).size());
        card.setContentDescription(contentDescription);
        card.setOnClickListener(v -> openHistoryEntry(entry));
        return card;
    }

    private void openHistoryEntry(@NonNull ScanHistoryEntry entry) {
        lastSections = deepCopySections(entry.sections);
        lastThreats = flattenFindings(lastSections);
        renderSummary(lastThreats);
        renderDetailedReport(lastSections, lastThreats);
        renderRemovalList();
        persistActiveSnapshot(SCREEN_REPORT);
        showDetailedReport();
    }

    @NonNull
    private String formatHistoryTimestamp(long timestamp) {
        Locale locale = createLocale(getSelectedLanguage());
        DateFormat formatter = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT, locale);
        return formatter.format(new Date(timestamp));
    }

    private void appendScanToHistory(@NonNull List<ScanSection> sections) {
        List<ScanHistoryEntry> updated = new ArrayList<>();
        updated.add(new ScanHistoryEntry(System.currentTimeMillis(), deepCopySections(sections)));
        for (ScanHistoryEntry entry : scanHistory) {
            if (updated.size() >= MAX_HISTORY_ENTRIES) {
                break;
            }
            updated.add(entry);
        }
        scanHistory = updated;
        persistHistory();
    }

    private void persistActiveSnapshot(@NonNull String screen) {
        SharedPreferences.Editor editor = getPreferences().edit().putString(KEY_ACTIVE_SCREEN, screen);
        if (lastSections.isEmpty()) {
            editor.remove(KEY_ACTIVE_SCAN).apply();
            return;
        }
        ScanHistoryEntry activeEntry = new ScanHistoryEntry(System.currentTimeMillis(), deepCopySections(lastSections));
        editor.putString(KEY_ACTIVE_SCAN, serializeHistoryEntry(activeEntry).toString()).apply();
    }

    private void persistScreenState(@NonNull String screen) {
        getPreferences().edit().putString(KEY_ACTIVE_SCREEN, screen).apply();
    }

    @NonNull
    private SharedPreferences getPreferences() {
        return getSharedPreferences(PREFS_NAME, MODE_PRIVATE);
    }

    private void persistHistory() {
        JSONArray array = new JSONArray();
        for (ScanHistoryEntry entry : scanHistory) {
            array.put(serializeHistoryEntry(entry));
        }
        getPreferences().edit().putString(KEY_SCAN_HISTORY, array.toString()).apply();
    }

    @NonNull
    private List<ScanHistoryEntry> readHistoryFromPrefs() {
        String raw = getPreferences().getString(KEY_SCAN_HISTORY, "");
        if (TextUtils.isEmpty(raw)) {
            return new ArrayList<>();
        }

        List<ScanHistoryEntry> entries = new ArrayList<>();
        try {
            JSONArray array = new JSONArray(raw);
            for (int i = 0; i < array.length(); i++) {
                JSONObject object = array.optJSONObject(i);
                if (object == null) {
                    continue;
                }
                ScanHistoryEntry entry = deserializeHistoryEntry(object);
                if (entry != null) {
                    entries.add(entry);
                }
            }
        } catch (JSONException e) {
            logWarn("Failed to parse scan history", e);
        }
        return entries;
    }

    @Nullable
    private ScanHistoryEntry readActiveScanFromPrefs() {
        String raw = getPreferences().getString(KEY_ACTIVE_SCAN, "");
        if (TextUtils.isEmpty(raw)) {
            return null;
        }
        try {
            return deserializeHistoryEntry(new JSONObject(raw));
        } catch (JSONException e) {
            logWarn("Failed to parse active scan", e);
            return null;
        }
    }

    @NonNull
    private JSONObject serializeHistoryEntry(@NonNull ScanHistoryEntry entry) {
        JSONObject object = new JSONObject();
        try {
            object.put("timestamp", entry.timestamp);
            JSONArray sectionsArray = new JSONArray();
            for (ScanSection section : entry.sections) {
                JSONObject sectionObject = new JSONObject();
                sectionObject.put("title", section.title);
                sectionObject.put("summary", section.summary);
                JSONArray findingArray = new JSONArray();
                for (ThreatFinding finding : section.findings) {
                    findingArray.put(serializeThreatFinding(finding));
                }
                sectionObject.put("findings", findingArray);
                sectionsArray.put(sectionObject);
            }
            object.put("sections", sectionsArray);
        } catch (JSONException e) {
            logWarn("Failed to serialize history entry", e);
        }
        return object;
    }

    @Nullable
    private ScanHistoryEntry deserializeHistoryEntry(@NonNull JSONObject object) {
        JSONArray sectionsArray = object.optJSONArray("sections");
        if (sectionsArray == null) {
            return null;
        }

        List<ScanSection> sections = new ArrayList<>();
        for (int i = 0; i < sectionsArray.length(); i++) {
            JSONObject sectionObject = sectionsArray.optJSONObject(i);
            if (sectionObject == null) {
                continue;
            }

            List<ThreatFinding> findings = new ArrayList<>();
            JSONArray findingArray = sectionObject.optJSONArray("findings");
            if (findingArray != null) {
                for (int j = 0; j < findingArray.length(); j++) {
                    JSONObject findingObject = findingArray.optJSONObject(j);
                    if (findingObject == null) {
                        continue;
                    }
                    ThreatFinding finding = deserializeThreatFinding(findingObject);
                    if (finding != null) {
                        findings.add(finding);
                    }
                }
            }

            sections.add(new ScanSection(
                    sectionObject.optString("title"),
                    sectionObject.optString("summary"),
                    findings
            ));
        }

        return new ScanHistoryEntry(object.optLong("timestamp", System.currentTimeMillis()), sections);
    }

    @NonNull
    private JSONObject serializeThreatFinding(@NonNull ThreatFinding finding) {
        JSONObject object = new JSONObject();
        try {
            object.put("title", finding.title);
            object.put("description", finding.description);
            object.put("attackType", finding.attackType);
            object.put("location", finding.location);
            object.put("whyFlagged", getRawWhyFlagged(finding));
            object.put("remediationHint", finding.remediationHint);
            object.put("removablePackage", finding.removablePackage);
            object.put("removable", finding.removable);
            object.put("showAppIcon", finding.showAppIcon);
            object.put("selectedForRemoval", finding.selectedForRemoval);
        } catch (JSONException e) {
            logWarn("Failed to serialize finding", e);
        }
        return object;
    }

    @Nullable
    private ThreatFinding deserializeThreatFinding(@NonNull JSONObject object) {
        String packageName = object.optString("removablePackage", "");
        if (TextUtils.isEmpty(packageName)) {
            packageName = null;
        }
        boolean showAppIcon = object.optBoolean("showAppIcon");
        Drawable icon = showAppIcon ? resolveThreatIcon(packageName, object.optString("location")) : null;
        ThreatFinding finding = new ThreatFinding(
                object.optString("title"),
                object.optString("description"),
                object.optString("attackType"),
                object.optString("location"),
                object.optString("whyFlagged"),
                object.optString("remediationHint"),
                packageName,
                icon,
                object.optBoolean("removable"),
                showAppIcon
        );
        finding.selectedForRemoval = object.optBoolean("selectedForRemoval", false);
        return finding;
    }

    @NonNull
    private String getRawWhyFlagged(@NonNull ThreatFinding finding) {
        if (!TextUtils.isEmpty(finding.remediationHint)) {
            String suffix = "\n" + finding.remediationHint;
            if (finding.whyFlagged.endsWith(suffix)) {
                return finding.whyFlagged.substring(0, finding.whyFlagged.length() - suffix.length());
            }
        }
        return finding.whyFlagged;
    }

    @Nullable
    private Drawable resolveThreatIcon(@Nullable String removablePackage, @Nullable String location) {
        String packageName = !TextUtils.isEmpty(removablePackage) ? removablePackage : location;
        if (!isValidPackageName(packageName)) {
            return null;
        }
        try {
            return getPackageManager().getApplicationIcon(packageName);
        } catch (Exception ignored) {
            return null;
        }
    }

    @NonNull
    private List<ScanSection> deepCopySections(@NonNull List<ScanSection> source) {
        List<ScanSection> copy = new ArrayList<>();
        for (ScanSection section : source) {
            List<ThreatFinding> findings = new ArrayList<>();
            for (ThreatFinding finding : section.findings) {
                findings.add(copyThreatFinding(finding));
            }
            copy.add(new ScanSection(section.title, section.summary, findings));
        }
        return copy;
    }

    @NonNull
    private ThreatFinding copyThreatFinding(@NonNull ThreatFinding source) {
        ThreatFinding copy = new ThreatFinding(
                source.title,
                source.description,
                source.attackType,
                source.location,
                getRawWhyFlagged(source),
                source.remediationHint,
                source.removablePackage,
                source.icon,
                source.removable,
                source.showAppIcon
        );
        copy.selectedForRemoval = source.selectedForRemoval;
        return copy;
    }

    private void focusAndAnnounce(@NonNull View view, @NonNull String announcement) {
        view.post(() -> {
            view.requestFocus();
            announceForAccessibility(announcement);
        });
    }

    private void announceForAccessibility(@NonNull String message) {
        AccessibilityManager accessibilityManager =
                (AccessibilityManager) getSystemService(Context.ACCESSIBILITY_SERVICE);
        if (accessibilityManager != null && accessibilityManager.isEnabled()) {
            View root = findViewById(R.id.main);
            if (root != null) {
                root.announceForAccessibility(message);
            }
        }
    }

    private boolean isHighContrastEnabled() {
        boolean systemHighContrast = false;
        try {
            systemHighContrast = Settings.Secure.getInt(
                    getContentResolver(),
                    "high_text_contrast_enabled",
                    0
            ) == 1;
        } catch (Exception ignored) {
            // Fall back to font scale heuristic below.
        }
        return systemHighContrast || getResources().getConfiguration().fontScale >= 1.3f;
    }

    private void applyAccessibilityVisualMode() {
        homeHeroCard.setBackgroundResource(getHeroBackgroundRes());
        languageToggleButton.setBackgroundResource(getPanelBackgroundRes());
        languageDropdown.setBackgroundResource(getPanelBackgroundRes());
        historySection.setBackgroundResource(getPanelBackgroundRes());
        currentScanLabel.setBackgroundResource(getPanelBackgroundRes());
        scanningPanel.setBackgroundResource(getScanPanelBackgroundRes());
        startScanButton.setBackgroundResource(getButtonBackgroundRes());
        reviewAccessButton.setBackgroundResource(getPanelBackgroundRes());
        viewReportButton.setBackgroundResource(getButtonBackgroundRes());
        reportPrimaryButton.setBackgroundResource(getButtonBackgroundRes());
        removeSelectedButton.setBackgroundResource(getButtonBackgroundRes());

        homeTitle.setTextColor(getPrimaryTextColor());
        scanTitle.setTextColor(getPrimaryTextColor());
        accessCenterTitle.setTextColor(getPrimaryTextColor());
        reportTitle.setTextColor(getPrimaryTextColor());
        removalTitle.setTextColor(getPrimaryTextColor());
        currentScanLabel.setTextColor(getPrimaryTextColor());
        scanCounter.setTextColor(getPrimaryTextColor());
        scanFootnote.setTextColor(getSecondaryTextColor());
        summaryBody.setTextColor(ContextCompat.getColor(this, R.color.summary_text));
        removalSelectionSummary.setTextColor(getPrimaryTextColor());
        reviewAccessButton.setTextColor(getPrimaryTextColor());
        clearHistoryButton.setTextColor(getPrimaryTextColor());
        accessCenterBackButton.setTextColor(getPrimaryTextColor());
    }

    private int getPrimaryTextColor() {
        return ContextCompat.getColor(this, highContrastMode ? R.color.accessible_ink_primary : R.color.ink_primary);
    }

    private int getSecondaryTextColor() {
        return ContextCompat.getColor(this, highContrastMode ? R.color.accessible_ink_secondary : R.color.ink_secondary);
    }

    private int getPanelBackgroundRes() {
        return highContrastMode ? R.drawable.bg_glass_panel_accessible : R.drawable.bg_glass_panel;
    }

    private int getHeroBackgroundRes() {
        return highContrastMode ? R.drawable.bg_glass_hero_accessible : R.drawable.bg_glass_hero;
    }

    private int getButtonBackgroundRes() {
        return highContrastMode ? R.drawable.bg_glass_button_accessible : R.drawable.bg_glass_button;
    }

    private int getInnerBackgroundRes() {
        return highContrastMode ? R.drawable.bg_inner_glass_accessible : R.drawable.bg_inner_glass;
    }

    private int getScanPanelBackgroundRes() {
        return highContrastMode ? R.drawable.bg_scan_panel_accessible : R.drawable.bg_scan_panel;
    }

    private int getChipBackgroundRes() {
        return highContrastMode ? R.drawable.bg_chip_accessible : R.drawable.bg_chip;
    }

    private int getStatusBackgroundRes(boolean clean) {
        if (highContrastMode) {
            return clean ? R.drawable.bg_status_safe_accessible : R.drawable.bg_status_danger_accessible;
        }
        return clean ? R.drawable.bg_status_safe : R.drawable.bg_status_danger;
    }

    private boolean isThreatActionable(@NonNull ThreatFinding threat) {
        return buildRemediationAction(threat).type != RemediationActionType.NONE;
    }

    @NonNull
    private RemediationAction buildRemediationAction(@NonNull ThreatFinding threat) {
        String packageName = threat.removablePackage != null ? threat.removablePackage : threat.location;
        String reasonText = threat.whyFlagged == null ? "" : threat.whyFlagged;

        if (threat.attackType.equals(getString(R.string.attack_type_permissions))) {
            return new RemediationAction(
                    RemediationActionType.APP_SETTINGS,
                    packageName,
                    getString(R.string.action_open_app_settings),
                    RemediationActionType.APP_SETTINGS.name() + ":" + packageName
            );
        }

        if (threat.attackType.equals(getString(R.string.attack_type_install_trust))) {
            if (!TextUtils.isEmpty(packageName) && packageName.contains(".")) {
                return new RemediationAction(
                        RemediationActionType.UNKNOWN_APP_SOURCES,
                        packageName,
                        getString(R.string.action_review_unknown_installs),
                        RemediationActionType.UNKNOWN_APP_SOURCES.name() + ":" + packageName
                );
            }
            return new RemediationAction(
                    RemediationActionType.SECURITY_SETTINGS,
                    "",
                    getString(R.string.action_review_security_settings),
                    RemediationActionType.SECURITY_SETTINGS.name()
            );
        }

        if (threat.attackType.equals(getString(R.string.attack_type_default_handler))) {
            return new RemediationAction(
                    RemediationActionType.DEFAULT_APPS,
                    packageName,
                    getString(R.string.action_review_default_apps),
                    RemediationActionType.DEFAULT_APPS.name()
            );
        }

        if (threat.attackType.equals(getString(R.string.attack_type_persistence))) {
            if (reasonText.contains(getString(R.string.reason_accessibility_on))) {
                return new RemediationAction(
                        RemediationActionType.ACCESSIBILITY_SETTINGS,
                        packageName,
                        getString(R.string.action_review_accessibility),
                        RemediationActionType.ACCESSIBILITY_SETTINGS.name() + ":" + packageName
                );
            }
            if (reasonText.contains(getString(R.string.reason_notification_access))) {
                return new RemediationAction(
                        RemediationActionType.NOTIFICATION_LISTENER_SETTINGS,
                        packageName,
                        getString(R.string.action_review_notification_access),
                        RemediationActionType.NOTIFICATION_LISTENER_SETTINGS.name()
                );
            }
            if (reasonText.contains(getString(R.string.reason_overlay))
                    || reasonText.contains(getString(R.string.reason_overlay_access))) {
                return new RemediationAction(
                        RemediationActionType.OVERLAY_SETTINGS,
                        packageName,
                        getString(R.string.action_review_overlay),
                        RemediationActionType.OVERLAY_SETTINGS.name() + ":" + packageName
                );
            }
            if (reasonText.contains(getString(R.string.reason_battery_bypass))) {
                return new RemediationAction(
                        RemediationActionType.APP_SETTINGS,
                        packageName,
                        getString(R.string.action_open_app_settings),
                        RemediationActionType.APP_SETTINGS.name() + ":" + packageName
                );
            }
            return new RemediationAction(
                    RemediationActionType.APP_SETTINGS,
                    packageName,
                    getString(R.string.action_open_app_settings),
                    RemediationActionType.APP_SETTINGS.name() + ":" + packageName
            );
        }

        if (threat.attackType.equals(getString(R.string.attack_type_surveillance))
                || threat.attackType.equals(getString(R.string.attack_type_keylogger))
                || threat.attackType.equals(getString(R.string.attack_type_sensitive_service))
                || threat.attackType.equals(getString(R.string.attack_type_accessibility))) {
            return new RemediationAction(
                    RemediationActionType.APP_SETTINGS,
                    packageName,
                    getString(R.string.action_open_app_settings),
                    RemediationActionType.APP_SETTINGS.name() + ":" + packageName
            );
        }

        if (threat.attackType.equals(getString(R.string.attack_type_component_surface))) {
            return new RemediationAction(
                    RemediationActionType.PLAY_STORE_UPDATE,
                    packageName,
                    getString(R.string.action_check_for_update),
                    RemediationActionType.PLAY_STORE_UPDATE.name() + ":" + packageName
            );
        }

        if (threat.attackType.equals(getString(R.string.attack_type_sideload))) {
            return new RemediationAction(
                    RemediationActionType.PLAY_STORE_UPDATE,
                    packageName,
                    getString(R.string.action_verify_source_or_update),
                    RemediationActionType.PLAY_STORE_UPDATE.name() + ":" + packageName
            );
        }

        if (threat.attackType.equals(getString(R.string.attack_type_remote))) {
            return new RemediationAction(
                    RemediationActionType.DEVELOPMENT_SETTINGS,
                    "",
                    getString(R.string.action_review_developer_settings),
                    RemediationActionType.DEVELOPMENT_SETTINGS.name()
            );
        }

        if (threat.attackType.equals(getString(R.string.attack_type_hardening))) {
            return new RemediationAction(
                    RemediationActionType.SECURITY_SETTINGS,
                    "",
                    getString(R.string.action_review_security_settings),
                    RemediationActionType.SECURITY_SETTINGS.name()
            );
        }

        if (threat.removable && !TextUtils.isEmpty(threat.removablePackage)) {
            return new RemediationAction(
                    RemediationActionType.UNINSTALL,
                    threat.removablePackage,
                    getString(R.string.action_uninstall_app),
                    RemediationActionType.UNINSTALL.name() + ":" + threat.removablePackage
            );
        }

        return new RemediationAction(RemediationActionType.NONE, packageName, "", "none");
    }

    @Nullable
    private Intent buildRemediationIntent(@NonNull RemediationAction action) {
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

    private boolean canResolveIntent(@NonNull Intent intent) {
        PackageManager packageManager = getPackageManager();
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            return packageManager.resolveActivity(intent,
                    PackageManager.ResolveInfoFlags.of(PackageManager.MATCH_DEFAULT_ONLY)) != null;
        }
        return packageManager.resolveActivity(intent, PackageManager.MATCH_DEFAULT_ONLY) != null;
    }

    @NonNull
    private String getRecommendedActionLabel(@NonNull RemediationActionType actionType) {
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

    private boolean isValidPackageName(@Nullable String packageName) {
        return !TextUtils.isEmpty(packageName) && packageName.matches(PACKAGE_NAME_PATTERN);
    }

    private void logWarn(@NonNull String message, @Nullable Throwable throwable) {
        if (isDebugLoggingEnabled()) {
            Log.w(TAG, message, throwable);
        }
    }

    private void logError(@NonNull String message, @Nullable Throwable throwable) {
        if (isDebugLoggingEnabled()) {
            Log.e(TAG, message, throwable);
        }
    }

    private boolean isDebugLoggingEnabled() {
        return (getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0;
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

    private static final class ScanHistoryEntry {
        final long timestamp;
        final List<ScanSection> sections;

        ScanHistoryEntry(long timestamp, @NonNull List<ScanSection> sections) {
            this.timestamp = timestamp;
            this.sections = sections;
        }
    }

    private enum RemediationActionType {
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

    private static final class RemediationAction {
        final RemediationActionType type;
        final String packageName;
        final String label;
        final String uniqueKey;

        RemediationAction(
                @NonNull RemediationActionType type,
                @Nullable String packageName,
                @NonNull String label,
                @NonNull String uniqueKey
        ) {
            this.type = type;
            this.packageName = packageName == null ? "" : packageName;
            this.label = label;
            this.uniqueKey = uniqueKey;
        }
    }

    @NonNull
    private static String getStoredLanguage(@NonNull Context context) {
        return context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .getString(KEY_LANGUAGE, DEFAULT_LANGUAGE);
    }

    @NonNull
    private static Context wrapContextWithLocale(@NonNull Context context, @Nullable String languageCode) {
        Locale locale = createLocale(languageCode);
        Locale.setDefault(locale);
        Configuration configuration = new Configuration(context.getResources().getConfiguration());
        configuration.setLocale(locale);
        configuration.setLayoutDirection(locale);
        return context.createConfigurationContext(configuration);
    }

    @NonNull
    private static Locale createLocale(@Nullable String languageCode) {
        if (TextUtils.isEmpty(languageCode)) {
            return Locale.ENGLISH;
        }
        if ("zh".equals(languageCode)) {
            return Locale.SIMPLIFIED_CHINESE;
        }
        return Locale.forLanguageTag(languageCode);
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
