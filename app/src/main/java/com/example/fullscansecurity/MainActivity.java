package com.example.fullscansecurity;

import android.content.ActivityNotFoundException;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import android.text.TextUtils;
import android.view.View;
import android.view.WindowManager;
import android.widget.CheckBox;
import android.widget.LinearLayout;
import android.widget.TextView;

import androidx.activity.EdgeToEdge;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.StringRes;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.ContextCompat;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;
import androidx.core.widget.NestedScrollView;

import com.example.fullscansecurity.data.ScanStore;
import com.example.fullscansecurity.model.RemediationAction;
import com.example.fullscansecurity.model.ScanHistoryEntry;
import com.example.fullscansecurity.model.ScanSection;
import com.example.fullscansecurity.model.ThreatFinding;
import com.example.fullscansecurity.remediation.RemediationPlanner;
import com.example.fullscansecurity.scan.ScanEngine;
import com.example.fullscansecurity.ui.A11y;
import com.example.fullscansecurity.ui.Views;
import com.google.android.material.button.MaterialButton;
import com.google.android.material.dialog.MaterialAlertDialogBuilder;
import com.google.android.material.progressindicator.CircularProgressIndicator;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Lifecycle, navigation between the six screens, and rendering. Scanning, storage and fixes live in their packages. */
public class MainActivity extends AppCompatActivity {

    private enum Screen { HOME, ACCESS, SCAN, SUMMARY, REPORT, REMOVAL }

    private static final int[] LANGUAGE_NAMES = {
            R.string.language_english, R.string.language_spanish, R.string.language_german,
            R.string.language_chinese, R.string.language_slovenian
    };
    private static final int HISTORY_ROWS = 5;

    private final ExecutorService scanExecutor = Executors.newSingleThreadExecutor();
    private final Handler mainHandler = new Handler(Looper.getMainLooper());
    private final ArrayDeque<RemediationAction> remediationQueue = new ArrayDeque<>();
    private final Map<Screen, NestedScrollView> screens = new LinkedHashMap<>();

    private ScanEngine engine;
    private ScanStore store;
    private RemediationPlanner planner;
    private Views views;
    private View root;

    private LinearLayout languageDropdown;
    private MaterialButton languageToggleButton;
    private MaterialButton reportPrimaryButton;
    private MaterialButton removeSelectedButton;
    private TextView homeTitle;
    private TextView scanTitle;
    private TextView accessCenterTitle;
    private TextView reportTitle;
    private TextView removalTitle;
    private TextView currentScanLabel;
    private TextView scanCounter;
    private TextView removalSelectionSummary;
    private TextView summaryCount;
    private TextView summaryTitle;
    private TextView summaryBody;
    private CircularProgressIndicator circularProgress;
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
        super.attachBaseContext(LocaleController.wrapContextWithLocale(newBase, LocaleController.getStoredLanguage(newBase)));
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        highContrastMode = A11y.isHighContrast(this);
        if (highContrastMode) {
            setTheme(R.style.Theme_FullScanSecurity_HighContrast);
        }
        super.onCreate(savedInstanceState);
        EdgeToEdge.enable(this);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        setContentView(R.layout.activity_main);
        engine = new ScanEngine(this);
        store = new ScanStore(this);
        planner = new RemediationPlanner(this);
        views = new Views(this);
        reducedMotionMode = A11y.isReducedMotion();
        bindViews();
        ViewCompat.setOnApplyWindowInsetsListener(root, (view, insets) -> {
            Insets bars = insets.getInsets(WindowInsetsCompat.Type.systemBars());
            view.setPadding(bars.left, bars.top, bars.right, bars.bottom);
            return insets;
        });
        registerLaunchers();
        setupActions();
        setupAccessibility();
        restorePersistedState();
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (A11y.isHighContrast(this) != highContrastMode) {
            recreate();
            return;
        }
        reducedMotionMode = A11y.isReducedMotion();
        if (isShowing(Screen.ACCESS)) {
            renderAccessCenter();
        }
        if (pendingScanRequest && !scanInProgress && engine.hasUsageStatsAccess()) {
            startScan();
        }
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        scanExecutor.shutdownNow();
    }

    private void bindViews() {
        root = findViewById(R.id.main);
        screens.put(Screen.HOME, findViewById(R.id.homeScreen));
        screens.put(Screen.ACCESS, findViewById(R.id.accessCenterScreen));
        screens.put(Screen.SCAN, findViewById(R.id.scanScreen));
        screens.put(Screen.SUMMARY, findViewById(R.id.summaryScreen));
        screens.put(Screen.REPORT, findViewById(R.id.reportScreen));
        screens.put(Screen.REMOVAL, findViewById(R.id.removalScreen));
        languageDropdown = findViewById(R.id.languageDropdown);
        languageToggleButton = findViewById(R.id.languageToggleButton);
        reportPrimaryButton = findViewById(R.id.reportPrimaryButton);
        removeSelectedButton = findViewById(R.id.removeSelectedButton);
        homeTitle = findViewById(R.id.homeTitle);
        scanTitle = findViewById(R.id.scanTitle);
        accessCenterTitle = findViewById(R.id.accessCenterTitle);
        reportTitle = findViewById(R.id.reportTitle);
        removalTitle = findViewById(R.id.removalTitle);
        currentScanLabel = findViewById(R.id.currentScanLabel);
        scanCounter = findViewById(R.id.scanCounter);
        removalSelectionSummary = findViewById(R.id.removalSelectionSummary);
        summaryCount = findViewById(R.id.summaryCount);
        summaryTitle = findViewById(R.id.summaryTitle);
        summaryBody = findViewById(R.id.summaryBody);
        circularProgress = findViewById(R.id.circularProgress);
        historySection = findViewById(R.id.historySection);
        historyContainer = findViewById(R.id.historyContainer);
        accessCenterContainer = findViewById(R.id.accessCenterContainer);
        summaryFindingsContainer = findViewById(R.id.summaryFindingsContainer);
        reportSectionsContainer = findViewById(R.id.reportSectionsContainer);
        removalThreatsContainer = findViewById(R.id.removalThreatsContainer);
    }

    private void registerLaunchers() {
        permissionLauncher = registerForActivityResult(
                new ActivityResultContracts.RequestMultiplePermissions(),
                result -> continueAfterPermissionStep());
        usageAccessLauncher = registerForActivityResult(
                new ActivityResultContracts.StartActivityForResult(),
                result -> {
                    if (pendingScanRequest && !scanInProgress) {
                        startScan();
                    }
                });
        remediationLauncher = registerForActivityResult(
                new ActivityResultContracts.StartActivityForResult(),
                result -> launchNextRemediationStep());
    }

    private void setupActions() {
        languageToggleButton.setOnClickListener(v -> toggleLanguageDropdown());
        findViewById(R.id.startScanButton).setOnClickListener(v -> requestAccessAndStart());
        findViewById(R.id.reviewAccessButton).setOnClickListener(v -> show(Screen.ACCESS));
        findViewById(R.id.viewReportButton).setOnClickListener(v -> show(Screen.REPORT));
        reportPrimaryButton.setOnClickListener(v -> show(hasActionableThreats() ? Screen.REMOVAL : Screen.HOME));
        removeSelectedButton.setOnClickListener(v -> startRemovalFlow());
        findViewById(R.id.removalBackButton).setOnClickListener(v -> show(Screen.REPORT));
        findViewById(R.id.clearHistoryButton).setOnClickListener(v -> confirmClearHistory());
        findViewById(R.id.accessCenterBackButton).setOnClickListener(v -> show(Screen.HOME));
        renderLanguageOptions();
    }

    private void setupAccessibility() {
        for (TextView title : new TextView[]{homeTitle, scanTitle, accessCenterTitle, summaryTitle, reportTitle, removalTitle}) {
            ViewCompat.setAccessibilityHeading(title, true);
        }
        updateLanguageToggleDescription(false);
        updateRemovalSelectionSummary(false);
    }

    // ---- navigation ----

    private boolean isShowing(@NonNull Screen screen) {
        NestedScrollView view = screens.get(screen);
        return view != null && view.getVisibility() == View.VISIBLE;
    }

    private void show(@NonNull Screen target) {
        for (Map.Entry<Screen, NestedScrollView> entry : screens.entrySet()) {
            entry.getValue().setVisibility(entry.getKey() == target ? View.VISIBLE : View.GONE);
        }
        languageDropdown.setVisibility(View.GONE);
        updateLanguageToggleDescription(false);
        NestedScrollView screen = screens.get(target);
        if (screen != null) {
            screen.scrollTo(0, 0);
        }
        switch (target) {
            case HOME:
                renderHistorySection();
                store.saveScreen(ScanStore.SCREEN_HOME);
                A11y.focusAndAnnounce(homeTitle, root, getString(R.string.a11y_home_opened));
                break;
            case ACCESS:
                renderAccessCenter();
                A11y.focusAndAnnounce(accessCenterTitle, root, getString(R.string.access_center_title));
                break;
            case SCAN:
                circularProgress.setMax(engine.checkCount());
                circularProgress.setProgressCompat(0, false);
                scanCounter.setText(getString(R.string.scan_counter_value, 0, engine.checkCount()));
                currentScanLabel.setText(R.string.preparing_scan);
                A11y.focusAndAnnounce(scanTitle, root, getString(R.string.scan_progress_label));
                break;
            case SUMMARY:
                store.saveActiveSnapshot(ScanStore.SCREEN_SUMMARY, lastSections);
                A11y.focusAndAnnounce(summaryTitle, root, getString(lastThreats.isEmpty()
                        ? R.string.a11y_scan_complete_safe
                        : R.string.a11y_scan_complete_danger));
                break;
            case REPORT:
                store.saveActiveSnapshot(ScanStore.SCREEN_REPORT, lastSections);
                A11y.focusAndAnnounce(reportTitle, root, getString(R.string.a11y_report_opened));
                break;
            case REMOVAL:
                renderRemovalList();
                store.saveActiveSnapshot(ScanStore.SCREEN_REMOVAL, lastSections);
                A11y.focusAndAnnounce(removalTitle, root, getString(R.string.a11y_removal_opened));
                break;
        }
    }

    // ---- language ----

    private void renderLanguageOptions() {
        String selected = LocaleController.getStoredLanguage(this);
        languageDropdown.removeAllViews();
        for (int i = 0; i < LocaleController.LANGUAGES.length; i++) {
            String code = LocaleController.LANGUAGES[i];
            boolean isSelected = code.equals(selected);
            LinearLayout row = views.tappableRow(48);
            TextView label = views.text(isSelected ? R.style.TextAppearance_FullScan_Label : R.style.TextAppearance_FullScan_Body,
                    getString(LANGUAGE_NAMES[i]));
            if (isSelected) {
                label.setTextColor(ContextCompat.getColor(this, R.color.accent));
            }
            row.addView(label, Views.weighted());
            row.setSelected(isSelected);
            row.setContentDescription(getString(LANGUAGE_NAMES[i]) + ". "
                    + getString(isSelected ? R.string.a11y_selected_yes : R.string.a11y_selected_no));
            row.setOnClickListener(v -> selectLanguage(code));
            languageDropdown.addView(row);
        }
    }

    private void toggleLanguageDropdown() {
        if (!isShowing(Screen.HOME)) {
            return;
        }
        boolean expanded = languageDropdown.getVisibility() != View.VISIBLE;
        languageDropdown.setVisibility(expanded ? View.VISIBLE : View.GONE);
        updateLanguageToggleDescription(expanded);
        A11y.announce(root, getString(expanded ? R.string.a11y_language_menu_expanded : R.string.a11y_language_menu_collapsed));
    }

    private void selectLanguage(@NonNull String languageCode) {
        if (languageCode.equals(LocaleController.getStoredLanguage(this))) {
            languageDropdown.setVisibility(View.GONE);
            updateLanguageToggleDescription(false);
            return;
        }
        LocaleController.saveLanguage(this, languageCode);
        recreate();
    }

    private void updateLanguageToggleDescription(boolean expanded) {
        languageToggleButton.setContentDescription(getString(
                expanded ? R.string.a11y_language_menu_expanded : R.string.a11y_language_menu_collapsed));
    }

    // ---- scan ----

    private void requestAccessAndStart() {
        pendingScanRequest = true;
        String[] permissions = engine.getRuntimePermissions();
        if (permissions.length > 0 && !engine.hasAllRuntimePermissions(permissions)) {
            permissionLauncher.launch(permissions);
            return;
        }
        continueAfterPermissionStep();
    }

    private void continueAfterPermissionStep() {
        if (engine.hasUsageStatsAccess()) {
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
        show(Screen.SCAN);
        scanExecutor.execute(() -> {
            List<ScanSection> sections = engine.runAll((step, total, label) -> mainHandler.post(() -> {
                currentScanLabel.setText(getString(R.string.currently_scanning_prefix) + " " + label);
                scanCounter.setText(getString(R.string.scan_counter_value, step, total));
                circularProgress.setProgressCompat(step, !reducedMotionMode);
                A11y.announce(root, getString(R.string.a11y_scan_step_announcement, label, step, total));
            }));
            List<ThreatFinding> findings = ScanEngine.flattenFindings(sections);
            mainHandler.post(() -> finishScan(sections, findings));
        });
    }

    private void finishScan(@NonNull List<ScanSection> sections, @NonNull List<ThreatFinding> threats) {
        scanInProgress = false;
        scanHistory = store.appendToHistory(scanHistory, sections);
        openResults(sections, threats);
        show(Screen.SUMMARY);
    }

    private void openResults(@NonNull List<ScanSection> sections, @NonNull List<ThreatFinding> threats) {
        lastSections = sections;
        lastThreats = threats;
        renderSummary();
        renderDetailedReport();
        renderRemovalList();
    }

    // ---- summary ----

    private void renderSummary() {
        boolean hasThreats = !lastThreats.isEmpty();
        summaryCount.setText(String.valueOf(lastThreats.size()));
        summaryCount.setTextColor(ContextCompat.getColor(this, hasThreats ? R.color.negative : R.color.accent));
        summaryTitle.setText(hasThreats ? R.string.summary_danger_title : R.string.summary_safe_title);
        summaryBody.setText(hasThreats ? R.string.summary_danger_body : R.string.summary_safe_body);
        summaryTitle.setContentDescription(lastThreats.size() + " " + summaryTitle.getText());
        summaryFindingsContainer.removeAllViews();

        if (!hasThreats) {
            summaryFindingsContainer.addView(summaryRow(getString(R.string.summary_clean_chip_dynamic, lastSections.size()), null));
            return;
        }
        Map<String, Integer> grouped = new LinkedHashMap<>();
        for (ThreatFinding threat : lastThreats) {
            Integer current = grouped.get(threat.attackType);
            grouped.put(threat.attackType, current == null ? 1 : current + 1);
        }
        for (Map.Entry<String, Integer> entry : grouped.entrySet()) {
            views.addRow(summaryFindingsContainer, summaryRow(entry.getKey(), entry.getValue()));
        }
    }

    @NonNull
    private View summaryRow(@NonNull String label, @Nullable Integer count) {
        LinearLayout row = views.row();
        row.setMinimumHeight(views.dp(52));
        row.setPadding(views.dp(16), views.dp(12), views.dp(16), views.dp(12));
        row.addView(views.text(R.style.TextAppearance_FullScan_Body, label), Views.weighted());
        if (count != null) {
            TextView value = views.text(R.style.TextAppearance_FullScan_Label, String.valueOf(count));
            value.setFontFeatureSettings("tnum");
            value.setTextColor(ContextCompat.getColor(this, R.color.negative));
            row.addView(value);
        }
        row.setFocusable(true);
        row.setContentDescription(count == null ? label : label + ": " + count);
        return row;
    }

    // ---- report ----

    private void renderDetailedReport() {
        reportSectionsContainer.removeAllViews();
        for (ScanSection section : lastSections) {
            View card = createSectionCard(section);
            card.setLayoutParams(views.fill(0, 12));
            reportSectionsContainer.addView(card);
        }
        reportPrimaryButton.setText(hasActionableThreats() ? R.string.remove_malware : R.string.go_home);
    }

    @NonNull
    private View createSectionCard(@NonNull ScanSection section) {
        boolean clean = section.findings.isEmpty();
        LinearLayout card = views.column(R.drawable.bg_surface, 0);

        LinearLayout header = views.column(0, 16);
        header.setFocusable(true);
        LinearLayout titleRow = views.row();
        TextView title = views.text(R.style.TextAppearance_FullScan_Section, section.title);
        ViewCompat.setAccessibilityHeading(title, true);
        titleRow.addView(title, Views.weighted());
        titleRow.addView(views.pill(getString(clean ? R.string.status_clean : R.string.status_warning), clean));
        header.addView(titleRow);
        TextView summary = views.text(R.style.TextAppearance_FullScan_Caption, section.summary);
        header.addView(summary, views.fill(4, 0));
        card.addView(header);

        if (clean) {
            header.setContentDescription(section.title + ". " + section.summary + ". " + getString(R.string.section_clear));
            return card;
        }
        header.setContentDescription(getString(R.string.a11y_section_summary, section.title, section.summary, section.findings.size()));
        for (ThreatFinding finding : section.findings) {
            card.addView(views.divider());
            card.addView(createFindingRow(finding));
        }
        return card;
    }

    @NonNull
    private View createFindingRow(@NonNull ThreatFinding finding) {
        LinearLayout row = views.row();
        row.setGravity(android.view.Gravity.TOP);
        row.setPadding(views.dp(16), views.dp(14), views.dp(8), views.dp(6));
        if (finding.showAppIcon && finding.icon != null) {
            row.addView(views.icon(finding.icon, 32));
        }
        LinearLayout text = views.column(0, 0);
        text.setFocusable(true);
        text.addView(views.text(R.style.TextAppearance_FullScan_Label, finding.title));
        text.addView(views.text(R.style.TextAppearance_FullScan_Caption, finding.description), views.fill(2, 0));
        MaterialButton details = views.textButton(getString(R.string.details));
        details.setContentDescription(getString(R.string.a11y_details_for, finding.title));
        details.setOnClickListener(v -> showThreatDetails(finding));
        text.addView(details, views.wrap(0));
        text.setContentDescription(getString(R.string.a11y_finding_item, finding.title, finding.attackType, finding.description));
        row.addView(text, Views.weighted());
        return row;
    }

    private void showThreatDetails(@NonNull ThreatFinding finding) {
        StringBuilder message = new StringBuilder()
                .append(finding.description).append("\n\n")
                .append(getString(R.string.details_attack)).append(" ").append(finding.attackType).append("\n\n")
                .append(getString(R.string.details_location)).append(" ").append(finding.location).append("\n\n")
                .append(getString(R.string.details_reason)).append(" ").append(finding.whyFlagged);
        if (finding.removablePackage != null) {
            message.append("\n\n").append(getString(R.string.details_package)).append(" ").append(finding.removablePackage);
        }
        new MaterialAlertDialogBuilder(this)
                .setTitle(finding.title)
                .setMessage(message.toString())
                .setPositiveButton(R.string.ok, null)
                .show();
    }

    // ---- removal ----

    private void renderRemovalList() {
        removalThreatsContainer.removeAllViews();
        for (ThreatFinding threat : lastThreats) {
            if (planner.isThreatActionable(threat)) {
                views.addRow(removalThreatsContainer, createRemovalOption(threat));
            }
        }
        removalThreatsContainer.setVisibility(removalThreatsContainer.getChildCount() == 0 ? View.GONE : View.VISIBLE);
        removeSelectedButton.setEnabled(hasSelectedThreats());
        updateRemovalSelectionSummary(false);
    }

    @NonNull
    private View createRemovalOption(@NonNull ThreatFinding threat) {
        RemediationAction action = planner.buildRemediationAction(threat);
        LinearLayout row = views.tappableRow(64);
        row.setPadding(views.dp(4), views.dp(8), views.dp(16), views.dp(8));

        CheckBox checkBox = new CheckBox(this);
        checkBox.setChecked(threat.selectedForRemoval);
        checkBox.setMinHeight(views.dp(48));
        checkBox.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);
        checkBox.setOnCheckedChangeListener((buttonView, isChecked) -> {
            threat.selectedForRemoval = isChecked;
            removeSelectedButton.setEnabled(hasSelectedThreats());
            updateRemovalSelectionSummary(true);
            updateRemovalRowDescription(row, threat, action);
            store.saveActiveSnapshot(ScanStore.SCREEN_REMOVAL, lastSections);
        });
        row.addView(checkBox);

        if (threat.icon != null) {
            row.addView(views.icon(threat.icon, 32));
        }
        LinearLayout text = views.column(0, 0);
        text.addView(views.text(R.style.TextAppearance_FullScan_Label, getRemovalPrimaryLabel(threat)));
        text.addView(views.text(R.style.TextAppearance_FullScan_Caption, getRemovalSecondaryLabel(threat, action)), views.fill(2, 0));
        row.addView(text, Views.weighted());
        row.setOnClickListener(v -> checkBox.toggle());
        updateRemovalRowDescription(row, threat, action);
        return row;
    }

    private void updateRemovalRowDescription(@NonNull View row, @NonNull ThreatFinding threat, @NonNull RemediationAction action) {
        row.setContentDescription(getString(
                R.string.a11y_removal_item,
                getRemovalPrimaryLabel(threat),
                getRemovalSecondaryLabel(threat, action),
                getString(threat.selectedForRemoval ? R.string.a11y_selected_yes : R.string.a11y_selected_no)));
    }

    @NonNull
    private String getRemovalPrimaryLabel(@NonNull ThreatFinding threat) {
        return threat.showAppIcon && !TextUtils.isEmpty(threat.attackType) ? threat.attackType : threat.title;
    }

    @NonNull
    private String getRemovalSecondaryLabel(@NonNull ThreatFinding threat, @NonNull RemediationAction action) {
        String actionLabel = planner.getRecommendedActionLabel(action.type);
        return threat.showAppIcon && !TextUtils.isEmpty(threat.title) ? threat.title + " · " + actionLabel : actionLabel;
    }

    private void updateRemovalSelectionSummary(boolean announce) {
        int selectedCount = 0;
        for (ThreatFinding threat : lastThreats) {
            if (planner.isThreatActionable(threat) && threat.selectedForRemoval) {
                selectedCount++;
            }
        }
        String summary = selectedCount == 0
                ? getString(R.string.a11y_no_selected_threats)
                : getString(R.string.a11y_selected_threats, selectedCount);
        removalSelectionSummary.setText(summary);
        if (announce) {
            A11y.announce(root, summary);
        }
    }

    private void startRemovalFlow() {
        if (!hasSelectedThreats()) {
            return;
        }
        store.saveActiveSnapshot(ScanStore.SCREEN_REMOVAL, lastSections);
        remediationQueue.clear();
        Set<String> queuedActions = new LinkedHashSet<>();
        for (ThreatFinding threat : lastThreats) {
            if (!threat.selectedForRemoval) {
                continue;
            }
            RemediationAction action = planner.buildRemediationAction(threat);
            if (action.type != RemediationAction.Type.NONE && queuedActions.add(action.uniqueKey)) {
                remediationQueue.add(action);
            }
        }
        launchNextRemediationStep();
    }

    private void launchNextRemediationStep() {
        RemediationAction nextAction = remediationQueue.poll();
        if (nextAction == null) {
            show(Screen.HOME);
            return;
        }
        Intent intent = planner.buildRemediationIntent(nextAction);
        if (intent == null || !planner.canResolveIntent(intent)) {
            A11y.announce(root, getString(R.string.action_unavailable));
            launchNextRemediationStep();
            return;
        }
        try {
            remediationLauncher.launch(intent);
        } catch (ActivityNotFoundException ignored) {
            A11y.announce(root, getString(R.string.action_unavailable));
            launchNextRemediationStep();
        }
    }

    private boolean hasActionableThreats() {
        for (ThreatFinding threat : lastThreats) {
            if (planner.isThreatActionable(threat)) {
                return true;
            }
        }
        return false;
    }

    private boolean hasSelectedThreats() {
        for (ThreatFinding threat : lastThreats) {
            if (threat.selectedForRemoval && planner.isThreatActionable(threat)) {
                return true;
            }
        }
        return false;
    }

    // ---- home: history ----

    private void restorePersistedState() {
        scanHistory = store.readHistory();
        renderHistorySection();
        ScanHistoryEntry activeEntry = store.readActiveScan();
        if (activeEntry == null || activeEntry.sections.isEmpty()) {
            show(Screen.HOME);
            return;
        }
        List<ScanSection> sections = store.deepCopySections(activeEntry.sections);
        openResults(sections, ScanEngine.flattenFindings(sections));
        String activeScreen = store.readActiveScreen();
        if (ScanStore.SCREEN_SUMMARY.equals(activeScreen)) {
            show(Screen.SUMMARY);
        } else if (ScanStore.SCREEN_REPORT.equals(activeScreen)) {
            show(Screen.REPORT);
        } else if (ScanStore.SCREEN_REMOVAL.equals(activeScreen)) {
            show(Screen.REMOVAL);
        } else {
            show(Screen.HOME);
        }
    }

    private void renderHistorySection() {
        historyContainer.removeAllViews();
        historySection.setVisibility(scanHistory.isEmpty() ? View.GONE : View.VISIBLE);
        for (int i = 0; i < Math.min(HISTORY_ROWS, scanHistory.size()); i++) {
            views.addRow(historyContainer, createHistoryRow(scanHistory.get(i)));
        }
    }

    @NonNull
    private View createHistoryRow(@NonNull ScanHistoryEntry entry) {
        int threats = ScanEngine.flattenFindings(entry.sections).size();
        String when = ScanStore.formatTimestamp(entry.timestamp, LocaleController.createLocale(LocaleController.getStoredLanguage(this)));
        LinearLayout row = views.tappableRow(56);
        row.addView(views.text(R.style.TextAppearance_FullScan_Body, when), Views.weighted());
        TextView count = views.text(R.style.TextAppearance_FullScan_Caption, getString(R.string.history_item_threats, threats));
        count.setFontFeatureSettings("tnum");
        if (threats > 0) {
            count.setTextColor(ContextCompat.getColor(this, R.color.negative));
        }
        row.addView(count);
        row.setContentDescription(getString(R.string.history_item_content_description, when, threats));
        row.setOnClickListener(v -> {
            List<ScanSection> sections = store.deepCopySections(entry.sections);
            openResults(sections, ScanEngine.flattenFindings(sections));
            show(Screen.REPORT);
        });
        return row;
    }

    private void confirmClearHistory() {
        new MaterialAlertDialogBuilder(this)
                .setTitle(R.string.clear_history)
                .setMessage(R.string.clear_history_message)
                .setPositiveButton(R.string.clear_history, (dialog, which) -> {
                    scanHistory = new ArrayList<>();
                    store.saveHistory(scanHistory);
                    renderHistorySection();
                })
                .setNegativeButton(android.R.string.cancel, null)
                .show();
    }

    // ---- access ----

    private void renderAccessCenter() {
        accessCenterContainer.removeAllViews();
        boolean usage = engine.hasUsageStatsAccess();
        boolean media = engine.hasAllRuntimePermissions(engine.getRuntimePermissions());
        boolean lock = engine.isDeviceSecure();
        boolean dns = engine.isPrivateDnsEnabled();
        addAccessCard(R.string.access_usage_title, usage, R.string.access_usage_ready_body, R.string.access_usage_missing_body,
                () -> usageAccessLauncher.launch(new Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS)));
        addAccessCard(R.string.access_media_title, media, R.string.access_media_ready_body, R.string.access_media_missing_body,
                this::openAppDetailsSettings);
        addAccessCard(R.string.access_lock_title, lock, R.string.access_lock_ready_body, R.string.access_lock_missing_body,
                () -> openSystemIntent(new Intent(Settings.ACTION_SECURITY_SETTINGS)));
        addAccessCard(R.string.access_dns_title, dns, R.string.access_dns_ready_body, R.string.access_dns_missing_body,
                () -> openSystemIntent(new Intent(Settings.ACTION_WIRELESS_SETTINGS)));
    }

    private void addAccessCard(@StringRes int title, boolean ready, @StringRes int readyBody, @StringRes int missingBody,
                               @NonNull Runnable fix) {
        LinearLayout card = views.column(R.drawable.bg_surface, 16);
        LinearLayout header = views.row();
        header.addView(views.text(R.style.TextAppearance_FullScan_Section, getString(title)), Views.weighted());
        header.addView(views.pill(getString(ready ? R.string.access_status_ready : R.string.access_status_needs_review), ready));
        card.addView(header);
        card.addView(views.text(R.style.TextAppearance_FullScan_Caption, getString(ready ? readyBody : missingBody)), views.fill(6, 0));
        if (!ready) {
            MaterialButton button = views.outlinedButton(getString(R.string.open_settings));
            button.setOnClickListener(v -> fix.run());
            card.addView(button, views.fill(14, 0));
        }
        card.setLayoutParams(views.fill(0, 12));
        accessCenterContainer.addView(card);
    }

    private void openAppDetailsSettings() {
        openSystemIntent(new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:" + getPackageName())));
    }

    private void openSystemIntent(@NonNull Intent intent) {
        if (planner.canResolveIntent(intent)) {
            startActivity(intent);
        } else {
            A11y.announce(root, getString(R.string.action_unavailable));
        }
    }
}
