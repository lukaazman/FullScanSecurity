package com.example.fullscansecurity.data;

import android.content.Context;
import android.content.SharedPreferences;
import android.graphics.drawable.Drawable;
import android.text.TextUtils;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import com.example.fullscansecurity.model.ScanHistoryEntry;
import com.example.fullscansecurity.model.ScanSection;
import com.example.fullscansecurity.model.ThreatFinding;
import com.example.fullscansecurity.scan.ScanSupport;
import java.text.DateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/** History and the last opened scan, kept as JSON in SharedPreferences. */
public final class ScanStore extends ScanSupport {

    public static final String PREFS_NAME = "full_scan_security_prefs";
    public static final String SCREEN_HOME = "home";
    public static final String SCREEN_SUMMARY = "summary";
    public static final String SCREEN_REPORT = "report";
    public static final String SCREEN_REMOVAL = "removal";
    private static final String KEY_ACTIVE_SCREEN = "active_screen";
    private static final String KEY_ACTIVE_SCAN = "active_scan";
    private static final String KEY_SCAN_HISTORY = "scan_history";
    private static final int MAX_HISTORY_ENTRIES = 12;

    public ScanStore(Context base) {
        super(base);
    }

    @NonNull
    private SharedPreferences getPreferences() {
        return getSharedPreferences(PREFS_NAME, MODE_PRIVATE);
    }

    @NonNull
    public String readActiveScreen() {
        return getPreferences().getString(KEY_ACTIVE_SCREEN, SCREEN_HOME);
    }

    public void saveScreen(@NonNull String screen) {
        getPreferences().edit().putString(KEY_ACTIVE_SCREEN, screen).apply();
    }

    public void saveActiveSnapshot(@NonNull String screen, @NonNull List<ScanSection> sections) {
        SharedPreferences.Editor editor = getPreferences().edit().putString(KEY_ACTIVE_SCREEN, screen);
        if (sections.isEmpty()) {
            editor.remove(KEY_ACTIVE_SCAN).apply();
            return;
        }
        ScanHistoryEntry activeEntry = new ScanHistoryEntry(System.currentTimeMillis(), deepCopySections(sections));
        editor.putString(KEY_ACTIVE_SCAN, serializeHistoryEntry(activeEntry).toString()).apply();
    }

    /** Prepends a copy of the scan, trims to the history limit, persists, and returns the new list. */
    @NonNull
    public List<ScanHistoryEntry> appendToHistory(@NonNull List<ScanHistoryEntry> history, @NonNull List<ScanSection> sections) {
        List<ScanHistoryEntry> updated = new ArrayList<>();
        updated.add(new ScanHistoryEntry(System.currentTimeMillis(), deepCopySections(sections)));
        for (ScanHistoryEntry entry : history) {
            if (updated.size() >= MAX_HISTORY_ENTRIES) {
                break;
            }
            updated.add(entry);
        }
        saveHistory(updated);
        return updated;
    }

    public void saveHistory(@NonNull List<ScanHistoryEntry> history) {
        JSONArray array = new JSONArray();
        for (ScanHistoryEntry entry : history) {
            array.put(serializeHistoryEntry(entry));
        }
        getPreferences().edit().putString(KEY_SCAN_HISTORY, array.toString()).apply();
    }

    @NonNull
    public static String formatTimestamp(long timestamp, @NonNull Locale locale) {
        DateFormat formatter = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT, locale);
        return formatter.format(new Date(timestamp));
    }

    @NonNull
    public List<ScanHistoryEntry> readHistory() {
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
    public ScanHistoryEntry readActiveScan() {
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
    public List<ScanSection> deepCopySections(@NonNull List<ScanSection> source) {
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
}
