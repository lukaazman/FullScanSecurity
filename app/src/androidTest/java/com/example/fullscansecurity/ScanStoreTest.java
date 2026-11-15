package com.example.fullscansecurity;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import android.content.Context;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.example.fullscansecurity.data.ScanStore;
import com.example.fullscansecurity.model.ScanHistoryEntry;
import com.example.fullscansecurity.model.ScanSection;
import com.example.fullscansecurity.model.ThreatFinding;
import com.example.fullscansecurity.scan.ScanEngine;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@RunWith(AndroidJUnit4.class)
public class ScanStoreTest {

    private Context context;
    private ScanStore store;

    @Before
    public void setUp() {
        context = InstrumentationRegistry.getInstrumentation().getTargetContext();
        context.getSharedPreferences(ScanStore.PREFS_NAME, Context.MODE_PRIVATE).edit().clear().commit();
        store = new ScanStore(context);
    }

    @After
    public void tearDown() {
        context.getSharedPreferences(ScanStore.PREFS_NAME, Context.MODE_PRIVATE).edit().clear().commit();
    }

    private static List<ScanSection> sampleScan() {
        ThreatFinding finding = new ThreatFinding("Spy app", "Reads SMS", "Sideload", "com.example.spy",
                "Installer: unknown", "Uninstall it", "com.example.spy", null, true, false);
        finding.selectedForRemoval = false;
        List<ScanSection> sections = new ArrayList<>();
        sections.add(new ScanSection("Installed apps", "12 apps", Collections.singletonList(finding)));
        sections.add(new ScanSection("Network", "Clean", new ArrayList<>()));
        return sections;
    }

    @Test
    public void historyRoundTripKeepsFindings() {
        List<ScanHistoryEntry> history = store.appendToHistory(new ArrayList<>(), sampleScan());
        assertEquals(1, history.size());

        List<ScanHistoryEntry> read = store.readHistory();
        assertEquals(1, read.size());
        List<ScanSection> sections = read.get(0).sections;
        assertEquals(2, sections.size());
        ThreatFinding finding = sections.get(0).findings.get(0);
        assertEquals("Spy app", finding.title);
        assertEquals("Installer: unknown\nUninstall it", finding.whyFlagged);
        assertEquals("com.example.spy", finding.removablePackage);
        assertTrue(finding.removable);
        assertFalse(finding.selectedForRemoval);
        assertTrue(sections.get(1).findings.isEmpty());
    }

    @Test
    public void historyIsCappedAtTwelve() {
        List<ScanHistoryEntry> history = new ArrayList<>();
        for (int i = 0; i < 15; i++) {
            history = store.appendToHistory(history, sampleScan());
        }
        assertEquals(12, history.size());
        assertEquals(12, store.readHistory().size());
    }

    @Test
    public void activeSnapshotRestoresScreenAndScan() {
        store.saveActiveSnapshot(ScanStore.SCREEN_REPORT, sampleScan());
        assertEquals(ScanStore.SCREEN_REPORT, store.readActiveScreen());
        ScanHistoryEntry active = store.readActiveScan();
        assertNotNull(active);
        assertEquals(1, ScanEngine.flattenFindings(active.sections).size());
    }

    @Test
    public void engineRunsFifteenChecks() {
        assertEquals(15, new ScanEngine(context).checkCount());
    }
}
