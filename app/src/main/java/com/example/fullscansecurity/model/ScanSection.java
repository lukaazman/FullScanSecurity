package com.example.fullscansecurity.model;

import java.util.List;

public final class ScanSection {
    public final String title;
    public final String summary;
    public final List<ThreatFinding> findings;

    public ScanSection(String title, String summary, List<ThreatFinding> findings) {
        this.title = title;
        this.summary = summary;
        this.findings = findings;
    }
}
