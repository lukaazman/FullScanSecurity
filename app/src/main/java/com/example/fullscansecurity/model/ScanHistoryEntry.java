package com.example.fullscansecurity.model;

import androidx.annotation.NonNull;

import java.util.List;

public final class ScanHistoryEntry {
    public final long timestamp;
    public final List<ScanSection> sections;

    public ScanHistoryEntry(long timestamp, @NonNull List<ScanSection> sections) {
        this.timestamp = timestamp;
        this.sections = sections;
    }
}
