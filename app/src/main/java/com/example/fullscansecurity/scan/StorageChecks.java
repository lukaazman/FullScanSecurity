package com.example.fullscansecurity.scan;

import android.content.ContentResolver;
import android.content.Context;
import android.os.Build;
import android.os.Environment;
import android.provider.MediaStore;
import androidx.annotation.NonNull;
import com.example.fullscansecurity.R;
import com.example.fullscansecurity.model.ScanSection;
import com.example.fullscansecurity.model.ThreatFinding;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

final class StorageChecks extends ScanSupport {

    StorageChecks(Context base) {
        super(base);
    }

    ScanSection scanReachableStorageSurfaces() {
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

    int inspectDirectory(@NonNull File directory, @NonNull List<ThreatFinding> findings, int depth) {
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

    int inspectMediaStoreDownloads(@NonNull List<ThreatFinding> findings) {
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
}
