package com.example.fullscansecurity.ui;

import android.animation.ValueAnimator;
import android.content.Context;
import android.os.Build;
import android.provider.Settings;
import android.view.View;
import android.view.accessibility.AccessibilityManager;

import androidx.annotation.NonNull;

/** Accessibility signals and announcements. */
public final class A11y {

    private A11y() {
    }

    /** System high-contrast text, or a font scale of 1.3 and up. */
    public static boolean isHighContrast(@NonNull Context context) {
        boolean systemHighContrast = false;
        try {
            systemHighContrast = Settings.Secure.getInt(context.getContentResolver(), "high_text_contrast_enabled", 0) == 1;
        } catch (Exception ignored) {
            // Fall back to the font scale heuristic.
        }
        return systemHighContrast || context.getResources().getConfiguration().fontScale >= 1.3f;
    }

    public static boolean isReducedMotion() {
        return Build.VERSION.SDK_INT >= Build.VERSION_CODES.O && !ValueAnimator.areAnimatorsEnabled();
    }

    public static void announce(@NonNull View root, @NonNull String message) {
        AccessibilityManager manager = (AccessibilityManager) root.getContext().getSystemService(Context.ACCESSIBILITY_SERVICE);
        if (manager != null && manager.isEnabled()) {
            root.announceForAccessibility(message);
        }
    }

    public static void focusAndAnnounce(@NonNull View target, @NonNull View root, @NonNull String message) {
        target.post(() -> {
            target.requestFocus();
            announce(root, message);
        });
    }
}
