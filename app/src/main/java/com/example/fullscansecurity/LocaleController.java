package com.example.fullscansecurity;

import android.content.Context;
import android.content.res.Configuration;
import android.text.TextUtils;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import com.example.fullscansecurity.data.ScanStore;
import java.util.Locale;

/** The in-app language picker: stored choice, and the locale-wrapped base context. */
public final class LocaleController {

    public static final String[] LANGUAGES = {"en", "es", "de", "zh", "sl"};
    private static final String KEY_LANGUAGE = "selected_language";

    private LocaleController() {
    }

    public static void saveLanguage(@NonNull Context context, @NonNull String languageCode) {
        context.getSharedPreferences(ScanStore.PREFS_NAME, Context.MODE_PRIVATE)
                .edit().putString(KEY_LANGUAGE, languageCode).apply();
    }

    @NonNull
    public static String getStoredLanguage(@NonNull Context context) {
        return context.getSharedPreferences(ScanStore.PREFS_NAME, Context.MODE_PRIVATE)
                .getString(KEY_LANGUAGE, LANGUAGES[0]);
    }

    @NonNull
    public static Context wrapContextWithLocale(@NonNull Context context, @Nullable String languageCode) {
        Locale locale = createLocale(languageCode);
        Locale.setDefault(locale);
        Configuration configuration = new Configuration(context.getResources().getConfiguration());
        configuration.setLocale(locale);
        configuration.setLayoutDirection(locale);
        return context.createConfigurationContext(configuration);
    }

    @NonNull
    public static Locale createLocale(@Nullable String languageCode) {
        if (TextUtils.isEmpty(languageCode)) {
            return Locale.ENGLISH;
        }
        if ("zh".equals(languageCode)) {
            return Locale.SIMPLIFIED_CHINESE;
        }
        return Locale.forLanguageTag(languageCode);
    }
}
