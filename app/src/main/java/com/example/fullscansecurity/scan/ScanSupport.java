package com.example.fullscansecurity.scan;

import android.Manifest;
import android.annotation.SuppressLint;
import android.app.AppOpsManager;
import android.app.KeyguardManager;
import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.ContextWrapper;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.ComponentInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.ProxyInfo;
import android.net.Uri;
import android.os.Build;
import android.os.PowerManager;
import android.provider.Settings;
import android.provider.Telephony;
import android.text.TextUtils;
import android.util.Log;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.content.ContextCompat;
import com.example.fullscansecurity.R;
import com.example.fullscansecurity.model.ThreatFinding;
import java.io.File;
import java.lang.reflect.Method;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

public class ScanSupport extends ContextWrapper {

    public ScanSupport(Context base) {
        super(base);
    }

    protected static final String TAG = "FullScanSecurity";

    protected static final String PACKAGE_NAME_PATTERN = "^[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+$";


    protected static final List<String> HIGH_RISK_PERMISSIONS = Arrays.asList(
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

    protected static final List<String> SUSPICIOUS_KEYWORDS = Arrays.asList(
            "trojan", "spy", "keylog", "inject", "overlay", "stealer",
            "hack", "mod", "cracker", "rat", "miner", "dropper", "loader"
    );

    protected static final List<String> ROOT_PACKAGES = Arrays.asList(
            "com.topjohnwu.magisk",
            "eu.chainfire.supersu",
            "com.koushikdutta.superuser",
            "com.thirdparty.superuser",
            "com.kingroot.kinguser"
    );

    protected static final List<String> ROOT_PATHS = Arrays.asList(
            "/system/bin/su",
            "/system/xbin/su",
            "/sbin/su",
            "/system/bin/.ext/su",
            "/system/usr/we-need-root/su",
            "/system/app/Superuser.apk",
            "/cache/magisk.log",
            "/data/adb/magisk"
    );

    protected static final List<String> KNOWN_BROWSER_PACKAGES = Arrays.asList(
            "com.android.chrome",
            "org.mozilla.firefox",
            "com.microsoft.emmx",
            "com.brave.browser",
            "com.opera.browser",
            "com.sec.android.app.sbrowser",
            "com.duckduckgo.mobile.android",
            "com.vivaldi.browser"
    );

    @NonNull
    protected List<String> collectSensitiveServiceRoles(@NonNull PackageInfo packageInfo) {
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
    protected String getSensitiveServiceLabel(@Nullable String permission) {
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

    protected int countExportedComponents(@Nullable ComponentInfo[] components) {
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

    protected int countUnprotectedExportedComponents(@Nullable ComponentInfo[] components) {
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
    protected String getComponentPermission(@NonNull ComponentInfo component) {
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

    protected List<ApplicationInfo> getInstalledApplicationsCompat() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            return getPackageManager().getInstalledApplications(
                    PackageManager.ApplicationInfoFlags.of(PackageManager.GET_META_DATA));
        }
        return getPackageManager().getInstalledApplications(PackageManager.GET_META_DATA);
    }

    protected PackageInfo getPackageInfoCompat(@NonNull String packageName, long flags)
            throws PackageManager.NameNotFoundException {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            return getPackageManager().getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(flags));
        }
        return getPackageManager().getPackageInfo(packageName, (int) flags);
    }

    protected boolean isScannableUserApp(@NonNull ApplicationInfo appInfo) {
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

    protected boolean shouldSkipPackage(@Nullable String packageName) {
        return packageName == null || getPackageName().equals(packageName);
    }

    protected List<String> getRequestedPermissions(@NonNull PackageInfo packageInfo) {
        if (packageInfo.requestedPermissions == null) {
            return Collections.emptyList();
        }
        return Arrays.asList(packageInfo.requestedPermissions);
    }

    protected int countHighRiskPermissions(@NonNull List<String> requestedPermissions) {
        int count = 0;
        for (String permission : HIGH_RISK_PERMISSIONS) {
            if (requestedPermissions.contains(permission)) {
                count++;
            }
        }
        return count;
    }

    protected boolean containsSuspiciousKeyword(@NonNull String value) {
        String normalized = value.toLowerCase(Locale.US);
        for (String keyword : SUSPICIOUS_KEYWORDS) {
            if (normalized.contains(keyword)) {
                return true;
            }
        }
        return false;
    }

    protected String getInstallerPackage(@NonNull String packageName) {
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

    protected String safeInstallerLabel(@Nullable String installer) {
        if (TextUtils.isEmpty(installer)) {
            return getString(R.string.label_unknown);
        }
        if ("com.android.vending".equals(installer)) {
            return getString(R.string.label_google_play);
        }
        return installer;
    }

    protected String safeValue(@Nullable String value) {
        return TextUtils.isEmpty(value) ? getString(R.string.label_unknown) : value;
    }

    protected boolean isTrustedPrivateDnsHost(@NonNull String host) {
        String normalized = host.toLowerCase(Locale.US);
        return normalized.contains("dns.google")
                || normalized.contains("one.one.one.one")
                || normalized.contains("cloudflare")
                || normalized.contains("quad9")
                || normalized.contains("nextdns");
    }

    protected int getUserInstalledCaCount() {
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
    protected ProxyInfo getDefaultProxyInfo() {
        ConnectivityManager connectivityManager = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
        if (connectivityManager == null) {
            return null;
        }
        return connectivityManager.getDefaultProxy();
    }

    protected boolean isVpnActive() {
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
    protected String getAlwaysOnVpnPackage() {
        return Settings.Secure.getString(getContentResolver(), "always_on_vpn_app");
    }

    protected boolean isPackageInstalled(@NonNull String packageName) {
        try {
            getPackageManager().getPackageInfo(packageName, 0);
            return true;
        } catch (Exception ignored) {
            return false;
        }
    }

    protected boolean isBrowserPackage(@Nullable String packageName) {
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

    protected boolean hasRootBinary() {
        for (String path : ROOT_PATHS) {
            if (new File(path).exists()) {
                return true;
            }
        }
        return false;
    }

    protected boolean isProbablyEmulator() {
        return Build.FINGERPRINT.startsWith("generic")
                || Build.FINGERPRINT.toLowerCase(Locale.US).contains("emulator")
                || Build.MODEL.toLowerCase(Locale.US).contains("sdk")
                || Build.HARDWARE.toLowerCase(Locale.US).contains("ranchu")
                || Build.HARDWARE.toLowerCase(Locale.US).contains("goldfish")
                || Build.PRODUCT.toLowerCase(Locale.US).contains("sdk");
    }

    protected String getSystemPropertyCompat(@NonNull String key) {
        try {
            Class<?> systemProperties = Class.forName("android.os.SystemProperties");
            Method getMethod = systemProperties.getMethod("get", String.class, String.class);
            Object value = getMethod.invoke(null, key, "");
            return value instanceof String ? (String) value : "";
        } catch (Exception ignored) {
            return "";
        }
    }

    protected Set<String> getEnabledNotificationListenerPackages() {
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

    protected boolean hasBootPersistenceReceiver(@NonNull PackageInfo packageInfo, @NonNull List<String> requestedPermissions) {
        return requestedPermissions.contains(Manifest.permission.RECEIVE_BOOT_COMPLETED)
                || (packageInfo.receivers != null && packageInfo.receivers.length > 0);
    }

    protected boolean isIgnoringBatteryOptimizations(@NonNull String packageName) {
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

    protected Set<String> getEnabledInputMethodPackages() {
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
    protected String getDefaultInputMethodPackage() {
        String value = Settings.Secure.getString(getContentResolver(), Settings.Secure.DEFAULT_INPUT_METHOD);
        if (TextUtils.isEmpty(value)) {
            return null;
        }
        ComponentName component = ComponentName.unflattenFromString(value);
        return component == null ? null : component.getPackageName();
    }

    protected void maybeAddPermissionLabel(
            @NonNull List<String> requested,
            @NonNull String permission,
            @NonNull String label,
            @NonNull List<String> output
    ) {
        if (requested.contains(permission)) {
            output.add(label);
        }
    }

    protected List<ThreatFinding> buildDefaultRoleFindings(
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
    protected String getDefaultSmsPackage() {
        return Telephony.Sms.getDefaultSmsPackage(this);
    }

    @Nullable
    protected String getDefaultDialerPackage() {
        Object telecom = getSystemService(Context.TELECOM_SERVICE);
        if (!(telecom instanceof android.telecom.TelecomManager)) {
            return null;
        }
        return ((android.telecom.TelecomManager) telecom).getDefaultDialerPackage();
    }

    @Nullable
    protected String getDefaultBrowserPackage() {
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

    protected ThreatFinding buildPackageFinding(
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

    protected Set<String> getEnabledAccessibilityPackages() {
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

    protected Set<String> getActiveAdminPackages() {
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

    protected boolean isDeveloperOptionsEnabled() {
        return Settings.Global.getInt(getContentResolver(),
                Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) == 1;
    }

    protected boolean isAdbEnabled() {
        return Settings.Global.getInt(getContentResolver(), Settings.Global.ADB_ENABLED, 0) == 1;
    }

    public boolean isDeviceSecure() {
        KeyguardManager keyguardManager = (KeyguardManager) getSystemService(Context.KEYGUARD_SERVICE);
        return keyguardManager != null && keyguardManager.isDeviceSecure();
    }

    @SuppressLint("WrongConstant")
    public boolean hasUsageStatsAccess() {
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

    public String[] getRuntimePermissions() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            return new String[]{
                    Manifest.permission.READ_MEDIA_IMAGES,
                    Manifest.permission.READ_MEDIA_VIDEO,
                    Manifest.permission.READ_MEDIA_AUDIO
            };
        }
        return new String[]{Manifest.permission.READ_EXTERNAL_STORAGE};
    }

    public boolean hasAllRuntimePermissions(@NonNull String[] permissions) {
        for (String permission : permissions) {
            if (ContextCompat.checkSelfPermission(this, permission) != PackageManager.PERMISSION_GRANTED) {
                return false;
            }
        }
        return true;
    }

    protected boolean isValidPackageName(@Nullable String packageName) {
        return !TextUtils.isEmpty(packageName) && packageName.matches(PACKAGE_NAME_PATTERN);
    }

    protected void logWarn(@NonNull String message, @Nullable Throwable throwable) {
        if (isDebugLoggingEnabled()) {
            Log.w(TAG, message, throwable);
        }
    }

    protected void logError(@NonNull String message, @Nullable Throwable throwable) {
        if (isDebugLoggingEnabled()) {
            Log.e(TAG, message, throwable);
        }
    }

    protected boolean isDebugLoggingEnabled() {
        return (getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0;
    }

    protected String shortPermissionName(@NonNull String permission) {
        int index = permission.lastIndexOf('.');
        return index >= 0 ? permission.substring(index + 1) : permission;
    }

    public boolean isPrivateDnsEnabled() {
        String privateDnsMode = Settings.Global.getString(getContentResolver(), "private_dns_mode");
        return !TextUtils.isEmpty(privateDnsMode) && !"off".equalsIgnoreCase(privateDnsMode);
    }
}
