package com.example.fullscansecurity.scan;

import android.content.Context;
import android.content.pm.PackageManager;
import android.net.ProxyInfo;
import android.provider.Settings;
import android.text.TextUtils;
import com.example.fullscansecurity.R;
import com.example.fullscansecurity.model.ScanSection;
import com.example.fullscansecurity.model.ThreatFinding;
import java.util.ArrayList;
import java.util.List;

final class NetworkChecks extends ScanSupport {

    NetworkChecks(Context base) {
        super(base);
    }

    ScanSection scanNetworkSecurityPosture() {
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
}
