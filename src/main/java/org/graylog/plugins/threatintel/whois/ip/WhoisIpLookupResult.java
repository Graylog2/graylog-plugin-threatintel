package org.graylog.plugins.threatintel.whois.ip;

import com.google.common.base.Strings;
import com.google.common.collect.ForwardingMap;

import java.util.HashMap;
import java.util.Map;

public class WhoisIpLookupResult extends ForwardingMap<String, Object> {

    private static final String NA = "N/A";

    private static WhoisIpLookupResult EMPTY = new WhoisIpLookupResult(NA, NA);

    private final String organization;
    private final String countryCode;

    private String prefix;

    WhoisIpLookupResult(String organization, String countryCode) {
        this.organization = organization;
        this.countryCode = countryCode;
    }

    static WhoisIpLookupResult empty() {
        return EMPTY;
    }

    public String getOrganization() {
        if(Strings.isNullOrEmpty(organization)) {
            return NA;
        } else {
            return organization;
        }
    }

    public String getCountryCode() {
        if(Strings.isNullOrEmpty(countryCode)) {
            return NA;
        } else {
            return countryCode;
        }
    }

    public void setPrefix(String prefix) {
        this.prefix = prefix;
    }

    public Map<String, Object> getResults() {
        final StringBuilder keyOrg = new StringBuilder();
        final StringBuilder keyCountryCode = new StringBuilder();

        if(prefix != null && !prefix.isEmpty()) {
            keyOrg.append(prefix).append("_");
            keyCountryCode.append(prefix).append("_");
        }

        keyOrg.append("whois_organization");
        keyCountryCode.append("whois_country_code");

        return new HashMap<String, Object>(){{
            put(keyOrg.toString(), getOrganization());
            put(keyCountryCode.toString(), getCountryCode());
        }};
    }

    @Override
    protected Map<String, Object> delegate() {
        return getResults();
    }

}
