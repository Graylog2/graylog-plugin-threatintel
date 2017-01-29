package org.graylog.plugins.threatintel.whois.ip;

import com.google.common.collect.ForwardingMap;
import org.apache.commons.collections.map.HashedMap;

import java.util.HashMap;
import java.util.Map;

public class WhoisIpLookupResult extends ForwardingMap<String, Object> {

    public static final String NA = "N/A";

    public static WhoisIpLookupResult EMPTY = new WhoisIpLookupResult(NA, NA);

    private final String organization;
    private final String countryCode;

    private String prefix;

    public WhoisIpLookupResult(String organization, String countryCode) {
        this.organization = organization;
        this.countryCode = countryCode;
    }

    public String getOrganization() {
        if(organization == null || organization.isEmpty()) {
            return NA;
        } else {
            return organization;
        }
    }

    public String getCountryCode() {
        if(countryCode == null || countryCode.isEmpty()) {
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
