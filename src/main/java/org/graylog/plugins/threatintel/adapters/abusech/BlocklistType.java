package org.graylog.plugins.threatintel.adapters.abusech;

import com.google.common.base.MoreObjects;

public enum BlocklistType {
    DOMAINS("https://ransomwaretracker.abuse.ch/downloads/RW_DOMBL.txt", true),
    URLS("https://ransomwaretracker.abuse.ch/downloads/RW_URLBL.txt", true),
    IPS("https://ransomwaretracker.abuse.ch/downloads/RW_IPBL.txt", false);

    private final String url;
    private final boolean caseInsensitive;

    BlocklistType(String url, boolean caseInsensitive) {
        this.url = url;
        this.caseInsensitive = caseInsensitive;
    }

    public String getUrl() {
        return url;
    }

    public boolean isCaseInsensitive() {
        return caseInsensitive;
    }

    @Override
    public String toString() {
        return MoreObjects.toStringHelper(this)
                .add("url", url)
                .add("caseInsensitive", caseInsensitive)
                .toString();
    }

}
