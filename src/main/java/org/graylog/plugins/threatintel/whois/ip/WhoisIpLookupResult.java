package org.graylog.plugins.threatintel.whois.ip;

import com.google.common.collect.ForwardingMap;

import java.util.Map;

public class WhoisIpLookupResult extends ForwardingMap<String, String> {

    private final Map<String, String> results;

    public WhoisIpLookupResult(Map<String, String> fields) {
        this.results = fields;
    }

    public Map<String, String> getResults() {
        return results;
    }

    @Override
    protected Map<String, String> delegate() {
        return getResults();
    }

}
