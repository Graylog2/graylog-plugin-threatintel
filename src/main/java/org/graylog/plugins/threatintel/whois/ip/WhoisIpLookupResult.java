package org.graylog.plugins.threatintel.whois.ip;

import com.google.common.collect.ForwardingMap;

import java.util.Map;

public class WhoisIpLookupResult extends ForwardingMap<String, Object> {

    private final Map<String, Object> results;

    public WhoisIpLookupResult(Map<String, Object> fields) {
        this.results = fields;
    }

    public Map<String, Object> getResults() {
        return results;
    }

    @Override
    protected Map<String, Object> delegate() {
        return getResults();
    }

}
