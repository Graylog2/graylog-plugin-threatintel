package org.graylog.plugins.threatintel.tools;

public class Domain {

    public static String prepareDomain(String domain) {
        // A typical issue is regular expressions that also capture a whitespace at the beginning or the end.
        domain = domain.trim();

        // Some systems will capture DNS requests with a trailing '.'. Remove that for the lookup.
        if(domain.endsWith(".")) {
            domain = domain.substring(0, domain.length()-1);
        }

        return domain;
    }

}
