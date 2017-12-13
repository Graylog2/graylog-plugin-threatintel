package org.graylog.plugins.threatintel.tools;

public class Domain {

    public static String prepareDomain(final String domain) {
        // A typical issue is regular expressions that also capture a whitespace at the beginning or the end.
        String trimmedDomain = domain.trim();

        // Some systems will capture DNS requests with a trailing '.'. Remove that for the lookup.
        if(trimmedDomain.endsWith(".")) {
            trimmedDomain = trimmedDomain.substring(0, trimmedDomain.length()-1);
        }

        return trimmedDomain;
    }

}
