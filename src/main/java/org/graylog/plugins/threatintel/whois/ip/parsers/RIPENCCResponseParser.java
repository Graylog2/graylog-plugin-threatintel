package org.graylog.plugins.threatintel.whois.ip.parsers;

import org.graylog.plugins.threatintel.whois.ip.InternetRegistry;

public class RIPENCCResponseParser extends WhoisParser {

    @Override
    public void readLine(String line) {
        if (line.startsWith("%") || line.isEmpty()) {
            return;
        }

        if(line.startsWith("descr") && this.organization == null) {
            this.organization = lineValue(line);
        }

        // Some responses have an org-name. Let this always overwrite the organization parsed from "descr" field.
        if(line.startsWith("org-name:")) {
            this.organization = lineValue(line);
        }

        if(line.startsWith("country:") && this.countryCode == null) {
            this.countryCode = lineValue(line);
        }
    }

    @Override
    public boolean isRedirect() {
        return false; // TODO implement
    }

    @Override
    public InternetRegistry getRegistryRedirect() {
        return null; // TODO implement
    }

}
