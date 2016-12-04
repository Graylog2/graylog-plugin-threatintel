package org.graylog.plugins.threatintel.whois.ip.parsers;

import org.graylog.plugins.threatintel.whois.ip.InternetRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class WhoisParser {

    protected static final Logger LOG = LoggerFactory.getLogger(WhoisParser.class);

    protected boolean isRedirect = false;
    protected InternetRegistry registryRedirect;

    protected String organization;
    protected String countryCode;

    protected String lineValue(String line) {
        if(!line.contains(":")) {
            return "";
        }

        String[] parts = line.split(":");
        return parts[1].trim();
    }

    protected InternetRegistry findRegistryFromWhoisServer(String server) {
        for (InternetRegistry registry : InternetRegistry.values()) {
            if (registry.getWhoisServer().equals(server)) {
                return registry;
            }
        }

        LOG.error("No known internet registry for WHOIS server redirect [{}].", server);
        return null;
    }

    public boolean isRedirect() {
        return isRedirect;
    }

    public InternetRegistry getRegistryRedirect() {
        return registryRedirect;
    }

    public String getOrganization() {
        return this.organization;
    }

    public String getCountryCode() {
        return this.countryCode;
    }

    public abstract void readLine(String line);

}
