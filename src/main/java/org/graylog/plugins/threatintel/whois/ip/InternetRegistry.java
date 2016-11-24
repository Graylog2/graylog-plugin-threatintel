package org.graylog.plugins.threatintel.whois.ip;

public enum InternetRegistry {

    AFRINIC("whois.afrinic.net"),
    APNIC("whois.apnic.net"),
    ARIN("whois.arin.net"),
    LACNIC("whois.lacnic.net"),
    RIPENCC("whois.ripe.net");

    final String whoisServer;

    InternetRegistry(String whoisServer) {
        this.whoisServer = whoisServer;
    }

    public String getWhoisServer() {
        return whoisServer;
    }

}
