package org.graylog.plugins.threatintel.whois.ip.parsers;

public class ARINResponseParser extends WhoisParser {

    @Override
    public void readLine(String line) {
        if (line.startsWith("#") || line.isEmpty()) {
            return;
        }

        if(line.startsWith("Organization:") && this.organization == null) {
            this.organization = lineValue(line);
        }

        if(line.startsWith("Country:") && this.countryCode == null) {
            this.countryCode = lineValue(line);
        }

        if(line.startsWith("ResourceLink") && !line.contains("http")) {
            this.isRedirect = true;
            registryRedirect = findRegistryFromWhoisServer(lineValue(line));
        }
    }

}
