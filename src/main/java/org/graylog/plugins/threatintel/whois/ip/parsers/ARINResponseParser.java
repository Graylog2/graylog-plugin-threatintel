/*
 * Copyright (C) 2020 Graylog, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the Server Side Public License, version 1,
 * as published by MongoDB, Inc.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * Server Side Public License for more details.
 *
 * You should have received a copy of the Server Side Public License
 * along with this program. If not, see
 * <http://www.mongodb.com/licensing/server-side-public-license>.
 */
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
