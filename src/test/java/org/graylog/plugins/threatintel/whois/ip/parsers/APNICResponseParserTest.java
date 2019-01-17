/**
 * This file is part of Graylog.
 *
 * Graylog is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Graylog is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Graylog.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.graylog.plugins.threatintel.whois.ip.parsers;

import org.junit.Test;

import static org.junit.Assert.*;

public class APNICResponseParserTest {

    private static final String MATCH = "% Information related to '42.61.114.128 - 42.61.114.159'\n" +
            "\n" +
            "inetnum:        42.61.114.128 - 42.61.114.159\n" +
            "netname:        SIMSYS-SG\n" +
            "descr:          SIMPLE SOLUTION SYSTEMS PTE LTD\n" +
            "descr:          739B HAVELOCK ROAD\n" +
            "descr:          .\n" +
            "descr:          Singapore 169654\n" +
            "country:        SG\n" +
            "admin-c:        AL1082-AP\n" +
            "tech-c:         SH9-AP\n" +
            "status:         ASSIGNED NON-PORTABLE\n" +
            "notify:         hostmaster@singnet.com.sg\n" +
            "mnt-by:         MAINT-SG-SINGNET\n" +
            "mnt-irt:        IRT-SINGNET-SG\n" +
            "changed:        hostmaster@singnet.com.sg 20130704\n" +
            "source:         APNIC\n" +
            "\n" +
            "irt:            IRT-SINGNET-SG\n" +
            "address:        SingNet Engineering & Operations\n" +
            "address:        2 Stirling Road\n" +
            "address:        #03-00 Queenstown Exchange\n" +
            "address:        Singapore 148943\n" +
            "e-mail:         hostmaster@singnet.com.sg\n" +
            "abuse-mailbox:  abuse@singnet.com.sg\n" +
            "admin-c:        SH9-AP\n" +
            "tech-c:         SH9-AP\n" +
            "auth:           # Filtered\n" +
            "mnt-by:         MAINT-SG-SINGNET\n" +
            "changed:        hostmaster@singnet.com.sg 20101221\n" +
            "source:         APNIC\n" +
            "\n" +
            "person:         Anurax Lian\n" +
            "address:        SIMPLE SOLUTION SYSTEMS PTE LTD\n" +
            "address:        739B HAVELOCK ROAD\n" +
            "address:        .\n" +
            "address:        Singapore 169654\n" +
            "country:        SG\n" +
            "phone:          +65\n" +
            "fax-no:         +65\n" +
            "e-mail:         anurax@simsys.sg\n" +
            "nic-hdl:        AL1082-AP\n" +
            "notify:         hostmaster@singnet.com.sg\n" +
            "mnt-by:         MAINT-SG-SINGNET\n" +
            "changed:        hostmaster@singnet.com.sg 20130704\n" +
            "source:         APNIC\n" +
            "\n" +
            "person:         SingNet Hostmaster\n" +
            "address:        SingNet Engineering & Operations\n" +
            "address:        2 Stirling Road\n" +
            "address:        #03-00 Queenstown Exchange\n" +
            "address:        Singapore 148943\n" +
            "country:        SG\n" +
            "phone:          +65 7845922\n" +
            "fax-no:         +65 4753273\n" +
            "e-mail:         hostmaster@singnet.com.sg\n" +
            "nic-hdl:        SH9-AP\n" +
            "notify:         hostmaster@singnet.com.sg\n" +
            "mnt-by:         MAINT-SG-SINGNET\n" +
            "changed:        hostmaster@singnet.com.sg 20000921\n" +
            "source:         APNIC\n" +
            "changed:        hm-changed@apnic.net 20111122\n" +
            "\n" +
            "% This query was served by the APNIC Whois Service version 1.69.1-APNICv1r0 (UNDEFINED)\n";

    @Test
    public void testRunDirectMatch() throws Exception {
        APNICResponseParser parser = new APNICResponseParser();
        for (String line : MATCH.split("\n")) {
            parser.readLine(line);
        }

        assertEquals("SG", parser.getCountryCode());
        assertEquals("SIMPLE SOLUTION SYSTEMS PTE LTD", parser.getOrganization());
    }

}