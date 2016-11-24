package org.graylog.plugins.threatintel.whois.ip.parsers;

import org.junit.Test;

import static org.junit.Assert.*;

public class RIPENCCResponseParserTest {

    private static final String MATCH = "% Note: this output has been filtered.\n" +
            "%       To receive output for a database update, use the \"-B\" flag.\n" +
            "\n" +
            "% Information related to '62.138.64.0 - 62.138.127.255'\n" +
            "\n" +
            "% Abuse contact for '62.138.64.0 - 62.138.127.255' is 'abuse@plusserver.de'\n" +
            "\n" +
            "inetnum:        62.138.64.0 - 62.138.127.255\n" +
            "netname:        DE-HEG-MANAGED\n" +
            "descr:          Managed Sub Alloc\n" +
            "country:        DE\n" +
            "org:            ORG-HM63-RIPE\n" +
            "admin-c:        HM5127-RIPE\n" +
            "tech-c:         HM5127-RIPE\n" +
            "status:         SUB-ALLOCATED PA\n" +
            "mnt-by:         MNT-HEG\n" +
            "mnt-lower:      MNT-HEG-MANAGED\n" +
            "mnt-domains:    MNT-HEG-MANAGED\n" +
            "mnt-routes:     MNT-HEG-MANAGED\n" +
            "created:        2015-11-18T10:28:01Z\n" +
            "last-modified:  2015-11-18T10:28:01Z\n" +
            "source:         RIPE # Filtered\n" +
            "\n" +
            "organisation:   ORG-HM63-RIPE\n" +
            "org-name:       HEG Managed\n" +
            "org-type:       OTHER\n" +
            "address:        Plusserver\n" +
            "address:        Welserstrasse 14\n" +
            "address:        51149 Koeln\n" +
            "address:        Germany\n" +
            "phone:          +49 2203 1045 0\n" +
            "admin-c:        HM5127-RIPE\n" +
            "tech-c:         HM5127-RIPE\n" +
            "abuse-c:        HMAH4-RIPE\n" +
            "mnt-ref:        MNT-HEG-MANAGED\n" +
            "mnt-by:         MNT-HEG-MANAGED\n" +
            "created:        2015-11-10T12:53:28Z\n" +
            "last-modified:  2015-11-10T12:53:28Z\n" +
            "source:         RIPE # Filtered\n" +
            "\n" +
            "role:           HEG Managed\n" +
            "address:        HEG Managed\n" +
            "address:        Welserstrasse 14\n" +
            "address:        51149 Koeln\n" +
            "address:        Germany\n" +
            "phone:          +49 2203 1045 0\n" +
            "admin-c:        OK2765-RIPE\n" +
            "tech-c:         OK2765-RIPE\n" +
            "nic-hdl:        HM5127-RIPE\n" +
            "mnt-by:         MNT-HEG-MANAGED\n" +
            "created:        2015-11-05T11:35:03Z\n" +
            "last-modified:  2015-12-07T15:15:08Z\n" +
            "source:         RIPE # Filtered\n" +
            "\n" +
            "% Information related to '62.138.64.0/18AS61157'\n" +
            "\n" +
            "route:          62.138.64.0/18\n" +
            "descr:          PlusServer\n" +
            "origin:         AS61157\n" +
            "mnt-by:         MNT-HEG-MANAGED\n" +
            "created:        2016-02-18T14:31:30Z\n" +
            "last-modified:  2016-10-25T13:43:37Z\n" +
            "source:         RIPE\n" +
            "\n" +
            "% This query was served by the RIPE Database Query Service version 1.88 (HEREFORD)\n";

    @Test
    public void testRunDirectMatch() throws Exception {
        RIPENCCResponseParser parser = new RIPENCCResponseParser();
        for (String line : MATCH.split("\n")) {
            parser.readLine(line);
        }

        assertEquals("DE", parser.getCountryCode());
        assertEquals("HEG Managed", parser.getOrganization());
    }

}