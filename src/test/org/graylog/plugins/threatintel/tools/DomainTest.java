package org.graylog.plugins.threatintel.tools;

import org.junit.Test;

import static org.junit.Assert.*;

public class DomainTest {

    @Test
    public void testPrepareDomain() throws Exception {
        // Trimming.
        assertEquals("example.org", Domain.prepareDomain("example.org "));
        assertEquals("example.org", Domain.prepareDomain(" example.org"));
        assertEquals("example.org", Domain.prepareDomain(" example.org "));

        // Getting rid of that last dot some systems will include in domain names.
        assertEquals("example.org", Domain.prepareDomain("example.org. "));
        assertEquals("example.org", Domain.prepareDomain(" example.org."));
        assertEquals("example.org", Domain.prepareDomain(" example.org. "));
    }

}