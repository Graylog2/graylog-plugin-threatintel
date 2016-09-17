package org.graylog.plugins.threatintel.pipelines.functions;

import org.junit.Test;

import static org.junit.Assert.*;

public class OTXDomainLookupFunctionTest {

    @Test
    public void testPrepareDomain() throws Exception {
        OTXDomainLookupFunction f = OTXDomainLookupFunction.buildStateless();

        // Trimming.
        assertEquals("example.org", f.prepareDomain("example.org "));
        assertEquals("example.org", f.prepareDomain(" example.org"));
        assertEquals("example.org", f.prepareDomain(" example.org "));

        // Getting rid of that last dot some systems will include in domain names.
        assertEquals("example.org", f.prepareDomain("example.org. "));
        assertEquals("example.org", f.prepareDomain(" example.org."));
        assertEquals("example.org", f.prepareDomain(" example.org. "));
    }

}