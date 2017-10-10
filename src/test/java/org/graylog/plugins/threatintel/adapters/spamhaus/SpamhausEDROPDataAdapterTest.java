package org.graylog.plugins.threatintel.adapters.spamhaus;

import com.codahale.metrics.MetricRegistry;
import org.graylog2.lookup.adapters.DSVHTTPDataAdapter;
import org.graylog2.lookup.adapters.dsvhttp.HTTPFileRetriever;
import org.graylog2.plugin.lookup.LookupCachePurge;
import org.graylog2.plugin.lookup.LookupDataAdapterConfiguration;
import org.graylog2.plugin.lookup.LookupResult;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.AbstractMap;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

public class SpamhausEDROPDataAdapterTest {
    @Rule
    public final MockitoRule mockitoRule = MockitoJUnit.rule();
    @Mock
    private HTTPFileRetriever httpFileRetriever;

    private final String dropSnapshot = readResourcesFile("drop.txt-snapshot-201709291400");
    private final String edropSnapshot = readResourcesFile("edrop.txt-snapshot-201709291400");

    private SpamhausEDROPDataAdapter adapter;

    public SpamhausEDROPDataAdapterTest() throws IOException, URISyntaxException {
    }

    private static String readResourcesFile(String filename) throws URISyntaxException, IOException {
        final URL torExitNodeListURL = SpamhausEDROPDataAdapterTest.class.getResource(filename);
        final Path torExitNodeListPath = Paths.get(torExitNodeListURL.toURI());
        return new String(Files.readAllBytes(torExitNodeListPath), StandardCharsets.UTF_8);
    }

    @Before
    public void setUp() throws Exception {
        this.adapter = new SpamhausEDROPDataAdapter("foobar",
                "foobar",
                mock(LookupDataAdapterConfiguration.class),
                new DSVHTTPDataAdapter.Descriptor(),
                mock(MetricRegistry.class),
                httpFileRetriever);
    }

    @Test
    public void tableStateShouldRetrieveListsSuccessfully() throws Exception {
        when(httpFileRetriever.fetchFileIfNotModified("https://www.spamhaus.org/drop/drop.txt")).thenReturn(Optional.of(dropSnapshot));
        when(httpFileRetriever.fetchFileIfNotModified("https://www.spamhaus.org/drop/edrop.txt")).thenReturn(Optional.of(edropSnapshot));
        adapter.doStart();

        verifyAdapterFunctionality(adapter);
    }

    @Test
    public void tableStateShouldStartupIfServiceMalfunctions() throws Exception {
        when(httpFileRetriever.fetchFileIfNotModified("https://www.spamhaus.org/drop/drop.txt")).thenReturn(Optional.ofNullable(null));
        when(httpFileRetriever.fetchFileIfNotModified("https://www.spamhaus.org/drop/edrop.txt")).thenReturn(Optional.ofNullable(null));

        adapter.doStart();

        final LookupResult negativeLookup = adapter.doGet("1.2.3.4");
        assertThat(negativeLookup).isNotNull();
        assertThat(negativeLookup.isEmpty()).isTrue();
    }

    @Test
    public void tableStateShouldRetainStateIfServiceMalfunctions() throws Exception {
        when(httpFileRetriever.fetchFileIfNotModified("https://www.spamhaus.org/drop/drop.txt")).thenReturn(Optional.of(dropSnapshot));
        when(httpFileRetriever.fetchFileIfNotModified("https://www.spamhaus.org/drop/edrop.txt")).thenReturn(Optional.of(edropSnapshot));

        adapter.doStart();

        when(httpFileRetriever.fetchFileIfNotModified("https://www.spamhaus.org/drop/drop.txt")).thenReturn(Optional.ofNullable(null));
        when(httpFileRetriever.fetchFileIfNotModified("https://www.spamhaus.org/drop/edrop.txt")).thenReturn(Optional.ofNullable(null));

        final LookupCachePurge lookupCachePurge = mock(LookupCachePurge.class);
        adapter.doRefresh(lookupCachePurge);

        verify(lookupCachePurge, never()).purgeAll();
        verify(lookupCachePurge, never()).purgeKey(any());
        verifyAdapterFunctionality(adapter);
    }

    @Test
    public void tableStateShouldHaveProperStateWhenOneListIsNotUpdated() throws Exception {
        when(httpFileRetriever.fetchFileIfNotModified("https://www.spamhaus.org/drop/drop.txt")).thenReturn(Optional.of("192.168.1.0/24 ; SBL0815\n"));
        when(httpFileRetriever.fetchFileIfNotModified("https://www.spamhaus.org/drop/edrop.txt")).thenReturn(Optional.of("10.1.0.0/16 ; SBL2342\n"));

        adapter.doStart();

        final LookupResult dropLookupResult = adapter.doGet("192.168.1.1");
        assertLookupResultHasMultiValue(dropLookupResult, entry("sbl_id", "SBL0815"), entry("subnet", "192.168.1.0/24"));

        final LookupResult edropLookupResult = adapter.doGet("10.1.0.1");
        assertLookupResultHasMultiValue(edropLookupResult, entry("sbl_id", "SBL2342"), entry("subnet", "10.1.0.0/16"));

        when(httpFileRetriever.fetchFileIfNotModified("https://www.spamhaus.org/drop/drop.txt")).thenReturn(Optional.of("172.16.0.0/16 ; SBL1919\n"));
        when(httpFileRetriever.fetchFileIfNotModified("https://www.spamhaus.org/drop/edrop.txt")).thenReturn(Optional.ofNullable(null));

        final LookupCachePurge lookupCachePurge = mock(LookupCachePurge.class);
        adapter.doRefresh(lookupCachePurge);

        verify(lookupCachePurge, times(1)).purgeAll();
        verify(lookupCachePurge, never()).purgeKey(any());

        final LookupResult negativeDropLookupResult = adapter.doGet("192.168.1.1");
        assertNegativeLookupResult(negativeDropLookupResult);

        final LookupResult dropLookupResult2 = adapter.doGet("172.16.0.1");
        assertLookupResultHasMultiValue(dropLookupResult2, entry("sbl_id", "SBL1919"), entry("subnet", "172.16.0.0/16"));

        final LookupResult edropLookupResult2 = adapter.doGet("10.1.0.1");
        assertLookupResultHasMultiValue(edropLookupResult2, entry("sbl_id", "SBL2342"), entry("subnet", "10.1.0.0/16"));
    }

    private void verifyAdapterFunctionality(SpamhausEDROPDataAdapter adapter) {
        final LookupResult dropLookupResult = adapter.doGet("209.66.128.1");
        assertLookupResultHasMultiValue(dropLookupResult,
                entry("sbl_id", "SBL180438"),
                entry("subnet", "209.66.128.0/19")
        );

        final LookupResult edropLookupResult = adapter.doGet("221.132.192.42");
        assertLookupResultHasMultiValue(edropLookupResult,
                entry("sbl_id", "SBL233662"),
                entry("subnet", "221.132.192.0/18")
        );

        final LookupResult negativeLookup = adapter.doGet("1.2.3.4");
        assertNegativeLookupResult(negativeLookup);
    }
    
    private void assertLookupResultHasMultiValue(LookupResult lookupResult, Map.Entry... entries) {
        assertThat(lookupResult).isNotNull();
        assertThat(lookupResult.isEmpty()).isFalse();
        assertThat(lookupResult.singleValue()).isNotNull();
        assertThat((Boolean) lookupResult.singleValue()).isTrue();
        assertThat(lookupResult.multiValue()).containsExactly(entries);
    }

    private void assertNegativeLookupResult(LookupResult negativeLookup) {
        assertThat(negativeLookup).isNotNull();
        assertThat(negativeLookup.isEmpty()).isFalse();
        assertThat(negativeLookup.singleValue()).isNotNull();
        assertThat((Boolean) negativeLookup.singleValue()).isFalse();
        assertThat(negativeLookup.multiValue()).containsExactly(
                entry("value", false)
        );
    }

    private Map.Entry<Object, Object> entry(String key, Object value) {
        return new AbstractMap.SimpleEntry<>(key, value);
    }
}