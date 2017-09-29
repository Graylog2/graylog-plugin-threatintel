package org.graylog.plugins.threatintel.adapters.spamhaus;

import com.codahale.metrics.MetricRegistry;
import org.graylog2.lookup.adapters.DSVHTTPDataAdapter;
import org.graylog2.lookup.adapters.dsvhttp.HTTPFileRetriever;
import org.graylog2.plugin.lookup.LookupCachePurge;
import org.graylog2.plugin.lookup.LookupDataAdapterConfiguration;
import org.graylog2.plugin.lookup.LookupResult;
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

    public SpamhausEDROPDataAdapterTest() throws IOException, URISyntaxException {
    }

    private static String readResourcesFile(String filename) throws URISyntaxException, IOException {
        final URL torExitNodeListURL = SpamhausEDROPDataAdapterTest.class.getResource(filename);
        final Path torExitNodeListPath = Paths.get(torExitNodeListURL.toURI());
        return new String(Files.readAllBytes(torExitNodeListPath), StandardCharsets.UTF_8);
    }

    @Test
    public void tableStateShouldRetrieveListsSuccessfully() throws Exception {
        final SpamhausEDROPDataAdapter adapter = new SpamhausEDROPDataAdapter("foobar",
                "foobar",
                mock(LookupDataAdapterConfiguration.class),
                new DSVHTTPDataAdapter.Descriptor(),
                mock(MetricRegistry.class),
                httpFileRetriever);

        when(httpFileRetriever.fetchFileIfNotModified("https://www.spamhaus.org/drop/drop.txt")).thenReturn(Optional.of(dropSnapshot));
        when(httpFileRetriever.fetchFileIfNotModified("https://www.spamhaus.org/drop/edrop.txt")).thenReturn(Optional.of(edropSnapshot));
        adapter.doStart();

        verifyAdapterFunctionality(adapter);
    }

    @Test
    public void tableStateShouldStartupIfServiceMalfunctions() throws Exception {
        final SpamhausEDROPDataAdapter adapter = new SpamhausEDROPDataAdapter("foobar",
                "foobar",
                mock(LookupDataAdapterConfiguration.class),
                new DSVHTTPDataAdapter.Descriptor(),
                mock(MetricRegistry.class),
                httpFileRetriever);

        when(httpFileRetriever.fetchFileIfNotModified("https://www.spamhaus.org/drop/drop.txt")).thenReturn(Optional.ofNullable(null));
        when(httpFileRetriever.fetchFileIfNotModified("https://www.spamhaus.org/drop/edrop.txt")).thenReturn(Optional.ofNullable(null));

        adapter.doStart();

        final LookupResult negativeLookup = adapter.doGet("1.2.3.4");
        assertThat(negativeLookup).isNotNull();
        assertThat(negativeLookup.isEmpty()).isTrue();
    }

    @Test
    public void tableStateShouldRetainStateIfServiceMalfunctions() throws Exception {
        final SpamhausEDROPDataAdapter adapter = new SpamhausEDROPDataAdapter("foobar",
                "foobar",
                mock(LookupDataAdapterConfiguration.class),
                new DSVHTTPDataAdapter.Descriptor(),
                mock(MetricRegistry.class),
                httpFileRetriever);

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

    private void verifyAdapterFunctionality(SpamhausEDROPDataAdapter adapter) {
        final LookupResult dropLookupResult = adapter.doGet("209.66.128.1");
        assertThat(dropLookupResult).isNotNull();
        assertThat(dropLookupResult.isEmpty()).isFalse();
        assertThat(dropLookupResult.singleValue()).isNotNull();
        assertThat((Boolean) dropLookupResult.singleValue()).isTrue();
        assertThat(dropLookupResult.multiValue()).containsExactly(
                new AbstractMap.SimpleEntry<Object, Object>("sbl_id", "SBL180438"),
                new AbstractMap.SimpleEntry<Object, Object>("subnet", "209.66.128.0/19")
        );

        final LookupResult edropLookupResult = adapter.doGet("221.132.192.42");
        assertThat(edropLookupResult).isNotNull();
        assertThat(edropLookupResult.isEmpty()).isFalse();
        assertThat(edropLookupResult.singleValue()).isNotNull();
        assertThat((Boolean) edropLookupResult.singleValue()).isTrue();
        assertThat(edropLookupResult.multiValue()).containsExactly(
                new AbstractMap.SimpleEntry<Object, Object>("sbl_id", "SBL233662"),
                new AbstractMap.SimpleEntry<Object, Object>("subnet", "221.132.192.0/18")
        );

        final LookupResult negativeLookup = adapter.doGet("1.2.3.4");
        assertThat(negativeLookup).isNotNull();
        assertThat(negativeLookup.isEmpty()).isFalse();
        assertThat(negativeLookup.singleValue()).isNotNull();
        assertThat((Boolean) negativeLookup.singleValue()).isFalse();
        assertThat(negativeLookup.multiValue()).containsExactly(
                new AbstractMap.SimpleEntry<Object, Object>("value", false)
        );
    }
}