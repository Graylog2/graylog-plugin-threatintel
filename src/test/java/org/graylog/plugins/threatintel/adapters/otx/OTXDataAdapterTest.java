package org.graylog.plugins.threatintel.adapters.otx;

import com.codahale.metrics.MetricRegistry;
import com.google.common.io.Resources;
import okhttp3.OkHttpClient;
import okhttp3.ResponseBody;
import org.graylog2.plugin.lookup.LookupResult;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

import java.net.URL;

import static java.util.Objects.requireNonNull;
import static org.assertj.core.api.Assertions.assertThat;

public class OTXDataAdapterTest {
    @Rule
    public final MockitoRule mockitoRule = MockitoJUnit.rule();

    private OTXDataAdapter otxDataAdapter;

    @Before
    public void setUp() throws Exception {
        final OTXDataAdapter.Config defaultConfiguration = new OTXDataAdapter.Descriptor().defaultConfiguration();
        final MetricRegistry metricRegistry = new MetricRegistry();

        this.otxDataAdapter = new OTXDataAdapter("1", "otx-test", defaultConfiguration, new OkHttpClient(), metricRegistry);
    }

    @Test
    public void parseResponse() throws Exception {
        final URL url = Resources.getResource(getClass(), "otx-IPv4-response.json");
        final ResponseBody body = ResponseBody.create(null, Resources.toByteArray(url));
        final LookupResult result = otxDataAdapter.parseResponse(body);

        assertThat(result.singleValue()).isEqualTo(0L);
        assertThat(result.multiValue()).isNotNull();
        assertThat(requireNonNull(result.multiValue()).get("country_name")).isEqualTo("Ireland");
    }
    
}