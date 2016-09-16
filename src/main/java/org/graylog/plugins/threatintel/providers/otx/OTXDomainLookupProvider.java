package org.graylog.plugins.threatintel.providers.otx;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.common.util.concurrent.ThreadFactoryBuilder;
import okhttp3.Call;
import okhttp3.HttpUrl;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.graylog.plugins.threatintel.ThreatIntelPluginConfiguration;
import org.graylog.plugins.threatintel.providers.otx.json.OTXDomainResponse;
import org.graylog.plugins.threatintel.providers.otx.json.OTXPulseResponse;
import org.graylog2.plugin.LocalMetricRegistry;
import org.graylog2.plugin.cluster.ClusterConfigService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class OTXDomainLookupProvider {

    /* TODO:
     *   metrics. how many requests actually went to api, cache misses, ...
     */
    private static final Logger LOG = LoggerFactory.getLogger(OTXDomainLookupProvider.class);


    private static OTXDomainLookupProvider INSTANCE = new OTXDomainLookupProvider();

    public static OTXDomainLookupProvider getInstance() {
        return INSTANCE;
    }

    private final LoadingCache<String, OTXIntel> cache;

    private ObjectMapper om;
    private boolean initialized = false;
    private ThreatIntelPluginConfiguration config;

    private OTXDomainLookupProvider() {
        this.cache = CacheBuilder.newBuilder()
                .expireAfterWrite(15, TimeUnit.MINUTES) // TODO make configurable. also add maximum # of entries
                .removalListener(removalNotification -> {
                    LOG.trace("Invalidating cached threat intel information for key [{}].", removalNotification.getKey());
                })
                .build(new CacheLoader<String, OTXIntel>() {
                    public OTXIntel load(String domain) throws ExecutionException {
                        LOG.trace("OTX threat intel cache MISS: [{}]", domain);
                        try {
                            return loadIntel(domain);
                        } catch (IOException e) {
                            throw new ExecutionException(e);
                        }
                    }
                });

        // TODO it should be possible to get this injected.
        this.om = new ObjectMapper();
        om.configure(DeserializationFeature.FAIL_ON_IGNORED_PROPERTIES, false);
        om.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    }

    public void initialize(final ClusterConfigService clusterConfigService,
                      final LocalMetricRegistry localRegistry) {
        if(initialized) {
            return;
        }

        // Set up config refresher and initial load.
        Runnable refresh = () -> {
            try {
                getInstance().setConfig(clusterConfigService.get(ThreatIntelPluginConfiguration.class));
            } catch (Exception e) {
                LOG.error("Could not refresh AWS instance lookup table.", e);
            }
        };

        ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor(
                new ThreadFactoryBuilder()
                        .setDaemon(true)
                        .setNameFormat("threatintel-configuration-refresher-%d")
                        .build()
        );

        executor.scheduleWithFixedDelay(refresh, 0, 15, TimeUnit.SECONDS);

        this.initialized = true;
    }

    public OTXIntel lookup(String domain) throws ExecutionException {
        // See if we are supposed to run at all.
        if(this.config == null || !this.config.otxEnabled()) {
            LOG.warn("OTX domain lookup requested but OTX is not enabled in configuration. Please enable it first.");
            return null;
        }

        if(!this.config.isComplete()) {
            LOG.warn("OTX domain lookup requested but OTX is not fully configured. Please configure all required parameters.");
            return null;
        }

        return this.cache.get(domain);
    }

    private OTXIntel loadIntel(String domain) throws IOException {
        LOG.debug("Loading OTX threat intel for domain [{}].", domain);

        // TODO: make timeouts configurable.
        OkHttpClient client = new OkHttpClient.Builder()
                .connectTimeout(2, TimeUnit.SECONDS)
                .readTimeout(3, TimeUnit.SECONDS)
                .followSslRedirects(true)
                .build();

        Call request = client.newCall(new Request.Builder()
                .get()
                .url(new HttpUrl.Builder()
                        .host("otx.alienvault.com")
                        .scheme("https")
                        .addPathSegment("api")
                        .addPathSegment("v1")
                        .addPathSegment("indicators")
                        .addPathSegment("domain")
                        .addPathSegment(domain)
                        .addPathSegment("general")
                        .build())
                .header("X-OTX-API-KEY", this.config.otxApiKey())
                .header("User-Agent", "graylog-server (threatintel-plugin)")
                .build()
        );

        Response response = request.execute();

        if(response.code() != 200) {
            throw new IOException("Expected OTX threat intel API HTTP status 200 but got [" + response.code() + "].");
        }

        // Parse response.
        OTXDomainResponse otx = om.readValue(response.body().string(), OTXDomainResponse.class);
        OTXIntel intel = new OTXIntel();
        if(otx.pulseInfo != null && otx.pulseInfo.pulses != null) {
            for (OTXPulseResponse pulse : otx.pulseInfo.pulses) {
                intel.addPulse(new OTXPulse(pulse.id, pulse.name));
            }
        } else {
            LOG.warn("Unexpected OTX domain threat intel lookup API response: {}", response.body().string().substring(0, 255));
        }

        return intel;
    }

    public void setConfig(ThreatIntelPluginConfiguration config) {
        this.config = config;
    }

}
