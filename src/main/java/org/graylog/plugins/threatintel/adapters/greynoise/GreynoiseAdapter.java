package org.graylog.plugins.threatintel.adapters.greynoise;

import com.codahale.metrics.MetricRegistry;
import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeName;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.google.auto.value.AutoValue;
import com.google.common.base.Joiner;
import com.google.common.collect.*;
import com.google.inject.assistedinject.Assisted;
import okhttp3.*;
import org.elasticsearch.common.Strings;
import org.graylog.autovalue.WithBeanGetter;
import org.graylog.plugins.threatintel.PluginConfigService;
import org.graylog.plugins.threatintel.tools.AdapterDisabledException;
import org.graylog.plugins.threatintel.tools.PrivateNet;
import org.graylog2.plugin.lookup.LookupCachePurge;
import org.graylog2.plugin.lookup.LookupDataAdapter;
import org.graylog2.plugin.lookup.LookupDataAdapterConfiguration;
import org.graylog2.plugin.lookup.LookupResult;
import org.joda.time.Duration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import javax.inject.Inject;
import javax.validation.constraints.Min;
import javax.validation.constraints.NotNull;
import java.io.IOException;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

public class GreynoiseAdapter extends LookupDataAdapter {

    private static final Logger LOG = LoggerFactory.getLogger(GreynoiseAdapter.class);
    public static final String NAME = "greynoise-noise";

    private static final String NOISE_BULK_API_URL = "https://enterprise.api.greynoise.io/v2/noise/bulk";
    private static final String NOISE_CONTEXT_API_URL = "https://enterprise.api.greynoise.io/v2/noise/context";

    private static final Duration REFRESH_INTERVAL = Duration.standardHours(1);
    private static final int MAX_LOOPS = 500;

    private final OkHttpClient httpClient;
    private final ObjectMapper om;
    private final PluginConfigService pluginConfigService;
    private final GreynoiseAdapter.Config config;

    private final AtomicReference<List<String>> noiseIps = new AtomicReference<>(Lists.newArrayList());

    @Inject
    public GreynoiseAdapter(@Assisted("id") String id,
                                    @Assisted("name") String name,
                                    @Assisted LookupDataAdapterConfiguration config,
                                    MetricRegistry metricRegistry,
                                    OkHttpClient httpClient,
                                    ObjectMapper om,
                                    PluginConfigService pluginConfigService) {
        super(id, name, config, metricRegistry);
        this.config = (Config) config;
        this.pluginConfigService = pluginConfigService;
        this.om = om.copy()
                .configure(DeserializationFeature.FAIL_ON_IGNORED_PROPERTIES, false)
                .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        this.httpClient = httpClient.newBuilder()
                .followRedirects(true)
                .followSslRedirects(true)
                .connectTimeout(15, TimeUnit.SECONDS)
                .readTimeout(15, TimeUnit.SECONDS)
                .writeTimeout(15, TimeUnit.SECONDS)
                .build();
    }


    @Override
    protected void doStart() throws Exception {
        if (!pluginConfigService.config().getCurrent().greynoiseNoiseEnabled()) {
            throw new AdapterDisabledException("Greynoise service is disabled, not starting Greynoise adapter. To enable it please go to System / Configurations.");
        }

        noiseIps.set(fetchBulkNoiseIPs());
    }

    @Override
    protected void doStop() throws Exception {
        // Not needed.
    }

    @Override
    public Duration refreshInterval() {
        if (!pluginConfigService.config().getCurrent().greynoiseNoiseEnabled()) {
            return Duration.ZERO;
        }

        return Duration.standardSeconds(((GreynoiseAdapter.Config) getConfig()).refreshInterval());
    }

    @Override
    protected void doRefresh(LookupCachePurge cachePurge) throws Exception {
        if (!pluginConfigService.config().getCurrent().greynoiseNoiseEnabled()) {
            throw new AdapterDisabledException("Greynoise service is disabled, not starting Greynoise adapter. To enable it please go to System / Configurations.");
        }

        noiseIps.set(fetchBulkNoiseIPs());
    }

    @Override
    protected LookupResult doGet(Object key) {
        String ip = String.valueOf(key);

        if(PrivateNet.isInPrivateAddressSpace(ip)) {
            LOG.debug("Always returning false for RFC1918 (internal network) IP addresses. IP passed for lookup: [{}].", ip);
            return LookupResult.single(false);
        }

        if(this.noiseIps.get().isEmpty()) {
            return LookupResult.single(false);
        }

        if (noiseIps.get().contains(ip)) {
            try {
                return LookupResult.multi(true, enrichIp(ip));
            } catch(Exception e) {
                // Enrichment failed, but we can still add the basic information that this IP was in the noise list.
                LOG.error("Could not enrich positive Greynoise noise result with actor information.", e);
                return LookupResult.single(true);
            }
        } else {
            // IP not in Greynoise list.
            return LookupResult.single(false);
        }

    }

    @Override
    public void set(Object key, Object value) {
        // noop
    }

    private List<String> fetchBulkNoiseIPs() {
        if (Strings.isNullOrEmpty(config.apiKey())) {
            LOG.warn("No Greynoise API key configured. Not fetching noise IPs.");
            return null;
        }

        ImmutableList.Builder<String> ips = new ImmutableList.Builder<>();

        boolean finished = false;
        long offset = 0;
        int loopCount = 5; // Avoid looping forever if Greynoise never returned a "complete" flag.
        long ipCount = 0;

        LOG.info("Loading Greynoise threat intelligence noise IPs into memory. This can take a while...");
        while (!finished) {
            if (loopCount >= MAX_LOOPS) {
                LOG.error("Looped more than the maximum of <{}> times. Not loading any more data and returning NULL.", MAX_LOOPS);
                return null;
            }

            final Request.Builder requestBuilder = new Request.Builder()
                    .get()
                    .url(HttpUrl.parse(NOISE_BULK_API_URL).newBuilder()
                            .addQueryParameter("offset", String.valueOf(offset))
                            .build())
                    .header("User-Agent", "Graylog (server)")
                    .header("key", config.apiKey());

            Call request = httpClient.newCall(requestBuilder.build());

            try (Response response = request.execute()) {
                if (response.isSuccessful()) {
                    if (response.body() != null) {
                        NoiseResponse noiseResponse = om.readValue(response.body().bytes(), NoiseResponse.class);
                        if (noiseResponse.noiseIps != null) {
                            ips.addAll(noiseResponse.noiseIps);
                            ipCount += noiseResponse.noiseIps.size();
                        }

                        finished = noiseResponse.complete;
                        offset = noiseResponse.offset;

                        LOG.info("Greynoise bulk update: Retrieved <{}> IP addresses so far.", ipCount);
                    } else {
                        LOG.error("Unable to retrieve Greynoise threat intelligence noise information. Empty response.");
                        return null;
                    }
                } else {
                    LOG.error("Unable to retrieve Greynoise threat intelligence noise information. Received HTTP code <{}>.", response.code());
                    return null;
                }
            } catch (IOException e) {
                LOG.error("Unable to retrieve Greynoise threat intelligence noise information.", e);
                return null;
            } finally {
                loopCount++;
            }
        }

        LOG.info("Completed Greynoise bulk update and retrieved a total of <{}> IP addresses.", ipCount);

        return ips.build();
    }

    private ImmutableMap<Object, Object> enrichIp(@NotNull String ip) {
        if (Strings.isNullOrEmpty(config.apiKey())) {
            LOG.warn("No Greynoise API key configured. Not enriching IP with noise information.");
            return null;
        }

        final Request.Builder requestBuilder = new Request.Builder()
                .get()
                .url(NOISE_CONTEXT_API_URL + "/" + ip)
                .header("User-Agent", "Graylog (server)")
                .header("key", config.apiKey());

        Call request = httpClient.newCall(requestBuilder.build());

        try (Response response = request.execute()) {
            if (response.isSuccessful()) {
                if (response.body() != null) {
                    NoiseContext context = om.readValue(response.body().bytes(), NoiseContext.class);

                    ImmutableMap.Builder<Object, Object> result = new ImmutableMap.Builder<>();

                    /*
                     * Set a value field to true, so we can both access .value in pipelines
                     * no matter if it is a single or multi-result lookup.
                     */
                    result.put("value", true);

                    if(!Strings.isNullOrEmpty(context.actor)) {
                        result.put("actor", context.actor);
                    }

                    if(context.tags != null) {
                        result.put("actor_tags", Joiner.on(",").join(context.tags));
                    }

                    return result.build();
                } else {
                    LOG.error("Unable to enrich IP with Greynoise context. Empty response.");
                    return null;
                }
            } else {
                LOG.error("Unable to enrich IP with Greynoise context. Received HTTP code <{}>.", response.code());
                return null;
            }
        } catch (IOException e) {
            LOG.error("Unable to enrich IP with Greynoise context.", e);
            return null;
        }
    }

    public interface Factory extends LookupDataAdapter.Factory<GreynoiseAdapter> {
        @Override
        GreynoiseAdapter create(@Assisted("id") String id, @Assisted("name") String name, LookupDataAdapterConfiguration configuration);

        @Override
        GreynoiseAdapter.Descriptor getDescriptor();
    }

    public static class Descriptor extends LookupDataAdapter.Descriptor<GreynoiseAdapter.Config> {
        public Descriptor() {
            super(NAME, GreynoiseAdapter.Config.class);
        }

        @Override
        public GreynoiseAdapter.Config defaultConfiguration() {
            return GreynoiseAdapter.Config.builder()
                    .type(NAME)
                    .refreshInterval(REFRESH_INTERVAL.toStandardSeconds().getSeconds())
                    .build();
        }
    }

    @AutoValue
    @WithBeanGetter
    @JsonAutoDetect
    @JsonDeserialize(builder = AutoValue_GreynoiseAdapter_Config.Builder.class)
    @JsonTypeName(NAME)
    public static abstract class Config implements LookupDataAdapterConfiguration {

        @Override
        @JsonProperty(TYPE_FIELD)
        public abstract String type();

        // refresh interval should not be shorter than an hour per spamhaus rules
        @JsonProperty("refresh_interval")
        @Min(3600)
        public abstract long refreshInterval();

        @JsonProperty("api_key")
        @Nullable
        public abstract String apiKey();

        public static GreynoiseAdapter.Config.Builder builder() {
            return new AutoValue_GreynoiseAdapter_Config.Builder();
        }

        @Override
        public Optional<Multimap<String, String>> validate() {
            final ArrayListMultimap<String, String> errors = ArrayListMultimap.create();

            return errors.isEmpty() ? Optional.empty() : Optional.of(errors);
        }

        @AutoValue.Builder
        public abstract static class Builder {
            @JsonProperty(TYPE_FIELD)
            public abstract GreynoiseAdapter.Config.Builder type(String type);

            @JsonProperty("refresh_interval")
            public abstract GreynoiseAdapter.Config.Builder refreshInterval(long refreshInterval);

            @JsonProperty("api_key")
            public abstract GreynoiseAdapter.Config.Builder apiKey(String apiKey);

            public abstract GreynoiseAdapter.Config build();
        }
    }

}
