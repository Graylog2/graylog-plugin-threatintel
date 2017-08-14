package org.graylog.plugins.threatintel.whois.ip;

import com.codahale.metrics.MetricRegistry;
import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeName;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.google.auto.value.AutoValue;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Multimap;
import com.google.inject.assistedinject.Assisted;
import org.graylog.autovalue.WithBeanGetter;
import org.graylog2.plugin.lookup.LookupCachePurge;
import org.graylog2.plugin.lookup.LookupDataAdapter;
import org.graylog2.plugin.lookup.LookupDataAdapterConfiguration;
import org.graylog2.plugin.lookup.LookupResult;
import org.joda.time.Duration;

import javax.inject.Inject;
import java.util.Map;
import java.util.Optional;

public class WhoisDataAdapter extends LookupDataAdapter {
    public static final String NAME = "whois";

    private final WhoisIpLookup whoisIpLookup;

    @Inject
    public WhoisDataAdapter(@Assisted("id") String id,
                            @Assisted("name") String name,
                            @Assisted LookupDataAdapterConfiguration config,
                            MetricRegistry metricRegistry) {
        super(id, name, config, metricRegistry);
        this.whoisIpLookup = new WhoisIpLookup(((Config) config).registry());
    }

    @Override
    protected void doStart() throws Exception {
    }

    @Override
    protected void doStop() throws Exception {
    }

    @Override
    public Duration refreshInterval() {
        return Duration.standardMinutes(60);
    }

    @Override
    protected void doRefresh(LookupCachePurge cachePurge) throws Exception {
    }

    @Override
    protected LookupResult doGet(Object key) {
        try {
            final WhoisIpLookupResult result = this.whoisIpLookup.run(key.toString());
            if (result != WhoisIpLookupResult.EMPTY) {
                final Map<Object, Object> fields = ImmutableMap.of(
                        "organization", result.getOrganization(),
                        "country_code", result.getCountryCode()
                );
                return LookupResult.multi(result.getOrganization() + "/" + result.getCountryCode(), fields);
            } else {
                return LookupResult.empty();
            }
        } catch (Exception e) {
            return LookupResult.single("Lookup Error: " + e.getMessage());
        }
    }

    @Override
    public void set(Object key, Object value) {
        throw new UnsupportedOperationException();
    }

    public interface Factory extends LookupDataAdapter.Factory<WhoisDataAdapter> {
        @Override
        WhoisDataAdapter create(@Assisted("id") String id,
                                @Assisted("name") String name,
                                LookupDataAdapterConfiguration configuration);

        @Override
        WhoisDataAdapter.Descriptor getDescriptor();
    }

    public static class Descriptor extends LookupDataAdapter.Descriptor<Config> {
        public Descriptor() {
            super(NAME, WhoisDataAdapter.Config.class);
        }

        @Override
        public WhoisDataAdapter.Config defaultConfiguration() {
            return WhoisDataAdapter.Config.builder()
                    .type(NAME)
                    .registry(InternetRegistry.ARIN)
                    .build();
        }
    }

    @AutoValue
    @WithBeanGetter
    @JsonAutoDetect
    @JsonDeserialize(builder = AutoValue_WhoisDataAdapter_Config.Builder.class)
    @JsonTypeName(NAME)
    public static abstract class Config implements LookupDataAdapterConfiguration {

        @Override
        @JsonProperty(TYPE_FIELD)
        public abstract String type();

        @JsonProperty("registry")
        public abstract InternetRegistry registry();

        public static Builder builder() {
            return new AutoValue_WhoisDataAdapter_Config.Builder();
        }

        @Override
        public Optional<Multimap<String, String>> validate() {
            return Optional.empty();
        }

        @AutoValue.Builder
        public abstract static class Builder {
            @JsonProperty(TYPE_FIELD)
            public abstract Builder type(String type);

            @JsonProperty("registry")
            public abstract Builder registry(InternetRegistry registry);

            public abstract Config build();
        }
    }
}
