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
package org.graylog.plugins.threatintel.adapters.abusech;

import com.codahale.metrics.MetricRegistry;
import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeName;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.google.auto.value.AutoValue;
import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.Multimap;
import com.google.inject.Inject;
import com.google.inject.assistedinject.Assisted;
import org.graylog.autovalue.WithBeanGetter;
import org.graylog.plugins.threatintel.PluginConfigService;
import org.graylog.plugins.threatintel.tools.AdapterDisabledException;
import org.graylog2.lookup.adapters.dsvhttp.DSVParser;
import org.graylog2.lookup.adapters.dsvhttp.HTTPFileRetriever;
import org.graylog2.plugin.lookup.LookupCachePurge;
import org.graylog2.plugin.lookup.LookupDataAdapter;
import org.graylog2.plugin.lookup.LookupDataAdapterConfiguration;
import org.graylog2.plugin.lookup.LookupResult;
import org.joda.time.Duration;
import org.joda.time.Period;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import javax.validation.constraints.Min;
import java.io.IOException;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

public class AbuseChRansomAdapter extends LookupDataAdapter {
    private static final Logger LOG = LoggerFactory.getLogger(AbuseChRansomAdapter.class);

    // abuse.ch lists are updated every 5 mins, we check more often to avoid lagging behind too much.
    // the adapter makes conditional requests to avoid reloading the data too often
    // for changes in update interval and URLs see https://ransomwaretracker.abuse.ch/blocklist/
    private static final int REFRESH_INTERVAL = Period.minutes(5).toStandardSeconds().getSeconds() / 2;

    public static final String NAME = "abuse-ch-ransom";
    private static final LookupResult TRUE_RESULT = LookupResult.single(true);

    private final HTTPFileRetriever httpFileRetriever;
    private final PluginConfigService pluginConfigService;
    private final AtomicReference<Set<String>> lookupRef = new AtomicReference<>(Collections.emptySet());
    private final DSVParser dsvParser;
    private final BlocklistType blocklistType;

    @Inject
    public AbuseChRansomAdapter(@Assisted("id") String id,
                                @Assisted("name") String name,
                                @Assisted LookupDataAdapterConfiguration config,
                                MetricRegistry metricRegistry,
                                HTTPFileRetriever httpFileRetriever,
                                PluginConfigService pluginConfigService) {
        super(id, name, config, metricRegistry);
        this.httpFileRetriever = httpFileRetriever;
        this.pluginConfigService = pluginConfigService;
        blocklistType = ((Config) getConfig()).blocklistType();
        dsvParser = new DSVParser(
                "#",
                "\n",
                ",",
                "\"",
                true,
                blocklistType.isCaseInsensitive(),
                0,
                Optional.of(0)
        );
    }

    @Override
    public void doStart() throws Exception {
        if (!pluginConfigService.config().getCurrent().abusechRansomEnabled()) {
            throw new AdapterDisabledException("Abuse.ch service is disabled, not starting adapter. To enable it please go to System / Configurations.");
        }
        final Config config = ((Config) getConfig());
        LOG.debug("Starting abuse.ch data adapter for blocklist {}", config.blocklistType());
        if (config.refreshInterval() < 1) {
            throw new IllegalStateException("Check interval setting cannot be smaller than 1");
        }

        loadData();
    }

    @Override
    protected void doStop() throws Exception {
        // nothing to do
    }

    @Override
    public Duration refreshInterval() {
        if (!pluginConfigService.config().getCurrent().abusechRansomEnabled()) {
            return Duration.ZERO;
        }
        return Duration.standardSeconds(((Config) getConfig()).refreshInterval());
    }

    @Override
    protected void doRefresh(LookupCachePurge cachePurge) throws Exception {
        if (!pluginConfigService.config().getCurrent().abusechRansomEnabled()) {
            throw new AdapterDisabledException("Abuse.ch service is disabled, not refreshing adapter. To enable it please go to System / Configurations.");
        }
        loadData();
        cachePurge.purgeAll();
    }

    private void loadData() throws IOException {
        final Optional<String> response = httpFileRetriever.fetchFileIfNotModified(blocklistType.getUrl());

        response.ifPresent(body -> {
            final Map<String, String> map = dsvParser.parse(body);
            lookupRef.set(map.keySet());
        });
    }

    @Override
    protected LookupResult doGet(Object key) {
        return lookupRef.get().contains(key.toString())
                ? TRUE_RESULT
                : LookupResult.empty();
    }

    @Override
    public void set(Object key, Object value) {
        // not supported
    }

    public interface Factory extends LookupDataAdapter.Factory<AbuseChRansomAdapter> {
        @Override
        AbuseChRansomAdapter create(@Assisted("id") String id,
                                    @Assisted("name") String name,
                                    LookupDataAdapterConfiguration configuration);

        @Override
        Descriptor getDescriptor();
    }

    public static class Descriptor extends LookupDataAdapter.Descriptor<Config> {

        public Descriptor() {
            super(NAME, Config.class);
        }

        @Override
        public Config defaultConfiguration() {
            return Config.builder()
                    .type(NAME)
                    .refreshInterval(REFRESH_INTERVAL)
                    .blocklistType(BlocklistType.DOMAINS)
                    .build();
        }
    }

    @AutoValue
    @WithBeanGetter
    @JsonAutoDetect
    @JsonDeserialize(builder = AutoValue_AbuseChRansomAdapter_Config.Builder.class)
    @JsonTypeName(NAME)
    public static abstract class Config implements LookupDataAdapterConfiguration {

        public static Builder builder() {
            return new AutoValue_AbuseChRansomAdapter_Config.Builder();
        }

        @Override
        @JsonProperty(TYPE_FIELD)
        public abstract String type();

        @JsonProperty("refresh_interval")
        @Min(150) // see REFRESH_INTERVAL
        public abstract long refreshInterval();

        @Nullable
        @JsonProperty("refresh_interval_unit")
        public abstract TimeUnit refreshIntervalUnit();

        @JsonProperty("blocklist_type")
        public abstract BlocklistType blocklistType();

        @Override
        public Optional<Multimap<String, String>> validate() {
            final ArrayListMultimap<String, String> errors = ArrayListMultimap.create();

            return errors.isEmpty() ? Optional.empty() : Optional.of(errors);
        }

        @AutoValue.Builder
        public abstract static class Builder {
            @JsonProperty(TYPE_FIELD)
            public abstract Builder type(String type);

            @JsonProperty("refresh_interval")
            public abstract Builder refreshInterval(long refreshInterval);

            @JsonProperty("blocklist_type")
            public abstract Builder blocklistType(BlocklistType blocklistType);

            @JsonProperty("refresh_interval_unit")
            public abstract Builder refreshIntervalUnit(@Nullable TimeUnit refreshIntervalUnit);

            public abstract Config build();
        }
    }
}
