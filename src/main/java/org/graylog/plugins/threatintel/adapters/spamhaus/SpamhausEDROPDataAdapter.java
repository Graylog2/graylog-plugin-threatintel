package org.graylog.plugins.threatintel.adapters.spamhaus;

import com.codahale.metrics.MetricRegistry;
import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeName;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.google.auto.value.AutoValue;
import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Multimap;
import com.google.inject.assistedinject.Assisted;
import org.apache.commons.net.util.SubnetUtils;
import org.graylog.autovalue.WithBeanGetter;
import org.graylog2.lookup.adapters.DSVHTTPDataAdapter;
import org.graylog2.lookup.adapters.dsvhttp.HTTPFileRetriever;
import org.graylog2.plugin.lookup.LookupCachePurge;
import org.graylog2.plugin.lookup.LookupDataAdapter;
import org.graylog2.plugin.lookup.LookupDataAdapterConfiguration;
import org.graylog2.plugin.lookup.LookupResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.validation.constraints.Min;
import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Scanner;
import java.util.concurrent.atomic.AtomicReference;

public class SpamhausEDROPDataAdapter extends DSVHTTPDataAdapter {
    private static final Logger LOG = LoggerFactory.getLogger(SpamhausEDROPDataAdapter.class);
    public static final String NAME = "spamhaus-edrop";

    private static final String[] lists = {
            "https://www.spamhaus.org/drop/drop.txt",
            "https://www.spamhaus.org/drop/edrop.txt"
    };

    private final AtomicReference<Map<String, Map<SubnetUtils.SubnetInfo, String>>> subnets = new AtomicReference<>(Collections.emptyMap());
    private final HTTPFileRetriever httpFileRetriever;

    @Inject
    public SpamhausEDROPDataAdapter(@Assisted("id") String id,
                                    @Assisted("name") String name,
                                    @Assisted LookupDataAdapterConfiguration config,
                                    DSVHTTPDataAdapter.Descriptor dsvHttpDataAdapterDescriptor,
                                    MetricRegistry metricRegistry,
                                    HTTPFileRetriever httpFileRetriever) {
        super(id, name, dsvHttpDataAdapterDescriptor.defaultConfiguration(), metricRegistry, httpFileRetriever);
        this.httpFileRetriever = httpFileRetriever;
    }

    @Override
    public void doStart() throws Exception {
        final ImmutableMap.Builder<String, Map<SubnetUtils.SubnetInfo, String>> builder = ImmutableMap.builder();
        for (String list : lists) {
            builder.put(list, fetchSubnetsFromEDROPLists(list));
        }
        this.subnets.set(builder.build());
    }

    @Override
    protected void doRefresh(LookupCachePurge cachePurge) throws Exception {
        final Map<String, Map<SubnetUtils.SubnetInfo, String>> result = new HashMap<>(lists.length);
        for (String list : lists) {
            result.put(list, fetchSubnetsFromEDROPLists(list));
        }
        if (result.values().stream().allMatch(Objects::isNull)) {
            return;
        }
        final Map<String, Map<SubnetUtils.SubnetInfo, String>> oldList = this.subnets.get();
        result.entrySet()
                .stream()
                .filter(Objects::isNull)
                .forEach(entry -> result.put(entry.getKey(), oldList.get(entry.getKey())));

        this.subnets.set(ImmutableMap.copyOf(result));
        cachePurge.purgeAll();
    }

    private Map<SubnetUtils.SubnetInfo, String> fetchSubnetsFromEDROPLists(String list) {
        final ImmutableMap.Builder<SubnetUtils.SubnetInfo, String> builder = ImmutableMap.builder();
        try {
            final Optional<String> body = httpFileRetriever.fetchFileIfNotModified(list);
            if (body.isPresent()) {
                try (final Scanner scanner = new Scanner(body.get())) {
                    while (scanner.hasNextLine()) {
                        final String line = scanner.nextLine().trim();

                        if (!line.isEmpty() && !line.startsWith(";") && line.contains(";")) {
                            final String[] parts = line.split(";");

                            final SubnetUtils su = new SubnetUtils(parts[0].trim());
                            builder.put(su.getInfo(), parts.length > 1 ? parts[1].trim() : "N/A");
                        }
                    }
                }
            } else {
                return null;
            }
        } catch (IOException e) {
            LOG.error("Unable to retrieve Spamhaus (E)DROP list <" + list + ">: ", e);
        }

        return builder.build();
    }

    @Override
    public LookupResult doGet(Object key) {
        final String ip = String.valueOf(key);

        if (this.subnets.get().isEmpty()) {
            return LookupResult.empty();
        }

        final Optional<Map.Entry<SubnetUtils.SubnetInfo, String>> match = subnets.get().values()
                .stream()
                .flatMap(list -> list.entrySet().stream())
                .filter(entry -> entry.getKey().isInRange(ip))
                .findFirst();

        return match.map(entry -> LookupResult.multi(true,
                ImmutableMap.of("sbl_id", entry.getValue(), "subnet", entry.getKey().getCidrSignature())
        )).orElse(LookupResult.single(false));
    }

    public interface Factory extends LookupDataAdapter.Factory<SpamhausEDROPDataAdapter> {
        @Override
        SpamhausEDROPDataAdapter create(@Assisted("id") String id,
                                  @Assisted("name") String name,
                                  LookupDataAdapterConfiguration configuration);

        @Override
        SpamhausEDROPDataAdapter.Descriptor getDescriptor();
    }

    public static class Descriptor extends LookupDataAdapter.Descriptor<SpamhausEDROPDataAdapter.Config> {
        public Descriptor() {
            super(NAME, SpamhausEDROPDataAdapter.Config.class);
        }

        @Override
        public SpamhausEDROPDataAdapter.Config defaultConfiguration() {
            return SpamhausEDROPDataAdapter.Config.builder()
                    .type(NAME)
                    .refreshInterval(43200)
                    .build();
        }
    }

    @AutoValue
    @WithBeanGetter
    @JsonAutoDetect
    @JsonDeserialize(builder = AutoValue_SpamhausEDROPDataAdapter_Config.Builder.class)
    @JsonTypeName(NAME)
    public static abstract class Config implements LookupDataAdapterConfiguration {

        @Override
        @JsonProperty(TYPE_FIELD)
        public abstract String type();

        @JsonProperty("refresh_interval")
        @Min(1)
        public abstract long refreshInterval();

        public static SpamhausEDROPDataAdapter.Config.Builder builder() {
            return new AutoValue_SpamhausEDROPDataAdapter_Config.Builder();
        }

        @Override
        public Optional<Multimap<String, String>> validate() {
            final ArrayListMultimap<String, String> errors = ArrayListMultimap.create();

            return errors.isEmpty() ? Optional.empty() : Optional.of(errors);
        }

        @AutoValue.Builder
        public abstract static class Builder {
            @JsonProperty(TYPE_FIELD)
            public abstract SpamhausEDROPDataAdapter.Config.Builder type(String type);

            @JsonProperty("refresh_interval")
            public abstract SpamhausEDROPDataAdapter.Config.Builder refreshInterval(long refreshInterval);

            public abstract SpamhausEDROPDataAdapter.Config build();
        }
    }
}
