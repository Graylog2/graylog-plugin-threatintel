package org.graylog.plugins.threatintel.adapters;

import com.codahale.metrics.MetricRegistry;
import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeName;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.google.auto.value.AutoValue;
import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Multimap;
import com.google.common.primitives.Ints;
import com.google.inject.assistedinject.Assisted;
import okhttp3.Call;
import okhttp3.HttpUrl;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.graylog.autovalue.WithBeanGetter;
import org.graylog2.plugin.lookup.LookupCachePurge;
import org.graylog2.plugin.lookup.LookupDataAdapter;
import org.graylog2.plugin.lookup.LookupDataAdapterConfiguration;
import org.graylog2.plugin.lookup.LookupResult;
import org.hibernate.validator.constraints.NotEmpty;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.joda.time.Duration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.validation.constraints.Min;
import javax.validation.constraints.Size;
import java.io.IOException;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static com.google.common.base.Strings.isNullOrEmpty;

public class DSVHTTPDataAdapter extends LookupDataAdapter {
    private static final Logger LOG = LoggerFactory.getLogger(DSVHTTPDataAdapter.class);

    public static final String NAME = "dsvhttp";

    private final DSVHTTPDataAdapter.Config config;
    private final AtomicReference<Map<String, String>> lookupRef = new AtomicReference<>(ImmutableMap.of());
    private final AtomicReference<String> lastLastModified = new AtomicReference<>();
    private OkHttpClient client;

    @Inject
    public DSVHTTPDataAdapter(@Assisted("id") String id,
                              @Assisted("name") String name,
                              @Assisted LookupDataAdapterConfiguration config,
                              MetricRegistry metricRegistry) {
        super(id, name, config, metricRegistry);
        this.config = (DSVHTTPDataAdapter.Config) config;
    }

    @Override
    public void doStart() throws Exception {
        LOG.debug("Starting HTTP DSV data adapter for URL: {}", config.url());
        if (isNullOrEmpty(config.url())) {
            throw new IllegalStateException("File path needs to be set");
        }
        if (config.refreshInterval() < 1) {
            throw new IllegalStateException("Check interval setting cannot be smaller than 1");
        }

        this.client = new OkHttpClient.Builder()
                .connectTimeout(10, TimeUnit.SECONDS)
                .readTimeout(15, TimeUnit.SECONDS)
                .followSslRedirects(true)
                .followRedirects(true)
                .build();
        final Response response = fetchDSVFile(config.url());
        lookupRef.set(parseDSVBody(response));
    }

    @Override
    public Duration refreshInterval() {
        return Duration.standardSeconds(Ints.saturatedCast(config.refreshInterval()));
    }

    @Override
    protected void doRefresh(LookupCachePurge cachePurge) throws Exception {
        try {
            final Response response = fetchDSVFile(config.url());

            final String lastModifiedHeader = response.header("Last-Modified", DateTime.now(DateTimeZone.UTC).toString());

            if (response.code() == 200) {
                LOG.debug("DSV file {} has changed, updating data", config.url());
                lookupRef.set(parseDSVBody(response));
                this.lastLastModified.set(lastModifiedHeader);
                cachePurge.purgeAll();
                clearError();
            }
        } catch (IOException e) {
            LOG.error("Couldn't check data adapter <{}> DSV file {} for updates: {} {}", name(), config.url(), e.getClass().getCanonicalName(), e.getMessage());
            setError(e);
        }
    }

    private Response fetchDSVFile(String url) throws IOException {
        final Request.Builder requestBuilder = new Request.Builder()
                .get()
                .url(url)
                .header("User-Agent", "graylog-server (threatintel-plugin)");
        final String lastModified = this.lastLastModified.get();
        if (lastModified != null) {
            requestBuilder.header("If-Modified-Since", lastModified);
        }
        final Call request = client.newCall(requestBuilder.build());

        final Response response = request.execute();
        if (!response.isSuccessful()) {
            throw new IOException(response.message());
        }

        return response;
    }

    private Map<String, String> parseDSVBody(Response response) throws IOException {
        if (response.body() == null) {
            throw new IOException("HTTP request returned empty body.");
        }
        final ImmutableMap.Builder<String, String> newLookupBuilder = ImmutableMap.builder();

        final String[] lines = response.body().string().split("\n");

        try {
            for (String line : lines) {
                if (line.startsWith(config.ignorechar())) {
                    continue;
                }
                final String[] values = line.split(config.separator());
                if (values.length == 0 || (!config.isCheckPresenceOnly() && values.length == 1)) {
                    continue;
                }
                final String key = config.isCaseInsensitiveLookup() ? values[0].toLowerCase(Locale.ENGLISH) : values[0];
                final String value = config.isCheckPresenceOnly() ? "" : values[1].trim();
                newLookupBuilder.put(key.trim(), value);
            }
        } catch (Exception e) {
            LOG.error("Couldn't parse DSV file {} (settings separator=<{}> quotechar=<{}> key_column=<{}> value_column=<{}>)", config.url(),
                    config.separator(), config.quotechar(), config.keyColumn(), config.valueColumn(), e);
            setError(e);
        }

        return newLookupBuilder.build();
    }

    @Override
    public void doStop() throws Exception {
        LOG.debug("Stopping HTTP DSV data adapter for url: {}", config.url());
    }

    @Override
    public LookupResult doGet(Object key) {
        final String stringKey = config.isCaseInsensitiveLookup() ? String.valueOf(key).toLowerCase(Locale.ENGLISH) : String.valueOf(key);

        if (config.isCheckPresenceOnly()) {
            return LookupResult.single(lookupRef.get().containsKey(stringKey));
        }

        final String value = lookupRef.get().get(stringKey);

        if (value == null) {
            return LookupResult.empty();
        }

        return LookupResult.single(value);
    }

    @Override
    public void set(Object key, Object value) {

    }

    public interface Factory extends LookupDataAdapter.Factory<DSVHTTPDataAdapter> {
        @Override
        DSVHTTPDataAdapter create(@Assisted("id") String id,
                                  @Assisted("name") String name,
                                  LookupDataAdapterConfiguration configuration);

        @Override
        DSVHTTPDataAdapter.Descriptor getDescriptor();
    }

    public static class Descriptor extends LookupDataAdapter.Descriptor<DSVHTTPDataAdapter.Config> {
        public Descriptor() {
            super(NAME, DSVHTTPDataAdapter.Config.class);
        }

        @Override
        public DSVHTTPDataAdapter.Config defaultConfiguration() {
            return DSVHTTPDataAdapter.Config.builder()
                    .type(NAME)
                    .url("https://example.org/table.csv")
                    .separator(",")
                    .quotechar("\"")
                    .ignorechar("#")
                    .keyColumn("key")
                    .valueColumn("value")
                    .refreshInterval(60)
                    .caseInsensitiveLookup(false)
                    .checkPresenceOnly(false)
                    .build();
        }
    }

    @AutoValue
    @WithBeanGetter
    @JsonAutoDetect
    @JsonDeserialize(builder = AutoValue_DSVHTTPDataAdapter_Config.Builder.class)
    @JsonTypeName(NAME)
    public static abstract class Config implements LookupDataAdapterConfiguration {

        @Override
        @JsonProperty(TYPE_FIELD)
        public abstract String type();

        @JsonProperty("url")
        @NotEmpty
        public abstract String url();

        // Using String here instead of char to allow deserialization of a longer (invalid) string to get proper
        // validation error messages
        @JsonProperty("separator")
        @Size(min = 1, max = 1)
        @NotEmpty
        public abstract String separator();

        @JsonIgnore
        public char separatorAsChar() {
            return separator().charAt(0);
        }

        // Using String here instead of char to allow deserialization of a longer (invalid) string to get proper
        // validation error messages
        @JsonProperty("quotechar")
        @Size(min = 1, max = 1)
        @NotEmpty
        public abstract String quotechar();

        @JsonProperty("ignorechar")
        @Size(min = 1)
        @NotEmpty
        public abstract String ignorechar();

        @JsonIgnore
        public char quotecharAsChar() {
            return quotechar().charAt(0);
        }

        @JsonProperty("key_column")
        @NotEmpty
        public abstract String keyColumn();

        @JsonProperty("check_presence_only")
        public abstract Optional<Boolean> checkPresenceOnly();

        @JsonProperty("value_column")
        @NotEmpty
        public abstract Optional<String> valueColumn();

        @JsonProperty("refresh_interval")
        @Min(1)
        public abstract long refreshInterval();

        @JsonProperty("case_insensitive_lookup")
        public abstract Optional<Boolean> caseInsensitiveLookup();

        public boolean isCaseInsensitiveLookup() {
            return caseInsensitiveLookup().orElse(false);
        }

        public boolean isCheckPresenceOnly() {
            return checkPresenceOnly().orElse(false);
        }

        public static DSVHTTPDataAdapter.Config.Builder builder() {
            return new AutoValue_DSVHTTPDataAdapter_Config.Builder();
        }

        @Override
        public Optional<Multimap<String, String>> validate() {
            final ArrayListMultimap<String, String> errors = ArrayListMultimap.create();

            if (HttpUrl.parse(url()) == null) {
                errors.put("url", "Unable to parse url: " + url());
            }

            return errors.isEmpty() ? Optional.empty() : Optional.of(errors);
        }

        @AutoValue.Builder
        public abstract static class Builder {
            @JsonProperty(TYPE_FIELD)
            public abstract DSVHTTPDataAdapter.Config.Builder type(String type);

            @JsonProperty("url")
            public abstract DSVHTTPDataAdapter.Config.Builder url(String url);

            @JsonProperty("separator")
            public abstract DSVHTTPDataAdapter.Config.Builder separator(String separator);

            @JsonProperty("quotechar")
            public abstract DSVHTTPDataAdapter.Config.Builder quotechar(String quotechar);

            @JsonProperty("ignorechar")
            public abstract DSVHTTPDataAdapter.Config.Builder ignorechar(String ignorechar);

            @JsonProperty("key_column")
            public abstract DSVHTTPDataAdapter.Config.Builder keyColumn(String keyColumn);

            @JsonProperty("value_column")
            public abstract DSVHTTPDataAdapter.Config.Builder valueColumn(String valueColumn);

            @JsonProperty("refresh_interval")
            public abstract DSVHTTPDataAdapter.Config.Builder refreshInterval(long refreshInterval);

            @JsonProperty("case_insensitive_lookup")
            public abstract DSVHTTPDataAdapter.Config.Builder caseInsensitiveLookup(Boolean caseInsensitiveLookup);

            @JsonProperty("check_presence_only")
            public abstract DSVHTTPDataAdapter.Config.Builder checkPresenceOnly(Boolean checkPresenceOnly);

            public abstract DSVHTTPDataAdapter.Config build();
        }
    }
}