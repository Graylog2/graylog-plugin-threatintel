package org.graylog.plugins.threatintel;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.auto.value.AutoValue;

@JsonAutoDetect
@JsonIgnoreProperties(ignoreUnknown = true)
@AutoValue
public abstract class ThreatIntelPluginConfiguration {

    @JsonProperty("otx_enabled")
    public abstract boolean otxEnabled();

    @JsonProperty("otx_api_key")
    public abstract String otxApiKey();

    @JsonProperty("tor_enabled")
    public abstract boolean torEnabled();

    @JsonProperty("spamhaus_enabled")
    public abstract boolean spamhausEnabled();

    @JsonProperty("abusech_ransom_enabled")
    public abstract boolean abusechRansomEnabled();

    @JsonCreator
    public static ThreatIntelPluginConfiguration create(@JsonProperty("otx_enabled") boolean otxEnabled,
                                                        @JsonProperty("otx_api_key") String otxApiKey,
                                                        @JsonProperty("tor_enabled") boolean torEnabled,
                                                        @JsonProperty("spamhaus_enabled") boolean spamhausEnabled,
                                                        @JsonProperty("abusech_ransom_enabled") boolean abusechRansomEnabled) {
        return builder()
                .otxEnabled(otxEnabled)
                .otxApiKey(otxApiKey)
                .torEnabled(torEnabled)
                .spamhausEnabled(spamhausEnabled)
                .abusechRansomEnabled(abusechRansomEnabled)
                .build();
    }

    public static Builder builder() {
        return new AutoValue_ThreatIntelPluginConfiguration.Builder();
    }

    @JsonIgnore
    public boolean isOtxComplete() {
        return otxApiKey() != null && !otxApiKey().isEmpty();
    }

    @AutoValue.Builder
    public static abstract class Builder {
        public abstract Builder otxEnabled(boolean otxEnabled);

        public abstract Builder otxApiKey(String otxApiKey);

        public abstract Builder torEnabled(boolean torEnabled);

        public abstract Builder spamhausEnabled(boolean spamhausEnabled);

        public abstract Builder abusechRansomEnabled(boolean abusechRansomEnabled);

        public abstract ThreatIntelPluginConfiguration build();
    }

}
