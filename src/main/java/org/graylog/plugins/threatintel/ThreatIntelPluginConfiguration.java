package org.graylog.plugins.threatintel;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.auto.value.AutoValue;

import javax.annotation.Nullable;

@JsonAutoDetect
@JsonIgnoreProperties(ignoreUnknown = true)
@AutoValue
public abstract class ThreatIntelPluginConfiguration {

    @JsonProperty("otx_enabled")
    @Deprecated // Not used anymore
    public abstract boolean otxEnabled();

    @JsonProperty("otx_api_key")
    @Deprecated // Only used to migrate API key from pre-2.4 setups
    @Nullable
    public abstract String otxApiKey();

    @JsonProperty("tor_enabled")
    public abstract boolean torEnabled();

    @JsonProperty("spamhaus_enabled")
    public abstract boolean spamhausEnabled();

    @JsonProperty("abusech_ransom_enabled")
    public abstract boolean abusechRansomEnabled();

    @JsonProperty("greynoise_noise_enabled")
    public abstract boolean greynoiseNoiseEnabled();


    @JsonCreator
    public static ThreatIntelPluginConfiguration create(@JsonProperty("otx_enabled") boolean otxEnabled,
                                                        @JsonProperty("otx_api_key") @Nullable String otxApiKey,
                                                        @JsonProperty("tor_enabled") boolean torEnabled,
                                                        @JsonProperty("spamhaus_enabled") boolean spamhausEnabled,
                                                        @JsonProperty("abusech_ransom_enabled") boolean abusechRansomEnabled,
                                                        @JsonProperty("greynoise_noise_enabled") boolean greynoiseNoiseEnabled) {
        return builder()
                .otxEnabled(otxEnabled)
                .otxApiKey(otxApiKey)
                .torEnabled(torEnabled)
                .spamhausEnabled(spamhausEnabled)
                .abusechRansomEnabled(abusechRansomEnabled)
                .greynoiseNoiseEnabled(greynoiseNoiseEnabled)
                .build();
    }

    public static Builder builder() {
        return new AutoValue_ThreatIntelPluginConfiguration.Builder();
    }

    public static ThreatIntelPluginConfiguration defaults() {
        return builder()
                .otxEnabled(false)
                .torEnabled(false)
                .spamhausEnabled(false)
                .abusechRansomEnabled(false)
                .greynoiseNoiseEnabled(false)
                .build();
    }

    @AutoValue.Builder
    public static abstract class Builder {
        @Deprecated
        public abstract Builder otxEnabled(boolean otxEnabled);

        @Deprecated
        abstract Builder otxApiKey(String otxApiKey);

        public abstract Builder torEnabled(boolean torEnabled);

        public abstract Builder spamhausEnabled(boolean spamhausEnabled);

        public abstract Builder abusechRansomEnabled(boolean abusechRansomEnabled);

        public abstract Builder greynoiseNoiseEnabled(boolean greynoiseNoiseEnabled);

        public abstract ThreatIntelPluginConfiguration build();
    }

}
