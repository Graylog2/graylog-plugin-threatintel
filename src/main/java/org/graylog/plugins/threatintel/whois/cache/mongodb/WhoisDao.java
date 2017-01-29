package org.graylog.plugins.threatintel.whois.cache.mongodb;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.auto.value.AutoValue;
import org.mongojack.Id;
import org.mongojack.ObjectId;

import javax.annotation.Nullable;
import java.util.Date;

@AutoValue
@JsonAutoDetect
public abstract class WhoisDao {

    @JsonProperty("id")
    @Nullable
    @Id
    @ObjectId
    public abstract String id();

    @JsonProperty
    public abstract String ipAddress();

    @JsonProperty
    public abstract String organization();

    @JsonProperty
    public abstract String countryCode();

    @JsonProperty
    // This has a TTL index on it. Make sure it's always stored as Date BSON type in MongoDB.
    public abstract Date createdAt();

    public static Builder builder() {
        return new AutoValue_WhoisDao.Builder();
    }

    public abstract Builder toBuilder();

    @JsonCreator
    public static WhoisDao create(@Id @ObjectId @JsonProperty("_id") @Nullable String id,
                                  @JsonProperty("ip_address")  String ipAddress,
                                  @JsonProperty("organization") String organization,
                                  @JsonProperty("country_code") String countryCode,
                                  @JsonProperty("created_at") @Nullable Date createdAt) {
        return builder()
                .id(id)
                .ipAddress(ipAddress)
                .organization(organization)
                .countryCode(countryCode)
                .createdAt(createdAt)
                .build();
    }

    @AutoValue.Builder
    public abstract static class Builder {
        public abstract WhoisDao build();

        public abstract Builder id(String id);

        public abstract Builder ipAddress(String ipAddress);

        public abstract Builder organization(String organization);

        public abstract Builder countryCode(String countryCode);

        public abstract Builder createdAt(Date createdAt);
    }

}
