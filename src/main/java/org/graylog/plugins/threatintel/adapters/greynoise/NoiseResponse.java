package org.graylog.plugins.threatintel.adapters.greynoise;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public class NoiseResponse {

    public long offset;
    public boolean complete;

    @JsonProperty("noise_ips")
    public List<String> noiseIps;

}
