package org.graylog.plugins.threatintel.providers.otx.json;

import com.fasterxml.jackson.annotation.JsonProperty;

public class OTXResponse {

    @JsonProperty("pulse_info")
    public OTXPulseInfoResponse pulseInfo;

}