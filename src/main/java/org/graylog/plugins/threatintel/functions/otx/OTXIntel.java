package org.graylog.plugins.threatintel.functions.otx;

import com.google.common.collect.Lists;

import java.util.List;

public class OTXIntel {

    private final List<OTXPulse> pulses;
    private final List<String> pulseIds;
    private final List<String> pulseNames;

    public OTXIntel() {
        this.pulses = Lists.newArrayList();
        this.pulseIds = Lists.newArrayList();
        this.pulseNames = Lists.newArrayList();
    }

    public void addPulse(OTXPulse pulse) {
        this.pulseIds.add(pulse.getId());
        this.pulseNames.add(pulse.getName());
        this.pulses.add(pulse);
    }

    public List<OTXPulse> getPulses() {
        return this.pulses;
    }

    public List<String> getPulseIds() {
        return pulseIds;
    }

    public List<String> getPulseNames() {
        return pulseNames;
    }

    public int getPulseCount() {
        return pulses.size();
    }

}
