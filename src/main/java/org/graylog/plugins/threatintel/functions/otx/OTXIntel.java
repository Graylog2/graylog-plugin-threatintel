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
