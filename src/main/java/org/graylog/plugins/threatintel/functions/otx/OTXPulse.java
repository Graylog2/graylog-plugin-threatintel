package org.graylog.plugins.threatintel.functions.otx;


public class OTXPulse {

    private final String id;
    private final String name;

    public OTXPulse(String id, String name) {
        this.id = id;
        this.name = name;
    }

    public String getId() {
        return id;
    }

    public String getName() {
        return name;
    }

}
