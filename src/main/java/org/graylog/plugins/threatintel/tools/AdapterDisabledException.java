package org.graylog.plugins.threatintel.tools;

public class AdapterDisabledException extends RuntimeException {
    public AdapterDisabledException(String message) {
        super(message);
    }
}
