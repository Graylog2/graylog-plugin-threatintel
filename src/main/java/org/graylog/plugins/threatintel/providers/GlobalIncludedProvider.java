package org.graylog.plugins.threatintel.providers;

public interface GlobalIncludedProvider {

    String getIdentifier();
    GenericLookupResult lookup(String key, boolean silentOnDisabled) throws Exception;

}
