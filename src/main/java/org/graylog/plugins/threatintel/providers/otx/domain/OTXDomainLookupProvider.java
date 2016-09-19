package org.graylog.plugins.threatintel.providers.otx.domain;

import okhttp3.Call;
import okhttp3.HttpUrl;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import org.graylog.plugins.threatintel.providers.otx.OTXIntel;
import org.graylog.plugins.threatintel.providers.otx.OTXLookupProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.ExecutionException;

public class OTXDomainLookupProvider extends OTXLookupProvider {

    private static final Logger LOG = LoggerFactory.getLogger(OTXDomainLookupProvider.class);

    private static OTXDomainLookupProvider INSTANCE = new OTXDomainLookupProvider();

    public static OTXLookupProvider getInstance() {
        return INSTANCE;
    }

    private OTXDomainLookupProvider() {}

    @Override
    protected OTXIntel loadIntel(String domain) throws ExecutionException {
        LOG.debug("Loading OTX threat intel for domain [{}].", domain);

        this.lookupCount.mark();

        OkHttpClient client = getHttpClient();

        Call request = client.newCall(new Request.Builder()
                .get()
                .url(new HttpUrl.Builder()
                        .host("otx.alienvault.com")
                        .scheme("https")
                        .addPathSegment("api")
                        .addPathSegment("v1")
                        .addPathSegment("indicators")
                        .addPathSegment("domain")
                        .addPathSegment(domain)
                        .addPathSegment("general")
                        .build())
                .header("X-OTX-API-KEY", this.config.otxApiKey())
                .header("User-Agent", "graylog-server (threatintel-plugin)")
                .build()
        );

        return callOTX(request);
    }

}
