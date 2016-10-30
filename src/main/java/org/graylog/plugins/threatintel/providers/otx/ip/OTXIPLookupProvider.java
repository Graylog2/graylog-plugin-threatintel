package org.graylog.plugins.threatintel.providers.otx.ip;

import okhttp3.Call;
import okhttp3.HttpUrl;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import org.graylog.plugins.threatintel.providers.otx.OTXIntel;
import org.graylog.plugins.threatintel.providers.otx.OTXLookupProvider;
import org.graylog.plugins.threatintel.tools.PrivateNet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.ExecutionException;

public class OTXIPLookupProvider extends OTXLookupProvider {

    private static final Logger LOG = LoggerFactory.getLogger(OTXIPLookupProvider.class);

    private static OTXIPLookupProvider INSTANCE = new OTXIPLookupProvider();

    public static OTXLookupProvider getInstance() {
        return INSTANCE;
    }

    private OTXIPLookupProvider() {}

    private enum IPVersion {
        IPv4, IPv6
    }

    @Override
    protected OTXIntel loadIntel(String ip) throws ExecutionException {
        LOG.debug("Loading OTX threat intel for IP [{}].", ip);

        if(ip == null || ip.isEmpty()) {
            return null;
        }

        ip = ip.trim();

        // Detect if IPv4 or IPv6 address.
        IPVersion ipType = detectIpType(ip);
        LOG.debug("Decided that IP [{}] is of type [{}].", ip, ipType);

        if(ipType == IPVersion.IPv4) {
            if(PrivateNet.isInPrivateAddressSpace(ip)) {
                LOG.debug("IP [{}] is in private net as defined in RFC1918. Skipping.", ip);
                return null;
            }
        }

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
                        .addPathSegment(ipType.toString())
                        .addPathSegment(ip)
                        .addPathSegment("general")
                        .build())
                .header("X-OTX-API-KEY", this.config.otxApiKey())
                .header("User-Agent", "graylog-server (threatintel-plugin)")
                .build()
        );

        return callOTX(request);
    }

    private IPVersion detectIpType(String ip) {
        /*
         * This is gonna be super stupid but the user can pass anything in here and trying to recognize IPv4 by a
         * regular expression just costs a lot of CPU cycles. We trust the user to pass in either IPv4 or IPv6 and
         * if he/she puts something else in here, it's not our problem. ¯\_(ツ)_/¯
         */
        if(ip.contains(".")) {
            return IPVersion.IPv4;
        }

        /*
         * If it's not IPv4, we just expect it to be IPv6. OTX API will return
         * simply no results if its any artificial string.
         */
        return IPVersion.IPv6;
    }

}
