package org.graylog.plugins.threatintel.providers.abusech;

import com.codahale.metrics.Timer;
import com.google.common.collect.ImmutableList;
import okhttp3.Call;
import okhttp3.HttpUrl;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.graylog.plugins.threatintel.providers.GenericLookupResult;
import org.graylog.plugins.threatintel.providers.GlobalIncludedProvider;
import org.graylog.plugins.threatintel.providers.LocalCopyListProvider;
import org.graylog.plugins.threatintel.tools.PrivateNet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Scanner;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

public class AbuseChRansomLookupProvider extends LocalCopyListProvider<GenericLookupResult> implements GlobalIncludedProvider {

    private static final Logger LOG = LoggerFactory.getLogger(AbuseChRansomLookupProvider.class);

    private static AbuseChRansomLookupProvider INSTANCE = new AbuseChRansomLookupProvider();

    public static final String NAME = "Abuse.ch Ransomware tracker";
    public static final String IDENTIFIER = "abusech_ransomware";

    public static AbuseChRansomLookupProvider getInstance() {
        return INSTANCE;
    }

    private static final String[] lists = {
            "RW_DOMBL.txt",
            "RW_IPBL.txt"
    };

    private ImmutableList<String> domainsAndIps = new ImmutableList.Builder<String>().build();

    private AbuseChRansomLookupProvider() {
        super(NAME);
    }

    @Override
    protected boolean isEnabled() {
        return this.config != null && this.config.abusechRansomEnabled();
    }

    @Override
    public String getIdentifier() {
        return IDENTIFIER;
    }

    @Override
    protected GenericLookupResult fetchIntel(String key) throws Exception {
        // This is never matching for domains or other keys.
        if(PrivateNet.isInPrivateAddressSpace(key)) {
            LOG.debug("IP [{}] is in private net as defined in RFC1918. Skipping.", key);
            return GenericLookupResult.FALSE;
        }

        Timer.Context timer = this.lookupTiming.time();
        boolean result = domainsAndIps.contains(key);
        timer.stop();

        return result ? GenericLookupResult.TRUE : GenericLookupResult.FALSE;
    }

    @Override
    protected void refreshTable() throws ExecutionException {
        LOG.info("Refreshing internal table of Abuse.ch Ransomware tracker data.");
        Response response = null;

        // TODO make timeouts configurable
        OkHttpClient client = new OkHttpClient.Builder()
                .connectTimeout(10, TimeUnit.SECONDS)
                .readTimeout(15, TimeUnit.SECONDS)
                .followSslRedirects(true)
                .build();

        ImmutableList.Builder<String> listBuilder = new ImmutableList.Builder<>();

        for (String list : lists) {
            Call request = client.newCall(new Request.Builder()
                    .get()
                    .url(new HttpUrl.Builder()
                            .host("ransomwaretracker.abuse.ch")
                            .scheme("https")
                            .addPathSegment("downloads")
                            .addPathSegment(list)
                            .build())
                    .header("User-Agent", "graylog-server (threatintel-plugin)")
                    .build());

            try {
                Timer.Context timer = this.refreshTiming.time();
                response = request.execute();
                timer.stop();

                if(response.code() != 200) {
                    throw new ExecutionException("Expected Abuse.ch Ransomware tracker responding with HTTP status 200 but got [" + response.code() + "].", null);
                }
                // Read response line by line.
                Scanner scanner = new Scanner(response.body().byteStream());
                while (scanner.hasNextLine()) {
                    listBuilder.add(scanner.nextLine().trim());
                }
                scanner.close();
            } catch(IOException e) {

                throw new ExecutionException("Could not refresh local source table.", e);
            } finally {
                if(response != null) {
                    response.close();
                }
            }
        }

        // Le overwrite.
        this.domainsAndIps = listBuilder.build();
    }

}
