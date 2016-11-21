package org.graylog.plugins.threatintel.providers.tor;

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

public class TorExitNodeLookupProvider extends LocalCopyListProvider<GenericLookupResult> implements GlobalIncludedProvider {

    private static final Logger LOG = LoggerFactory.getLogger(TorExitNodeLookupProvider.class);

    private static TorExitNodeLookupProvider INSTANCE = new TorExitNodeLookupProvider();

    public static final String NAME = "Tor exit nodes";
    public static final String IDENTIFIER = "tor";

    private TorExitNodeLookupProvider() {
        super(NAME);
    }

    public static TorExitNodeLookupProvider getInstance() {
        return INSTANCE;
    }

    private ImmutableList<String> exitNodes = new ImmutableList.Builder<String>().build();

    @Override
    protected boolean isEnabled() {
        return this.config != null && this.config.torEnabled();
    }

    @Override
    public String getIdentifier() {
        return IDENTIFIER;
    }

    @Override
    protected GenericLookupResult fetchIntel(String ip) throws Exception {
        if(PrivateNet.isInPrivateAddressSpace(ip)) {
            LOG.debug("IP [{}] is in private net as defined in RFC1918. Skipping.", ip);
            return GenericLookupResult.FALSE;
        }

        Timer.Context timer = this.lookupTiming.time();
        boolean result = exitNodes.contains(ip);
        timer.stop();

        return result ? GenericLookupResult.TRUE : GenericLookupResult.FALSE;
    }

    public void refreshTable() throws ExecutionException {
        LOG.info("Refreshing internal table of known Tor exit nodes.");
        Response response = null;

        // TODO make timeouts configurable
        OkHttpClient client = new OkHttpClient.Builder()
                .connectTimeout(10, TimeUnit.SECONDS)
                .readTimeout(15, TimeUnit.SECONDS)
                .followSslRedirects(true)
                .build();

        Call request = client.newCall(new Request.Builder()
                .get()
                .url(new HttpUrl.Builder()
                        .host("check.torproject.org")
                        .scheme("https")
                        .addPathSegment("exit-addresses")
                        .build())
                .header("User-Agent", "graylog-server (threatintel-plugin)")
                .build());

        try {
            Timer.Context timer = this.refreshTiming.time();
            response = request.execute();
            timer.stop();

            if(response.code() != 200) {
                throw new ExecutionException("Expected Tor exit node list responding with HTTP status 200 but got [" + response.code() + "].", null);
            }

            ImmutableList.Builder<String> list = new ImmutableList.Builder<>();

            // Read response line by line.
            Scanner scanner = new Scanner(response.body().byteStream());
            while (scanner.hasNextLine()) {
                String line = scanner.nextLine();

                if (line.startsWith("ExitAddress")) {
                    String[] parts = line.split(" ");
                    if(parts.length != 4) {
                        LOG.warn("Malformed tor exit node entry: {}", line);
                    } else {
                        String ip = parts[1];

                        LOG.debug("Adding tor exit node: {}", ip);
                        list.add(ip);
                    }
                }
            }
            scanner.close();

            // Le overwrite.
            this.exitNodes = list.build();
        } catch(IOException e) {
            throw new ExecutionException("Could not refresh local source table.", e);
        } finally {
            if(response != null) {
                response.close();
            }
        }
    }

}
