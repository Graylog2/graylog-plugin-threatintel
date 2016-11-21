package org.graylog.plugins.threatintel.providers.spamhaus;

import com.codahale.metrics.Timer;
import com.google.common.collect.ImmutableList;
import okhttp3.Call;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.apache.commons.net.util.SubnetUtils;
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

public class SpamhausIpLookupProvider extends LocalCopyListProvider<GenericLookupResult> implements GlobalIncludedProvider {

    private static final Logger LOG = LoggerFactory.getLogger(SpamhausIpLookupProvider.class);

    private static SpamhausIpLookupProvider INSTANCE = new SpamhausIpLookupProvider();

    public static final String NAME = "Spamhaus";
    public static final String IDENTIFIER = "spamhaus";

    public static SpamhausIpLookupProvider getInstance() {
        return INSTANCE;
    }

    private static final String[] lists = {
            "https://www.spamhaus.org/drop/drop.txt",
            "https://www.spamhaus.org/drop/edrop.txt"
    };

    private ImmutableList<SubnetUtils.SubnetInfo> subnets = new ImmutableList.Builder<SubnetUtils.SubnetInfo>().build();

    private SpamhausIpLookupProvider() {
        super(NAME);
    }

    @Override
    protected boolean isEnabled() {
        return this.config != null && this.config.spamhausEnabled();
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

        GenericLookupResult result = GenericLookupResult.FALSE;
        Timer.Context timer = this.lookupTiming.time();
        for (SubnetUtils.SubnetInfo subnet : subnets) {
            if(subnet.isInRange(ip)) {
                result = GenericLookupResult.TRUE;
                break;
            }
        }
        timer.stop();

        return result;
    }

    protected void refreshTable() throws ExecutionException {
        LOG.info("Refreshing internal table of Spamhaus drop list IPs.");
        ImmutableList.Builder<SubnetUtils.SubnetInfo> list = new ImmutableList.Builder<>();

        // TODO make timeouts configurable
        OkHttpClient client = new OkHttpClient.Builder()
                .connectTimeout(10, TimeUnit.SECONDS)
                .readTimeout(15, TimeUnit.SECONDS)
                .followSslRedirects(true)
                .build();

        for (String url : lists) {
            Response response = null;

            Call request = client.newCall(new Request.Builder()
                    .get()
                    .url(url)
                    .header("User-Agent", "graylog-server (threatintel-plugin)")
                    .build());

            try {
                Timer.Context timer = this.refreshTiming.time();
                response = request.execute();
                timer.stop();

                if (response.code() != 200) {
                    throw new ExecutionException("Expected Spamhaus to respond with HTTP status 200 but got [" + response.code() + "].", null);
                }

                // Read response line by line.
                Scanner scanner = new Scanner(response.body().byteStream());
                while (scanner.hasNextLine()) {
                    String line = scanner.nextLine().trim();

                    if (!line.isEmpty() && !line.startsWith(";") && line.contains(";")) {
                        String[] parts = line.split(";");

                        SubnetUtils su = new SubnetUtils(parts[0].trim());
                        list.add(su.getInfo());
                    }
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
        this.subnets = list.build();
    }

}
