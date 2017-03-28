package org.graylog.plugins.threatintel.providers.graylog.classification.ip;

import com.codahale.metrics.Timer;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableMap;
import okhttp3.Call;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.apache.commons.net.util.SubnetUtils;
import org.graylog.plugins.threatintel.providers.LocalCopyListProvider;
import org.graylog.plugins.threatintel.providers.graylog.classification.GraylogIPClassification;
import org.graylog.plugins.threatintel.providers.graylog.classification.GraylogClassificationResult;
import org.graylog.plugins.threatintel.providers.graylog.classification.GraylogIPClassificationList;
import org.graylog.plugins.threatintel.tools.PrivateNet;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

public class GraylogIPClassificationProvider extends LocalCopyListProvider<GraylogClassificationResult> {

    public static final String NAME = "Graylog IP Classification";
    public static final String FEED = "https://s3-eu-west-1.amazonaws.com/graylog-enterprise/classifications/ipv4.json";

    private static GraylogIPClassificationProvider INSTANCE = new GraylogIPClassificationProvider();

    private final ObjectMapper om;

    public static GraylogIPClassificationProvider getInstance() {
        return INSTANCE;
    }

    private GraylogIPClassificationProvider() {
        super(NAME);

        // TODO inject
        this.om = new ObjectMapper();
        this.om.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        this.om.configure(DeserializationFeature.FAIL_ON_IGNORED_PROPERTIES, false);
    }

    private ImmutableMap<SubnetUtils.SubnetInfo, GraylogIPClassification> classifications = new ImmutableMap.Builder<SubnetUtils.SubnetInfo, GraylogIPClassification>().build();

    @Override
    protected boolean isEnabled() {
        return this.config != null && this.config.graylogIPClassificationsEnabled();
    }

    @Override
    protected GraylogClassificationResult fetchIntel(String ip) throws Exception {
        if(PrivateNet.isInPrivateAddressSpace(ip)) {
            LOG.debug("IP [{}] is in private net as defined in RFC1918. Skipping.", ip);
            return GraylogClassificationResult.FALSE;
        }

        GraylogClassificationResult result = GraylogClassificationResult.FALSE;
        Timer.Context timer = this.lookupTiming.time();
        for (Map.Entry<SubnetUtils.SubnetInfo, GraylogIPClassification> classification : classifications.entrySet()) {
            if (classification.getKey().isInRange(ip)) {
                result = GraylogClassificationResult.buildFromClassification(classification.getValue());
                break;
            }
        }

        timer.stop();

        return result;
    }

    @Override
    protected void refreshTable() throws ExecutionException {
        LOG.info("Refreshing internal table of Graylog classification networks.");
        ImmutableMap.Builder<SubnetUtils.SubnetInfo, GraylogIPClassification> list = new ImmutableMap.Builder<>();

        // TODO make timeouts configurable
        OkHttpClient client = new OkHttpClient.Builder()
                .connectTimeout(10, TimeUnit.SECONDS)
                .readTimeout(15, TimeUnit.SECONDS)
                .followSslRedirects(true)
                .build();

        Call request = client.newCall(new Request.Builder()
                .get()
                .url(FEED)
                .header("User-Agent", "graylog-server (threatintel-plugin)")
                .build());

        Response response = null;
        try {
            Timer.Context timer = this.refreshTiming.time();
            response = request.execute();
            timer.stop();

            if (response.code() != 200) {
                throw new ExecutionException("Expected Graylog classification service to respond with HTTP status 200 but got [" + response.code() + "].", null);
            }

            // Parse response
            GraylogIPClassificationList result = om.readValue(response.body().bytes(), GraylogIPClassificationList.class);
            for (GraylogIPClassification classification : result.classifications) {
                SubnetUtils su = new SubnetUtils(classification.cidr);
                list.put(su.getInfo(), classification);
            }
        } catch(IOException e) {
            throw new ExecutionException("Could not refresh local source table.", e);
        } finally {
            if(response != null) {
                response.close();
            }
        }

        // Le overwrite.
        this.classifications = list.build();
    }

}
