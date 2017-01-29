package org.graylog.plugins.threatintel.whois.cache.mongodb;

import com.codahale.metrics.Gauge;
import com.codahale.metrics.Meter;
import com.codahale.metrics.MetricRegistry;
import com.codahale.metrics.Timer;
import com.google.inject.Inject;
import com.mongodb.BasicDBObject;
import org.graylog.plugins.threatintel.whois.cache.WhoisCacheService;
import org.graylog2.bindings.providers.MongoJackObjectMapperProvider;
import org.graylog2.database.MongoConnection;
import org.graylog2.database.NotFoundException;
import org.mongojack.DBSort;
import org.mongojack.JacksonDBCollection;
import org.mongojack.WriteResult;

import static com.codahale.metrics.MetricRegistry.name;

public class MongoDBWhoisCacheService implements WhoisCacheService {

    private static final String COLLECTION = "ti_whois_cache";

    private final JacksonDBCollection<WhoisDao, String> dbCollection;
    private final MetricRegistry metrics;

    private final Meter lookupCount;
    private final Meter writeCount;
    private final Timer lookups;
    private final Timer writes;

    @Inject
    public MongoDBWhoisCacheService(MongoConnection mongoConnection,
                                    MongoJackObjectMapperProvider mapper,
                                    MetricRegistry metrics) {

        this.metrics = metrics;

        this.dbCollection = JacksonDBCollection.wrap(
                mongoConnection.getDatabase().getCollection(COLLECTION),
                WhoisDao.class,
                String.class,
                mapper.get());

        // TTL.
        this.dbCollection.createIndex(DBSort.asc("last_accessed_at"), new BasicDBObject("expireAfterSeconds", 36*60*60));

        // Normal indices.
        this.dbCollection.createIndex(DBSort.asc("ip_address"));

        // Metrics
        this.lookupCount = metrics.meter(name(this.getClass(), "lookupCount"));
        this.writeCount = metrics.meter(name(this.getClass(), "writeCount"));
        this.lookups = metrics.timer(name(this.getClass(), "lookupTime"));
        this.writes = metrics.timer(name(this.getClass(), "writeTime"));
        metrics.register(name(this.getClass(), "cacheSize"), new Gauge<Long>() {
            @Override
            public Long getValue() {
                return dbCollection.count();
            }
        });
    }

    @Override
    public WhoisDao save(WhoisDao rule) {
        writeCount.mark();

        Timer.Context time = writes.time();
        final WriteResult<WhoisDao, String> save = dbCollection.save(rule);
        time.stop();
        return save.getSavedObject();
    }

    @Override
    public WhoisDao findByIPAddress(String ip) throws NotFoundException {
        lookupCount.mark();

        Timer.Context time = lookups.time();
        final WhoisDao entry = dbCollection.findOne(new BasicDBObject("ip_address", ip));
        time.stop();
        if(entry == null) {
            throw new NotFoundException();
        }

        return entry;
    }


}