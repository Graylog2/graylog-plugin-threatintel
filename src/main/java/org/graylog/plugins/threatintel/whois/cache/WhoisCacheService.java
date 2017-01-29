package org.graylog.plugins.threatintel.whois.cache;

import org.graylog.plugins.threatintel.whois.cache.mongodb.WhoisDao;
import org.graylog2.database.NotFoundException;

public interface WhoisCacheService {

    WhoisDao save(WhoisDao rule);
    WhoisDao findByIPAddress(String ip) throws NotFoundException;

}