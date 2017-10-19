package org.graylog.plugins.threatintel;

import com.google.common.collect.Maps;
import org.graylog2.plugin.cluster.ClusterConfigService;
import org.graylog2.shared.utilities.AutoValueUtils;

import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import static com.google.common.base.MoreObjects.firstNonNull;

public class TestClusterConfigService implements ClusterConfigService {
    private final Map<String, Object> data = Maps.newConcurrentMap();

    @Override
    @SuppressWarnings("unchecked")
    public <T> T get(Class<T> type) {
        return (T) data.get(type.getCanonicalName());
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T> T get(String key, Class<T> type) {
        return (T) data.get(key);
    }

    @Override
    public <T> T getOrDefault(Class<T> type, T defaultValue) {
        return firstNonNull(get(type), defaultValue);
    }

    @Override
    public <T> void write(T payload) {
        data.put(AutoValueUtils.getCanonicalName(payload.getClass()), payload);
    }

    @Override
    public <T> int remove(Class<T> type) {
        return data.remove(type.getCanonicalName()) == null ? 0 : 1;
    }

    @Override
    public Set<Class<?>> list() {
        return data.keySet()
                .stream()
                .map(className -> {
                    try {
                        return Class.forName(className);
                    } catch (ClassNotFoundException ignore) {
                        return null;
                    }
                })
                .filter(Objects::nonNull)
                .collect(Collectors.toSet());
    }

    public void clear() {
        data.clear();
    }
}
