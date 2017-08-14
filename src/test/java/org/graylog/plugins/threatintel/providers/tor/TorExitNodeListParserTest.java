package org.graylog.plugins.threatintel.providers.tor;

import com.google.common.collect.Lists;
import org.junit.Test;

import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.AbstractMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

public class TorExitNodeListParserTest {
    @Test
    public void parseValidExitNodeList() throws Exception {
        final URL torExitNodeListURL = TorExitNodeListParser.class.getResource("TorExitNodeList-20170814133408.txt");
        final Path torExitNodeListPath = Paths.get(torExitNodeListURL.toURI());
        final String torExitNodeList = new String(Files.readAllBytes(torExitNodeListPath), StandardCharsets.UTF_8);

        final TorExitNodeListParser parser = new TorExitNodeListParser();

        final Map<String, List<String>> result = parser.parse(torExitNodeList);

        assertThat(result)
                .isNotNull()
                .isNotEmpty()
                .hasSize(873);

        assertThat(result)
                .contains(new AbstractMap.SimpleEntry<String, List<String>>("51.15.79.107", Lists.newArrayList("5D5006E4992F2F97DF4F8B926C3688870EB52BD8")))
                .contains(new AbstractMap.SimpleEntry<String, List<String>>("104.223.123.98", Lists.newArrayList(
                        "02A627FA195809A3ABE031B7864CCA7A310F1D44",
                        "7016E939A2DD6EF2FB66A33F1DD45357458B737F",
                        "8175A86D8896CEA37FDC67311F9BDC1DDCBE8136",
                        "D4010FAD096CFB59278015F711776D8CCB2735EC"
                )))
                .doesNotContainKey("1.2.3.4");
    }
}