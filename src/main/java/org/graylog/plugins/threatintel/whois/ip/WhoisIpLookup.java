package org.graylog.plugins.threatintel.whois.ip;

import org.apache.commons.io.IOUtils;
import org.graylog.plugins.threatintel.whois.ip.parsers.AFRINICResponseParser;
import org.graylog.plugins.threatintel.whois.ip.parsers.APNICResponseParser;
import org.graylog.plugins.threatintel.whois.ip.parsers.ARINResponseParser;
import org.graylog.plugins.threatintel.whois.ip.parsers.LACNICResponseParser;
import org.graylog.plugins.threatintel.whois.ip.parsers.RIPENCCResponseParser;
import org.graylog.plugins.threatintel.whois.ip.parsers.WhoisParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

public class WhoisIpLookup {

    protected static final Logger LOG = LoggerFactory.getLogger(WhoisIpLookup.class);

    private static final int PORT = 43;

    private final InternetRegistry defaultRegistry;

    public WhoisIpLookup(InternetRegistry defaultRegistry) {
        this.defaultRegistry = defaultRegistry;
    }

    public WhoisIpLookupResult run(String ip) throws Exception {
        return run(this.defaultRegistry, ip);
    }

    public WhoisIpLookupResult run(InternetRegistry registry, String ip) throws Exception {
        // Figure out the right response parser for the registry we are asking.
        WhoisParser parser;
        switch(registry) {
            case AFRINIC:
                parser = new AFRINICResponseParser();
                break;
            case APNIC:
                parser = new APNICResponseParser();
                break;
            case ARIN:
                parser = new ARINResponseParser();
                break;
            case LACNIC:
                parser = new LACNICResponseParser();
                break;
            case RIPENCC:
                parser = new RIPENCCResponseParser();
                break;
            default:
                throw new RuntimeException("No parser implemented for [" + registry.name() + "] responses.");
        }

        try (final Socket socket = new Socket(registry.getWhoisServer(), PORT)){
            final OutputStream out = socket.getOutputStream();
            final InputStream in = socket.getInputStream();

            out.write((ip + "\n").getBytes(StandardCharsets.UTF_8));

            IOUtils.readLines(in, StandardCharsets.UTF_8).forEach(parser::readLine);

            // Handle registry redirect.
            if(parser.isRedirect()) {
                // STAND BACK FOR STACKOVERFLOWEXCEPTION
                if(registry.equals(parser.getRegistryRedirect())) {
                    /*
                     *                ,--._,--.
                     *              ,'  ,'   ,-`.
                     *   (`-.__    /  ,'   /
                     *    `.   `--'        \__,--'-.
                     *      `--/       ,-.  ______/
                     *        (o-.     ,o- /
                     *         `. ;        \
                     *          |:          \
                     *         ,'`       ,   \
                     *        (o o ,  --'     :
                     *         \--','.        ;
                     *          `;;  :       /
                     *     GARY  ;'  ;  ,' ,'
                     *           ,','  :  '
                     *           \ \   :
                     */
                    LOG.error("{} redirected us back to itself. The Elders of the Internet say: This cannot happen(tm).", registry.toString());
                    return null;
                }

                // Actually run WHOIS request on registry we got redirected to.
                return run(parser.getRegistryRedirect(), ip);
            }

            return new WhoisIpLookupResult(parser.getOrganization(), parser.getCountryCode());
        } catch (IOException e) {
            LOG.error("Could not lookup WHOIS information for [{}] at [{}].", ip, registry.toString());
            throw e;
        }
    }

}
