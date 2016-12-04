package org.graylog.plugins.threatintel.whois.ip;

import autovalue.shaded.com.google.common.common.collect.Maps;
import com.google.common.base.Charsets;
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
import java.util.HashMap;

public class WhoisIpLookup {

    protected static final Logger LOG = LoggerFactory.getLogger(WhoisIpLookup.class);

    private static final int PORT = 43;

    /*
     * In the future we'll get rid of this and make the initial registry configurable.
     * European Graylog deployments will want to query RIPE NCC first.
     */
    public WhoisIpLookupResult run(String ip) throws Exception {
        return run(InternetRegistry.ARIN, ip);
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

        Socket socket = null;
        try {
            socket = new Socket(registry.getWhoisServer(), PORT);
            OutputStream out = socket.getOutputStream();
            InputStream in = socket.getInputStream();

            out.write((ip + "\n").getBytes());

            IOUtils.readLines(in, Charsets.UTF_8).forEach(parser::readLine);

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

            // Build result.
            HashMap<String, Object> result = Maps.newHashMap();
            result.put("whois_organization", parser.getOrganization());
            result.put("whois_country_code", parser.getCountryCode());

            return new WhoisIpLookupResult(result);
        } catch (IOException e) {
            LOG.error("Could not lookup WHOIS information for [{}] at [{}].", ip, registry.toString());
            throw e;
        } finally {
            if (socket != null) {
                try {
                    socket.close();
                } catch (IOException e) {
                    LOG.warn("Could not close WHOIS socket.");
                }
            }
        }
    }

}
