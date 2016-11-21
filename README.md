# Threat Intelligence Plugin for Graylog

[![Build Status](https://travis-ci.org/Graylog2/graylog-plugin-threatintel.svg?branch=master)](https://travis-ci.org/Graylog2/graylog-plugin-threatintel)

**Required Graylog version:** 2.1.0 and later

This plugin adds [Processing Pipeline](http://docs.graylog.org/en/latest/pages/pipelines.html) functions to enrich log messages with threat intelligence data.

It currently supports the following data feeds:

* [AlienVault Open Threat Exchange (OTX)](https://otx.alienvault.com/) (One API call per lookup but cached)
  * IP addresses
  * Hostnames
* Tor exit nodes (You'll need at least Java 8 (u101) to make this work. More information below.)
  * IP addresses
* [Spamhaus DROP/EDROP lists](https://www.spamhaus.org/drop/)
  * IP addresses
* [Abuse.ch Ransomware Tracker blocklists](https://ransomwaretracker.abuse.ch/blocklist/)
  * IP addresses
  * Hostnames

### Example

```
let src_addr_intel = threat_intel_lookup_ip(to_string($message.src_addr), "src_addr");
set_fields(src_addr_intel);
```

![](https://github.com/Graylog2/graylog-plugin-threatintel/blob/master/threatintel_example.jpg)

Please read the usage instructions below for more information and specific guides.

Installation
------------

[Download the plugin](https://github.com/Graylog2/graylog-plugin-threatintel/releases)
and place the `.jar` file in your Graylog plugin directory. The plugin directory
is the `plugins/` folder relative from your `graylog-server` directory by default
and can be configured in your `graylog.conf` file.

Restart `graylog-server` and you are done.

Usage
-----

Example [Processing Pipeline](http://docs.graylog.org/en/latest/pages/pipelines.html) rules are following:

### Global/combined lookup

This is the recommended way to use this plugin. The `threat_intel_lookup_*` function will run an indicator like
an IP address or domain name against all enabled threat intel sources and return a combined result. (Except OTX lookups)

```
let src_addr_intel = threat_intel_lookup_ip(to_string($message.src_addr), "src_addr");
set_fields(src_addr_intel);

let dns_question_intel = threat_intel_lookup_domain(to_string($message.dns_question), "dns_question");
set_fields(dns_question_intel);
```

This will lead to the fields `src_addr_threat_indicated:true|false` and `dns_question_threat_indicated:true|false`
being added to the processed message. It will also add fields like `testing_threat_indicated_abusech_ransomware:true`
(Abuse.ch Ransomware tracker OSINT) to indicate threat intel sources returned matches.

Add a second pipeline step that adds the field `threat_indicated:true` if either of the above fields was true
to allow easier queries for all messages that indicated any kind of threat:

```
rule "inflate threat intel results"
when
  to_bool($message.src_threat_indicated) || to_bool($message.dst_threat_indicated)
then
  set_field("threat_indicated", true);
end
```

### OTX

```
let intel = otx_lookup_ip(to_string($message.src_addr));
// let intel = otx_lookup_domain(to_string($message.dns_question))

set_field("threat_indicated", intel.otx_threat_indicated);
set_field("threat_ids", intel.otx_threat_ids);
set_field("threat_names", intel.otx_threat_names);
```

### Tor exit nodes

You'll need at least Java 8 (u101) to make this work. The exit node information is hosted on a Tor website that uses Let's Encrypt for SSL and only Java 8 (u101 or newer) supports it.

```
  let intel = tor_lookup(to_string($message.src_addr));
  set_field("src_addr_is_tor_exit_node", intel.exit_node_indicated);
```

### Spamhaus DROP/EDROP

```
  let intel = spamhaus_lookup_ip(to_string($message.src_addr));
  set_field("threat_indicated", intel.threat_indicated);
```

### Abuse.ch Ransomware tracker

```
  let intel = abusech_ransom_lookup_domain(to_string($message.dns_domain));
  // let intel = abusech_ransom_lookup_ip(to_string($message.src_addr));
  set_field("request_domain_is_ransomware", intel.threat_indicated);
```

Note that you can combine these and change field names as you wish.

## Performance considerations

* All lookups will automatically skip processing IPv4 addresses from private networks as defined in RFC 1918. (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
  * Note that this plugin also ships a new function `in_private_net(ip_address) : Boolean` for any manual lookups of the same kind.
* You can vastly improve performance by connecting pipelines that make use of the threat intelligence rules only to streams that contain data you want to run the lookups on.

Development
-----------

You can improve your development experience for the web interface part of your plugin
dramatically by making use of hot reloading. To do this, do the following:

* `git clone https://github.com/Graylog2/graylog2-server.git`
* `cd graylog2-server/graylog2-web-interface`
* `ln -s $YOURPLUGIN plugin/`
* `npm install && npm start`

Getting started
---------------

This project is using Maven 3 and requires Java 8 or higher.

* Clone this repository.
* Run `mvn package` to build a JAR file.
* Optional: Run `mvn jdeb:jdeb` and `mvn rpm:rpm` to create a DEB and RPM package respectively.
* Copy generated JAR file in target directory to your Graylog plugin directory.
* Restart the Graylog.

Plugin Release
--------------

We are using the maven release plugin:

```
$ mvn release:prepare
[...]
$ mvn release:perform
```

This sets the version numbers, creates a tag and pushes to GitHub. Travis CI will build the release artifacts and upload to GitHub automatically.
