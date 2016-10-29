# Threat Intelligence Plugin for Graylog

[![Build Status](https://travis-ci.org/Graylog2/graylog-plugin-threatintel.svg?branch=master)](https://travis-ci.org/Graylog2/graylog-plugin-threatintel)

**Required Graylog version:** 2.1.0 and later

This plugin adds [Processing Pipeline](http://docs.graylog.org/en/latest/pages/pipelines.html) functions to enrich log messages with threat intelligence data. 

It currently supports the following data feeds:

* [AlienVault Open Threat Exchange (OTX)](https://otx.alienvault.com/) (One API call per lookup but cached)
  * IP addresses
  * Hostnames
* Tor exit nodes
  * IP addresses
* [Spamhaus DROP/EDROP lists](https://www.spamhaus.org/drop/)
  * IP addresses

[Processing Pipeline Rule](http://docs.graylog.org/en/latest/pages/pipelines/rules.html):

```
let intel = otx_lookup_ip(to_string($message.src_addr));

set_field("threat_indicated", intel.otx_threat_indicated);
set_field("threat_ids", intel.otx_threat_ids);
set_field("threat_names", intel.otx_threat_names);
```

![](https://github.com/Graylog2/graylog-plugin-threatintel/blob/master/threatintel_example.jpg)

Please read the usage instructions below for more information.

Installation
------------

[Download the plugin](https://github.com/Graylog2/graylog-plugin-threatintel/releases)
and place the `.jar` file in your Graylog plugin directory. The plugin directory
is the `plugins/` folder relative from your `graylog-server` directory by default
and can be configured in your `graylog.conf` file.

Restart `graylog-server` and you are done.

Usage
-----

__Use this paragraph to document the usage of your plugin__

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
