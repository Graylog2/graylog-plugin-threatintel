package org.graylog.plugins.threatintel.adapters.BlockListMineMeld;

import com.google.common.base.MoreObjects;

public enum BlocklistType {
	
	//These URLs need to be changed to your minemeld instance output urls. 
	//To find the url follow these steps:
	
	// 1) Log into minemeld
	// 2) Click on Nodes
	// 3) Find the output you want to configure to utilize with this plugin.
	// 4) Copy the feed base URL.
	
    DOMAINS("https://FEEDBASEURL-FOR-DOMAINS", true),
    URLS("https://FEEDBASEURL-FOR-URLS", true),
	//keep the ?tr=1 on the IP list type in order to output into CIDR per documentation here: 
	//https://live.paloaltonetworks.com/t5/MineMeld-Articles/Parameters-for-the-output-feeds/ta-p/146170
    IPS("https://FEEDBASEURL-FOR-IPS?tr=1", false); 

    private final String url;
    private final boolean caseInsensitive;

    BlocklistType(String url, boolean caseInsensitive) {
        this.url = url;
        this.caseInsensitive = caseInsensitive;
    }

    public String getUrl() {
        return url;
    }

    public boolean isCaseInsensitive() {
        return caseInsensitive;
    }

    @Override
    public String toString() {
        return MoreObjects.toStringHelper(this)
                .add("url", url)
                .add("caseInsensitive", caseInsensitive)
                .toString();
    }

}
