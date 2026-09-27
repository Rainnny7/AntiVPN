package me.braydon.antivpn.detection;

/**
 * What a detection says about an IP address.
 *
 * @author Braydon
 */
public enum Category {
    /**
     * A commercial VPN server.
     */
    VPN,
    
    /**
     * A Tor exit node.
     */
    TOR,
    
    /**
     * A privacy relay used by ordinary consumers, such as iCloud Private Relay.
     */
    RELAY,
    
    /**
     * A datacenter, cloud or hosting network.
     */
    HOSTING,
    
    /**
     * A network known for abuse, such as a hijacked netblock.
     */
    ABUSE
}
