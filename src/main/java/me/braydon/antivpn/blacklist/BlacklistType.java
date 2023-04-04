package me.braydon.antivpn.blacklist;

/**
 * The type of blacklists.
 *
 * @author Braydon
 */
public enum BlacklistType {
    /**
     * A blacklist for ASN numbers and organizations.
     */
    ASN,
    
    /**
     * A blacklist for countries.
     */
    COUNTRY
}