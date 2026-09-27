package me.braydon.antivpn.detection;

/**
 * How certain a detection is.
 *
 * @author Braydon
 */
public enum Confidence {
    /**
     * Published by the operator of the network itself (e.g. a VPN provider's server list).
     */
    CONFIRMED,
    
    /**
     * Inferred by a third party, such as ASN-derived lists.
     */
    LIKELY
}
