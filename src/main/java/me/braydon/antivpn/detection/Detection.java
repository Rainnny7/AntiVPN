package me.braydon.antivpn.detection;

import lombok.NonNull;

/**
 * A single signal that matched an IP address.
 *
 * @param source     the id of the source that matched
 * @param name       the display name of the source
 * @param category   what the match says about the address
 * @param confidence how certain the match is
 * @param range      the matched CIDR block, or ASN (e.g. "AS14061")
 * @author Braydon
 */
public record Detection(@NonNull String source, @NonNull String name, @NonNull Category category,
                        @NonNull Confidence confidence, @NonNull String range) {}
