package me.braydon.antivpn.common;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

/**
 * A simple utility to store two objects.
 *
 * @author Braydon
 */
@AllArgsConstructor @Setter @Getter @ToString
public class Tuple<L, R> {
    private L left;
    private R right;
}
