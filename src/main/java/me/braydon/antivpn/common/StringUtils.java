package me.braydon.antivpn.common;

import lombok.NonNull;
import lombok.experimental.UtilityClass;

import java.text.DecimalFormat;

/**
 * @author Braydon
 */
@UtilityClass
public final class StringUtils {
    private static final DecimalFormat DECIMAL_FORMAT = new DecimalFormat("###,###");
    
    /**
     * Format the given number.
     *
     * @param number the number
     * @return the formatted number
     * @see #DECIMAL_FORMAT for the format
     */
    @NonNull
    public static String formatNumber(@NonNull Number number) {
        return DECIMAL_FORMAT.format(number);
    }
}
