package me.braydon.antivpn.discord;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration for Discord webhook logging, bound from {@code discord.*}.
 *
 * @author Braydon
 */
@ConfigurationProperties(prefix = "discord")
@Getter @Setter
public class DiscordProperties {
    /**
     * The Discord webhook URL to post lookup results to.
     * Leave blank to disable.
     */
    private String webhookUrl = "";
    
    /**
     * The username shown on webhook messages.
     */
    private String username = "AntiVPN";
    
    /**
     * Lookups with a risk below this are not sent.
     * {@code 0} logs every lookup.
     */
    private float minRisk = 0F;
}
