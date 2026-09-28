package me.braydon.antivpn.discord;

import me.braydon.antivpn.model.AddressData;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class DiscordWebhookServiceTest {
    @Test
    void acceptsDiscordWebhookUrls() {
        assertThat(DiscordWebhookService.isValidWebhookUrl("https://discord.com/api/webhooks/123/abc-token")).isTrue();
        assertThat(DiscordWebhookService.isValidWebhookUrl("https://discordapp.com/api/webhooks/123/abc")).isTrue();
        assertThat(DiscordWebhookService.isValidWebhookUrl("https://ptb.discord.com/api/webhooks/1/token")).isTrue();
        assertThat(DiscordWebhookService.isValidWebhookUrl("https://canary.discord.com/api/v10/webhooks/1/token")).isTrue();
    }
    
    @Test
    void rejectsNonDiscordUrls() {
        assertThat(DiscordWebhookService.isValidWebhookUrl("")).isFalse();
        assertThat(DiscordWebhookService.isValidWebhookUrl("https://example.com/api/webhooks/1/token")).isFalse();
        assertThat(DiscordWebhookService.isValidWebhookUrl("http://discord.com/api/webhooks/1/token")).isFalse();
        assertThat(DiscordWebhookService.isValidWebhookUrl("https://discord.com/api/v10/users/@me")).isFalse();
    }
    
    @Test
    void masksTheWebhookToken() {
        assertThat(DiscordWebhookService.mask("https://discord.com/api/webhooks/123/super-secret"))
            .isEqualTo("https://discord.com/api/webhooks/123/***");
    }
    
    @Test
    void isDisabledWhenNoUrlIsConfigured() {
        DiscordProperties properties = new DiscordProperties();
        DiscordWebhookService service = new DiscordWebhookService(properties);
        
        assertThat(service.isEnabled()).isFalse();
        assertThat(service.shouldLog(cleanAddress())).isFalse();
    }
    
    @Test
    void isDisabledWhenTheUrlIsNotAWebhook() {
        DiscordProperties properties = new DiscordProperties();
        properties.setWebhookUrl("https://example.com/not-a-webhook");
        DiscordWebhookService service = new DiscordWebhookService(properties);
        
        assertThat(service.isEnabled()).isFalse();
    }
    
    @Test
    void skipsLookupsBelowMinRisk() {
        DiscordProperties properties = new DiscordProperties();
        properties.setWebhookUrl("https://discord.com/api/webhooks/1/token");
        properties.setMinRisk(0.75F);
        DiscordWebhookService service = new DiscordWebhookService(properties);
        
        try {
            assertThat(service.isEnabled()).isTrue();
            assertThat(service.shouldLog(cleanAddress())).isFalse();
            assertThat(service.shouldLog(vpnAddress())).isTrue();
        } finally {
            service.shutdown();
        }
    }
    
    private static AddressData cleanAddress() {
        return new AddressData("1.128.0.1", 4, 0F, false, false, null, false, false, false, false,
            false, Set.of(), List.of(), null, null);
    }
    
    private static AddressData vpnAddress() {
        return new AddressData("89.35.28.131", 4, 1F, true, true, "NordVPN", false, false, false, false,
            false, Set.of(), List.of(), null, null);
    }
}
