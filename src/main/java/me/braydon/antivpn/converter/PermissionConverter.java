package me.braydon.antivpn.converter;

import lombok.NonNull;
import me.braydon.antivpn.model.APIKey;
import org.springframework.core.convert.converter.Converter;
import org.springframework.data.convert.ReadingConverter;
import org.springframework.data.convert.WritingConverter;

/**
 * @author Braydon
 */
public final class PermissionConverter {
    @WritingConverter
    public static class Writer implements Converter<APIKey.Permission, String> {
        @Override
        public String convert(@NonNull APIKey.Permission source) {
            return source.name();
        }
    }
    
    @ReadingConverter
    public static class Reader implements Converter<String, APIKey.Permission> {
        @Override
        public APIKey.Permission convert(@NonNull String source) {
            try {
                return APIKey.Permission.valueOf(source);
            } catch (IllegalArgumentException ignored) {}
            return null;
        }
    }
}
