package me.braydon.antivpn;

import lombok.NonNull;
import lombok.experimental.UtilityClass;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * Reads captured upstream responses from {@code src/test/resources/fixtures}.
 */
@UtilityClass
public final class Fixtures {
    @NonNull
    public static String read(@NonNull String name) {
        try (InputStream inputStream = Objects.requireNonNull(Fixtures.class.getResourceAsStream("/fixtures/" + name), name)) {
            return new String(inputStream.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
    }
}
