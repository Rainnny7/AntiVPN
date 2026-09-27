package me.braydon.antivpn.detection.source;

import lombok.NonNull;
import me.braydon.antivpn.common.WebRequest;
import me.braydon.antivpn.detection.Category;
import me.braydon.antivpn.detection.Confidence;
import me.braydon.antivpn.detection.DetectionSource;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * A source made of plain-text lists with one entry per line.
 *
 * @author Braydon
 */
public abstract class PlainListSource extends DetectionSource {
    @NonNull private final List<String> urls;
    
    protected PlainListSource(@NonNull String id, @NonNull String name, @NonNull Category category,
                              @NonNull Confidence confidence, @NonNull Duration refreshInterval, @NonNull String... urls) {
        super(id, name, category, confidence, refreshInterval);
        this.urls = List.of(urls);
    }
    
    @Override @NonNull
    public List<String> fetch() throws Exception {
        List<String> entries = new ArrayList<>();
        for (String url : urls) {
            entries.addAll(parse(WebRequest.builder().url(url).build().sendAsString()));
        }
        return entries;
    }
    
    /**
     * Parse a plain-text list.
     * <p>
     * Comments starting with {@code #} or {@code ;} are removed,
     * and only the first token of each line is kept.
     * </p>
     *
     * @param body the list
     * @return the entries
     */
    @NonNull
    public static List<String> parse(@NonNull String body) {
        List<String> entries = new ArrayList<>();
        for (String line : body.split("\\R")) {
            int comment = indexOfComment(line);
            if (comment >= 0) {
                line = line.substring(0, comment);
            }
            line = line.trim();
            if (line.isEmpty()) {
                continue;
            }
            entries.add(line.split("[\\s,]+", 2)[0]);
        }
        return entries;
    }
    
    private static int indexOfComment(@NonNull String line) {
        int hash = line.indexOf('#'), semicolon = line.indexOf(';');
        if (hash < 0) {
            return semicolon;
        }
        return semicolon < 0 ? hash : Math.min(hash, semicolon);
    }
}
