package me.braydon.antivpn.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.servlet.config.annotation.PathMatchConfigurer;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurationSupport;

/**
 * @author Braydon
 */
@Configuration
public class WebMvcConfiguration extends WebMvcConfigurationSupport {
    @Override
    protected void configurePathMatch(PathMatchConfigurer configurer) {
        configurer.setUseSuffixPatternMatch(false)
            .setUseTrailingSlashMatch(false)
            .setPathMatcher(new AntPathMatcher() {
                @Override
                public boolean isPattern(String path) {
                    return true;
                }
            });
    }
}