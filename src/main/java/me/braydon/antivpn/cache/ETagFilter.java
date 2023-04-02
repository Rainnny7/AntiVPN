package me.braydon.antivpn.cache;

import lombok.NonNull;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.WriteListener;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.MessageDigest;

/**
 * @author Braydon
 */
@Component
@Slf4j(topic = "ETags")
public final class ETagFilter extends OncePerRequestFilter {
    @Override @SneakyThrows
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {
        CapturingResponseWrapper capturingResponseWrapper = new CapturingResponseWrapper(response);
        filterChain.doFilter(request, capturingResponseWrapper);
        
        // Do not add etag header for responses with status code different from 200
        if (capturingResponseWrapper.getStatus() == HttpServletResponse.SC_OK) {
            String contentType = capturingResponseWrapper.getContentType();
            if (contentType == null || (!contentType.equals("application/json"))) { // Not the request we're looking for
                return;
            }
            byte[] capturedContent = capturingResponseWrapper.getCapturedContent(); // The bytes of the response content
            
            MessageDigest digest = MessageDigest.getInstance("SHA-1");
            byte[] hash = digest.digest(capturedContent);
            StringBuilder builder = new StringBuilder();
            for (byte contentByte : hash) { // Build the hex string
                builder.append(String.format("%02x", contentByte));
            }
            String hex = builder.toString(); // The hex from the response content
            String etag = "\"" + hex + "\"";
            
            log.info("ETag: {}", etag); // Log the eTag for the response
            response.setHeader("ETag", etag); // Setting the etag in the response
        }
    }
    
    private static class CapturingResponseWrapper extends HttpServletResponseWrapper {
        /**
         * The buffer to capture the response content.
         *
         * @see CapturingOutputStream for the stream that writes to this buffer
         */
        @NonNull private final ByteArrayOutputStream captureBuffer = new ByteArrayOutputStream();
        
        /**
         * The output stream that writes to the {@link #captureBuffer}.
         */
        private ServletOutputStream outputStream;
        
        public CapturingResponseWrapper(@NonNull HttpServletResponse response) {
            super(response);
        }
        
        /**
         * Get the output stream.
         *
         * @return the output stream
         * @throws IOException if an I/O error occurs
         * @see ServletOutputStream for the outpit stream
         */
        @Override
        public ServletOutputStream getOutputStream() throws IOException {
            if (outputStream == null) { // No output stream has been created yet
                outputStream = new CapturingOutputStream(super.getOutputStream());
            }
            return outputStream;
        }
        
        /**
         * Get the captured content as bytes.
         *
         * @return the captured content
         */
        public byte[] getCapturedContent() {
            return captureBuffer.toByteArray();
        }
    }
    
    private static class CapturingOutputStream extends ServletOutputStream {
        private final OutputStream outputStream;
        private final ByteArrayOutputStream captureBuffer;
        
        public CapturingOutputStream(OutputStream outputStream) {
            this.outputStream = outputStream;
            this.captureBuffer = new ByteArrayOutputStream();
        }
        
        @Override
        public void write(int b) throws IOException {
            outputStream.write(b);
            captureBuffer.write(b);
        }
        
        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            outputStream.write(b, off, len);
            captureBuffer.write(b, off, len);
        }
        
        @Override
        public boolean isReady() {
            return true;
        }
        
        @Override
        public void setWriteListener(WriteListener writeListener) {
        
        }
    }
}
