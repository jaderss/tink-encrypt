package dev.jaderss.encrypt.request;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Pattern;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class RequestIdFilter extends OncePerRequestFilter {

    public static final String HEADER = "X-Request-Id";

    private static final Pattern VALID_REQUEST_ID = Pattern.compile("[A-Za-z0-9._-]{1,64}");

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String requestId = Optional.ofNullable(request.getHeader(HEADER))
                .filter(VALID_REQUEST_ID.asMatchPredicate())
                .orElseGet(() -> UUID.randomUUID().toString());
        response.setHeader(HEADER, requestId);
        try {
            ScopedValue.where(RequestContext.CURRENT, new RequestContext(requestId))
                    .call(() -> {
                        chain.doFilter(request, response);
                        return null;
                    });
        } catch (IOException | ServletException | RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new ServletException(e);
        }
    }
}
