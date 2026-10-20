package dev.jaderss.encrypt.controller;

import dev.jaderss.encrypt.request.RequestContext;
import dev.jaderss.encrypt.service.CiphertextRejectedException;
import java.security.GeneralSecurityException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

@RestControllerAdvice
public class ApiExceptionHandler extends ResponseEntityExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(ApiExceptionHandler.class);

    @ExceptionHandler(CiphertextRejectedException.class)
    ProblemDetail ciphertextRejected(CiphertextRejectedException e) {
        log.warn("Ciphertext rejected, requestId={}", RequestContext.currentRequestId());
        return problem(
                HttpStatus.UNPROCESSABLE_CONTENT,
                "Ciphertext rejected",
                "The ciphertext is malformed, was encrypted under another context, or uses a key this service no"
                        + " longer holds.");
    }

    @ExceptionHandler(GeneralSecurityException.class)
    ProblemDetail encryptionFailed(GeneralSecurityException e) {
        log.error("Encryption failed, requestId={}", RequestContext.currentRequestId(), e);
        return problem(HttpStatus.INTERNAL_SERVER_ERROR, "Encryption failed", "The service could not encrypt.");
    }

    @ExceptionHandler(Exception.class)
    ProblemDetail unexpectedFailure(Exception e) {
        log.error("Unexpected failure, requestId={}", RequestContext.currentRequestId(), e);
        return problem(HttpStatus.INTERNAL_SERVER_ERROR, "Internal error", "The request could not be completed.");
    }

    @Override
    protected ResponseEntity<Object> handleExceptionInternal(
            Exception ex, Object body, HttpHeaders headers, HttpStatusCode statusCode, WebRequest request) {
        if (body instanceof ProblemDetail problem) {
            withRequestId(problem);
        }
        return super.handleExceptionInternal(ex, body, headers, statusCode, request);
    }

    private static ProblemDetail problem(HttpStatus status, String title, String detail) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(status, detail);
        problem.setTitle(title);
        return withRequestId(problem);
    }

    private static ProblemDetail withRequestId(ProblemDetail problem) {
        String requestId = RequestContext.currentRequestId();
        if (requestId != null) {
            problem.setProperty("requestId", requestId);
        }
        return problem;
    }
}
