package ch.admin.bj.swiyu.issuer.oid4vci.common.exception;

public class CredentialException extends RuntimeException {
    public CredentialException(String message) {super(message);}
    public CredentialException(Throwable cause) {super(cause);}
    public CredentialException(String message, Throwable cause) {super(message, cause);}
}
