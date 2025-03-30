package ch.admin.bj.swiyu.issuer.oid4vci.common.exception;

/**
 * Exception indicating that an error was made during the configuration phase of the service
 */
public class ConfigurationException extends RuntimeException {

    public ConfigurationException(String message) {
        super(message);
    }
}
