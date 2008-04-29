package com.entrouvert.lasso;

public class LassoException extends RuntimeException {
    public int errorCode;
    private static boolean throws_for_recoverable_errors = false;
    /** If set to true, enables throwing of exception for
     * recoverable errors, i.e. errors with a positive error
     * code.
     *
     * @param bool true if exception are throwed on recoverable errors.
     */
    public static void setThrowsForRecoverableErrors(boolean bool) {
        throws_for_recoverable_errors = bool;
    }
    public static boolean getThrowsForRecoverableErrors() {
        return throws_for_recoverable_errors;
    }

    protected LassoException(int errorCode) {
        super(LassoJNI.strError(errorCode));
        errorCode = errorCode;
    }
    protected LassoException(int errorCode, String message) {
        super(message);
        errorCode = errorCode;
    }
    private static final Class[] paramst = { Integer.class };
    protected static int throwError(int errorCode) throws LassoException {
            if (errorCode == 0 || (! throws_for_recoverable_errors && errorCode > 0))
                return errorCode;

