package com.entrouvert.lasso;

public class LassoException extends RuntimeException {
    private static final long serialVersionUID = 6170037639785281128L;
    public int errorCode;
    private static boolean throws_for_recoverable_errors = true;
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
        this.errorCode = errorCode;
    }
    protected LassoException(int errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }
    protected static int throwError(int errorCode) throws LassoException {
            if (errorCode == 0 || (! throws_for_recoverable_errors && errorCode > 0))
                return errorCode;

