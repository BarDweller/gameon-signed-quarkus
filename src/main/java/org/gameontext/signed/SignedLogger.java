package org.gameontext.signed;

import java.util.logging.Level;
import java.util.logging.Logger;

public class SignedLogger {

    final static Logger logger = Logger.getLogger("org.gameontext.signed");

    final static void writeLog(Level level, Object source, String message, Object... args) {

        //hack hack.. can't enable FINEST for native apps??!!
        if(level.equals(Level.FINEST))level = Level.FINER;

        if (logger.isLoggable(level)) {
            logger.logp(level, source.getClass().getName(), "", message, args);
        }
    }

    final static void writeLog(Level level, Object source, String message, Throwable thrown) {

        //hack hack.. can't enable FINEST for native apps??!!
        if(level.equals(Level.FINEST))level = Level.FINER;

        if (logger.isLoggable(level)) {
            logger.logp(level, source.getClass().getName(), "", message, thrown);
        }
    }    
}
