/*
 * Copyright (c) 2017.  Richard Scott McNew.
 *
 * This file is part of Liquid Fortress Packet Analyzer.
 *
 * Liquid Fortress Packet Analyzer is free software: you can redistribute
 * it and/or modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * Liquid Fortress Packet Analyzer is distributed in the hope that it will
 * be useful, but WITHOUT ANY WARRANTY; without even the implied
 * warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Liquid Fortress Packet Analyzer.
 * If not, see <http://www.gnu.org/licenses/>.
 */

package com.liquidfortress.packetanalyzer.logging;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.Logger;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.appender.ConsoleAppender;
import org.apache.logging.log4j.core.appender.FileAppender;
import org.apache.logging.log4j.core.config.AppenderRef;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.core.config.LoggerConfig;
import org.apache.logging.log4j.core.layout.PatternLayout;

import java.io.File;


/**
 * LoggerFactory
 * <p/>
 * Get a logger for console and / or file output based on command line args
 */
public class LoggerFactory {

    private static final String CONSOLE_APPENDER = "CONSOLE_APPENDER";
    private static final String FILE_APPENDER = "FILE_APPENDER";
    private static final String LOGGER_NAME = "LFPA_LOGGER";

    /**
     * Get the logger used for output
     *
     * @param outputFile The file to use for output, or null for just console output
     * @return Logger with dynamically-generated configuration
     */
    public static Logger getLogger(File outputFile) {
        // This approach is ugly, but it circumvents the need for multiple log4j
        // configuration files and simplifies writing results to the console and the output file

        // Silence StatusLogger
        System.setProperty("org.apache.logging.log4j.simplelog.StatusLogger.level", "FATAL");
        // Setup context
        LoggerContext loggerContext = (LoggerContext) LogManager.getContext(false);
        Configuration configuration = loggerContext.getConfiguration();
        // Define layout
        PatternLayout patternLayout = PatternLayout.newBuilder()
                .withConfiguration(configuration)
                .withPattern("%d{ISO8601} [%level] [%F:%L] %msg%n")
                .build();
        // Add appenders
        //// Always create console appender
        ConsoleAppender consoleAppender = ConsoleAppender.newBuilder()
                .setConfiguration(configuration)
                .withLayout(patternLayout)
                .withName(CONSOLE_APPENDER)
                .build();
        consoleAppender.start();
        configuration.addAppender(consoleAppender);
        AppenderRef[] appenderRefs;
        AppenderRef consoleAppenderRef = AppenderRef.createAppenderRef(CONSOLE_APPENDER, null, null);
        //// Create file appender if output file specified
        FileAppender fileAppender = null;
        if (outputFile != null) {
            fileAppender = FileAppender.newBuilder()
                    .setConfiguration(configuration)
                    .withLayout(patternLayout)
                    .withName(FILE_APPENDER)
                    .withFileName(outputFile.getAbsolutePath())
                    .build();
            fileAppender.start();
            configuration.addAppender(fileAppender);
            AppenderRef fileAppenderRef = AppenderRef.createAppenderRef(FILE_APPENDER, null, null);
            appenderRefs = new AppenderRef[]{consoleAppenderRef, fileAppenderRef};
        } else {
            appenderRefs = new AppenderRef[]{consoleAppenderRef};
        }
        // Build and update the LoggerConfig
        LoggerConfig loggerConfig = LoggerConfig.createLogger(false, Level.INFO, LOGGER_NAME, "true", appenderRefs, null, configuration, null);
        loggerConfig.addAppender(consoleAppender, null, null);
        if (fileAppender != null) {
            loggerConfig.addAppender(fileAppender, null, null);
        }
        configuration.addLogger(LOGGER_NAME, loggerConfig);
        loggerContext.updateLoggers();
        return (Logger) LogManager.getLogger(LOGGER_NAME);
    }

}
