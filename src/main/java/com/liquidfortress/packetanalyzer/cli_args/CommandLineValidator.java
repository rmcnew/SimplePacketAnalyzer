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

package com.liquidfortress.packetanalyzer.cli_args;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.ParseException;

import java.io.File;

/**
 * CommandLineValidator
 * <p/>
 * Get and validate command line arguments
 */
public class CommandLineValidator {

    private static final CommandLineParser commandLineParser = new DefaultParser();

    private static boolean isModeValid(CommandLine commandLine) {
        if (commandLine.hasOption(CommandLineOptions.MODE)) {
            int mode = Integer.valueOf(commandLine.getOptionValue(CommandLineOptions.MODE));
            return ((mode >= 1) && (mode <= 3));
        }
        return false;
    }

    private static boolean areInputFilesValid(CommandLine commandLine) {
        if (commandLine.hasOption(CommandLineOptions.INPUT_FILES)) {
            String[] inputFiles = commandLine.getOptionValues(CommandLineOptions.INPUT_FILES);
            for (String inputFile : inputFiles) {
                // TODO: if no path separator is in the inputFile String, assume current directory as path and append it
                File input = new File(inputFile);
                if ((!input.exists()) || (!input.canRead())) {
                    System.err.println("Input file: " + inputFile + " does not exist or cannot be read!");
                    return false;
                }
            }
            return true;
        }
        return false;
    }

    private static boolean isOutputFileValid(CommandLine commandLine) {
        String outputFile = commandLine.getOptionValue(CommandLineOptions.OUTPUT_FILE);
        // TODO: if no path separator is in the outputFile String, assume current directory as path and append it
        // TODO: make sure the outputFile is not in the input file list
        File output = new File(outputFile);
        return output.canWrite();
    }

    public static CommandLine validate(String[] args) {
        CommandLine commandLine = null;
        try {
            commandLine = commandLineParser.parse(CommandLineOptions.getCommandLineOptions(), args);
            // help
            if (commandLine.hasOption(CommandLineOptions.HELP)) {
                CommandLineOptions.printHelp();
                System.exit(0);
            }
            // mode
            if (!isModeValid(commandLine)) {
                System.err.println("Mode is not valid!  It must be 1, 2, or 3.");
                CommandLineOptions.printHelp();
                System.exit(-1);
            }
            // input files
            if (!areInputFilesValid(commandLine)) {
                CommandLineOptions.printHelp();
                System.exit(-2);
            }
            // output file
            if (commandLine.hasOption(CommandLineOptions.OUTPUT_FILE) && !isOutputFileValid(commandLine)) {
                CommandLineOptions.printHelp();
                System.exit(-3);
            }
        } catch (ParseException e) {
            System.err.println("ParseException: " + e);
        } finally {
            if (commandLine == null) {
                System.err.println("Fatal error parsing command line!  Exiting . . .");
                System.exit(-9);
            }
        }
        return commandLine;
    }
}
