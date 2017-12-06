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

package com.liquidfortress.packetanalyzer.main;

import com.liquidfortress.packetanalyzer.cli_args.CommandLineValidator;
import com.liquidfortress.packetanalyzer.cli_args.ValidatedArgs;
import com.liquidfortress.packetanalyzer.logging.LoggerFactory;
import com.liquidfortress.packetanalyzer.pcap_file.PcapFileProcessor;
import com.liquidfortress.packetanalyzer.util.SystemErrEater;
import org.apache.logging.log4j.core.Logger;

public class Main {

    public static Logger log;

    public static void main(String[] args) {
        System.setErr(SystemErrEater.getEater());
        ValidatedArgs validatedArgs = CommandLineValidator.validateCommandLineArgs(args);
        log = LoggerFactory.getLogger(validatedArgs);

        log.trace("Starting " + validatedArgs.mode.name() + " . . .");
        switch (validatedArgs.mode) {
            case BASIC_ANALYSIS:
            case DETAILED_ANALYSIS:
                PcapFileProcessor.processPcapFiles(validatedArgs);
                break;

            case POSSIBLE_ATTACKS_ANALYSIS:

                break;
        }
    }

}
