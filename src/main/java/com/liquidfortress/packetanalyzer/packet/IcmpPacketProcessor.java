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

package com.liquidfortress.packetanalyzer.packet;

import com.liquidfortress.packetanalyzer.main.Main;
import com.liquidfortress.packetanalyzer.pcap_file.PacketSummary;
import org.apache.logging.log4j.core.Logger;
import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.Packet;

/**
 * IcmpPacketProcessor
 * <p/>
 * Processor ICMP packets
 */
public class IcmpPacketProcessor {
    private static Logger log = Main.log;

    public static PacketSummary process(Packet packet) {
        PacketSummary packetSummary = new PacketSummary();
        try {
            log.info("Converting to ICMP packet");
            IcmpV4CommonPacket icmpV4CommonPacket = IcmpV4CommonPacket.newPacket(packet.getRawData(), 0, packet.length());

        } catch (IllegalRawDataException e) {
            log.error("Exception occurred while processing a packet. Exception was: " + e);
            System.exit(-2);
        }
        return packetSummary;
    }
}
