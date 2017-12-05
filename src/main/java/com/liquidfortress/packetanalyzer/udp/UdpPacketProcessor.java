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

package com.liquidfortress.packetanalyzer.udp;

import com.liquidfortress.packetanalyzer.main.Main;
import com.liquidfortress.packetanalyzer.statistics.UdpSources;
import org.apache.logging.log4j.core.Logger;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.namednumber.UdpPort;

/**
 * UdpPacketProcessor
 * <p/>
 * Processes UDP packets
 */
public class UdpPacketProcessor {
    private static Logger log = Main.log;


    public static void processUdpPacket(Packet packet, String sourceAddress, String destinationAddress) {
        if (packet == null) {
            return; // skip empty packets
        }
        try {
            log.info("Converting to UDP packet");
            UdpPacket udpPacket = UdpPacket.newPacket(packet.getRawData(), 0, packet.length());
            UdpPacket.UdpHeader udpHeader = udpPacket.getHeader();
            UdpPort sourcePort = udpHeader.getSrcPort();
            UdpPort destinationPort = udpHeader.getDstPort();
            String udpSource = sourceAddress + ":" + sourcePort.toString();
            String udpDestination = destinationAddress + ":" + destinationPort.toString();
            log.info("Adding UDP source to set: " + udpSource);
            UdpSources.add(udpSource);
            log.info("UDP{ source: " + udpSource + ", destination: " + udpDestination + " }");
        } catch (IllegalRawDataException e) {
            log.error("Exception occurred while processing a packet. Exception was: " + e);
            System.exit(-2);
        }
    }
}
