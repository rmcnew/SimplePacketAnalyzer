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
import com.liquidfortress.packetanalyzer.main.UniqueIpAddresses;
import com.liquidfortress.packetanalyzer.pcap_file.PacketSummary;
import org.apache.logging.log4j.core.Logger;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;

import java.net.Inet4Address;

/**
 * Ipv4PacketProcessor
 * <p/>
 * Process IPv4 packets
 */
public class Ipv4PacketProcessor {
    private static Logger log = Main.log;

    public static PacketSummary process(Packet packet) {
        PacketSummary packetSummary = new PacketSummary();
        try {
            log.info("Converting to IPv4 packet");
            IpV4Packet ipV4Packet = IpV4Packet.newPacket(packet.getRawData(), 0, packet.length());
            log.info("Getting IPv4 packet header");
            IpV4Packet.IpV4Header ipV4Header = ipV4Packet.getHeader();
            log.info("Getting IPv4 addresses");
            Inet4Address sourceAddress = ipV4Header.getSrcAddr();
            Inet4Address destAddress = ipV4Header.getDstAddr();
            log.info("Adding IPv4 addresses to set");
            UniqueIpAddresses.add(sourceAddress);
            UniqueIpAddresses.add(destAddress);

        } catch (IllegalRawDataException e) {
            log.error("Exception occurred while processing a packet. Exception was: " + e);
            System.exit(-2);
        }
        return packetSummary;
    }
}
