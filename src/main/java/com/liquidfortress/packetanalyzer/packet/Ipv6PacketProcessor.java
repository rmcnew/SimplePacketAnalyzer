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
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.Packet;

import java.net.Inet6Address;

/**
 * Ipv6PacketProcessor
 * <p/>
 * Process IPv6 packets
 */
public class Ipv6PacketProcessor {
    private static Logger log = Main.log;

    public static PacketSummary process(Packet packet) {
        PacketSummary packetSummary = new PacketSummary();
        try {
            log.info("Converting to IPv6 packet");
            IpV6Packet ipV6Packet = IpV6Packet.newPacket(packet.getRawData(), 0, packet.length());
            log.info("Getting IPv6 packet header");
            IpV6Packet.IpV6Header ipV6Header = ipV6Packet.getHeader();
            log.info("Getting IPv6 addresses");
            Inet6Address sourceAddress = ipV6Header.getSrcAddr();
            Inet6Address destAddress = ipV6Header.getDstAddr();
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
