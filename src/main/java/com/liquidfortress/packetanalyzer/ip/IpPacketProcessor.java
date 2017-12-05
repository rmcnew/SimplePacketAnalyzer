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

package com.liquidfortress.packetanalyzer.ip;

import com.liquidfortress.packetanalyzer.icmp.IcmpPacketProcessor;
import com.liquidfortress.packetanalyzer.main.Main;
import com.liquidfortress.packetanalyzer.statistics.UniqueIpAddresses;
import com.liquidfortress.packetanalyzer.tcp.TcpPacketProcessor;
import com.liquidfortress.packetanalyzer.udp.UdpPacketProcessor;
import org.apache.logging.log4j.core.Logger;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.IpNumber;

import java.net.Inet4Address;
import java.net.Inet6Address;

/**
 * IpPacketProcessor
 * <p/>
 * Processes IP packets
 */
public class IpPacketProcessor {
    private static Logger log = Main.log;


    public static void processIpv4Packet(Packet packet) {
        if (packet == null) {
            return; // skip empty packets
        }
        try {
            log.info("Converting to IPv4 packet");
            IpV4Packet ipV4Packet = IpV4Packet.newPacket(packet.getRawData(), 0, packet.length());
            IpV4Packet.IpV4Header ipV4Header = ipV4Packet.getHeader();
            Inet4Address sourceAddress = ipV4Header.getSrcAddr();
            Inet4Address destAddress = ipV4Header.getDstAddr();
            log.info("Adding IPv4 addresses to set:  source: " + sourceAddress.getHostAddress() + ", dest: " + destAddress.getHostAddress());
            UniqueIpAddresses.add(sourceAddress.getHostAddress());
            UniqueIpAddresses.add(destAddress.getHostAddress());
            IpNumber ipNumber = ipV4Header.getProtocol();
            Packet payload = ipV4Packet.getPayload();
            if (ipNumber == IpNumber.ICMPV4) {
                IcmpPacketProcessor.processIcmpv4Packet(payload, sourceAddress.getHostAddress(), destAddress.getHostAddress());
            } else if (ipNumber == IpNumber.ICMPV6) {
                IcmpPacketProcessor.processIcmpv6Packet(payload, sourceAddress.getHostAddress(), destAddress.getHostAddress());
            } else if (ipNumber == IpNumber.TCP) {
                TcpPacketProcessor.processTcpPacket(payload, sourceAddress.getHostAddress(), destAddress.getHostAddress());
            } else if (ipNumber == IpNumber.UDP) {
                UdpPacketProcessor.processUdpPacket(payload, sourceAddress.getHostAddress(), destAddress.getHostAddress());
            } else {
                log.warn("Skipping packet: " + payload);
            }
        } catch (IllegalRawDataException e) {
            log.error("Exception occurred while processing a packet. Exception was: " + e);
            System.exit(-2);
        }
    }

    public static void processIpv6Packet(Packet packet) {
        if (packet == null) {
            return; // skip empty packets
        }
        try {
            log.info("Converting to IPv6 packet");
            IpV6Packet ipV6Packet = IpV6Packet.newPacket(packet.getRawData(), 0, packet.length());
            IpV6Packet.IpV6Header ipV6Header = ipV6Packet.getHeader();
            Inet6Address sourceAddress = ipV6Header.getSrcAddr();
            Inet6Address destAddress = ipV6Header.getDstAddr();
            log.info("Adding IPv6 addresses to set:  source: " + sourceAddress.getHostAddress() + ", dest: " + destAddress.getHostAddress());
            UniqueIpAddresses.add(sourceAddress.getHostAddress());
            UniqueIpAddresses.add(destAddress.getHostAddress());
            IpNumber ipNumber = ipV6Header.getProtocol();
            Packet payload = ipV6Packet.getPayload();
            if (ipNumber == IpNumber.ICMPV4) {
                IcmpPacketProcessor.processIcmpv4Packet(payload, sourceAddress.getHostAddress(), destAddress.getHostAddress());
            } else if (ipNumber == IpNumber.ICMPV6) {
                IcmpPacketProcessor.processIcmpv6Packet(payload, sourceAddress.getHostAddress(), destAddress.getHostAddress());
            } else if (ipNumber == IpNumber.TCP) {
                TcpPacketProcessor.processTcpPacket(payload, sourceAddress.getHostAddress(), destAddress.getHostAddress());
            } else if (ipNumber == IpNumber.UDP) {
                UdpPacketProcessor.processUdpPacket(payload, sourceAddress.getHostAddress(), destAddress.getHostAddress());
            } else {
                log.warn("Skipping packet: " + payload);
            }
        } catch (IllegalRawDataException e) {
            log.error("Exception occurred while processing a packet. Exception was: " + e);
            System.exit(-2);
        }
    }
}
