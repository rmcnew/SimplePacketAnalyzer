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

package com.liquidfortress.packetanalyzer.pcap_file;

import com.liquidfortress.packetanalyzer.main.Main;
import com.liquidfortress.packetanalyzer.main.UdpSources;
import com.liquidfortress.packetanalyzer.main.UniqueIpAddresses;
import org.apache.logging.log4j.core.Logger;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.*;
import org.pcap4j.util.MacAddress;

import java.io.File;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.util.List;

public class PcapFileProcessor {
    private static Logger log = Main.log;

    private static long nonIpPacketCount = 0;

    public static void processPacketSummary(PacketSummary packetSummary) {

    }

    public static void processIcmpv4Packet(Packet packet, String sourceAddress, String destinationAddress) {
        if (packet == null) {
            return; // skip empty packets
        }
        try {
            log.info("Converting to ICMPv4 packet");
            IcmpV4CommonPacket icmpV4CommonPacket = IcmpV4CommonPacket.newPacket(packet.getRawData(), 0, packet.length());
            IcmpV4CommonPacket.IcmpV4CommonHeader icmpV4CommonHeader = icmpV4CommonPacket.getHeader();
            IcmpV4Type icmpV4Type = icmpV4CommonHeader.getType();
            if (icmpV4Type == IcmpV4Type.ECHO) {
                IcmpV4EchoPacket icmpV4EchoPacket = IcmpV4EchoPacket.newPacket(icmpV4CommonPacket.getRawData(), 0, icmpV4CommonPacket.length());
                IcmpV4EchoPacket.IcmpV4EchoHeader icmpV4EchoHeader = icmpV4EchoPacket.getHeader();
                short identifier = icmpV4EchoHeader.getIdentifier();
                short sequenceNumber = icmpV4EchoHeader.getSequenceNumber();
                log.info("ICMPv4_ECHO_REQUEST{ source: " + sourceAddress + ", destination: " + destinationAddress +
                        ", identifier: " + identifier + ", seq number: " + sequenceNumber + " }");
            } else if (icmpV4Type == IcmpV4Type.ECHO_REPLY) {
                IcmpV4EchoReplyPacket icmpV4EchoReplyPacket = IcmpV4EchoReplyPacket.newPacket(icmpV4CommonPacket.getRawData(), 0, icmpV4CommonPacket.length());
                IcmpV4EchoReplyPacket.IcmpV4EchoReplyHeader icmpV4EchoReplyHeader = icmpV4EchoReplyPacket.getHeader();
                short identifier = icmpV4EchoReplyHeader.getIdentifier();
                short sequenceNumber = icmpV4EchoReplyHeader.getSequenceNumber();
                log.info("ICMPv4_ECHO_REPLY{ source: " + sourceAddress + ", destination: " + destinationAddress +
                        ", identifier: " + identifier + ", seq number: " + sequenceNumber + " }");
            } else {
                log.info("Other ICMPv4 packet with type: " + icmpV4Type);
            }
        } catch (IllegalRawDataException e) {
            log.error("Exception occurred while processing a packet. Exception was: " + e);
            System.exit(-2);
        }
    }

    public static void processIcmpv6Packet(Packet packet, String sourceAddress, String destinationAddress) {
        if (packet == null) {
            return; // skip empty packets
        }
        try {
            log.info("Converting to ICMPv6 packet");
            IcmpV6CommonPacket icmpV6CommonPacket = IcmpV6CommonPacket.newPacket(packet.getRawData(), 0, packet.length());
            IcmpV6CommonPacket.IcmpV6CommonHeader icmpV6CommonHeader = icmpV6CommonPacket.getHeader();
            IcmpV6Type icmpV6Type = icmpV6CommonHeader.getType();
            if (icmpV6Type == IcmpV6Type.ECHO_REQUEST) {
                IcmpV6EchoRequestPacket icmpV6EchoRequestPacket = IcmpV6EchoRequestPacket.newPacket(icmpV6CommonPacket.getRawData(), 0, icmpV6CommonPacket.length());
                IcmpV6EchoRequestPacket.IcmpV6EchoRequestHeader icmpV6EchoRequestHeader = icmpV6EchoRequestPacket.getHeader();
                short identifier = icmpV6EchoRequestHeader.getIdentifier();
                short sequenceNumber = icmpV6EchoRequestHeader.getSequenceNumber();
                log.info("ICMPv6_ECHO_REQUEST{ source: " + sourceAddress + ", destination: " + destinationAddress +
                        ", identifier: " + identifier + ", seq number: " + sequenceNumber + " }");
            } else if (icmpV6Type == IcmpV6Type.ECHO_REPLY) {
                IcmpV6EchoReplyPacket icmpV6EchoReplyPacket = IcmpV6EchoReplyPacket.newPacket(icmpV6CommonPacket.getRawData(), 0, icmpV6CommonPacket.length());
                IcmpV6EchoReplyPacket.IcmpV6EchoReplyHeader icmpV6EchoReplyHeader = icmpV6EchoReplyPacket.getHeader();
                short identifier = icmpV6EchoReplyHeader.getIdentifier();
                short sequenceNumber = icmpV6EchoReplyHeader.getSequenceNumber();
                log.info("ICMPv6_ECHO_REPLY{ source: " + sourceAddress + ", destination: " + destinationAddress +
                        ", identifier: " + identifier + ", seq number: " + sequenceNumber + " }");
            } else {
                log.info("Other ICMPv6 packet with type: " + icmpV6Type);
            }
        } catch (IllegalRawDataException e) {
            log.error("Exception occurred while processing a packet. Exception was: " + e);
            System.exit(-2);
        }
    }

    public static void processTcpPacket(Packet packet, String sourceAddress, String destinationAddress) {
        if (packet == null) {
            return; // skip empty packets
        }
        try {
            log.info("Converting to TCP packet");
            TcpPacket tcpPacket = TcpPacket.newPacket(packet.getRawData(), 0, packet.length());
            TcpPacket.TcpHeader tcpHeader = tcpPacket.getHeader();
            TcpPort sourcePort = tcpHeader.getSrcPort();
            TcpPort destinationPort = tcpHeader.getDstPort();
            String tcpSource = sourceAddress + ":" + sourcePort;
            String tcpDestination = destinationAddress + ":" + destinationPort;
            boolean syn = tcpHeader.getSyn();
            boolean ack = tcpHeader.getAck();
            boolean fin = tcpHeader.getFin();
            int sequenceNumber = tcpHeader.getSequenceNumber();
            int acknowledgementNumber = tcpHeader.getAcknowledgmentNumber();
            log.info("TCP{ source: " + tcpSource + ", destination: " + tcpDestination +
                    ", SYN: " + syn + ", ACK: " + ack + ", FIN: " + fin +
                    ", seq number: " + sequenceNumber + ", ack number: " + acknowledgementNumber + " }");

        } catch (IllegalRawDataException e) {
            log.error("Exception occurred while processing a packet. Exception was: " + e);
            System.exit(-2);
        }
    }

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
                processIcmpv4Packet(payload, sourceAddress.getHostAddress(), destAddress.getHostAddress());
            } else if (ipNumber == IpNumber.ICMPV6) {
                processIcmpv6Packet(payload, sourceAddress.getHostAddress(), destAddress.getHostAddress());
            } else if (ipNumber == IpNumber.TCP) {
                processTcpPacket(payload, sourceAddress.getHostAddress(), destAddress.getHostAddress());
            } else if (ipNumber == IpNumber.UDP) {
                processUdpPacket(payload, sourceAddress.getHostAddress(), destAddress.getHostAddress());
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
                processIcmpv4Packet(payload, sourceAddress.getHostAddress(), destAddress.getHostAddress());
            } else if (ipNumber == IpNumber.ICMPV6) {
                processIcmpv6Packet(payload, sourceAddress.getHostAddress(), destAddress.getHostAddress());
            } else if (ipNumber == IpNumber.TCP) {
                processTcpPacket(payload, sourceAddress.getHostAddress(), destAddress.getHostAddress());
            } else if (ipNumber == IpNumber.UDP) {
                processUdpPacket(payload, sourceAddress.getHostAddress(), destAddress.getHostAddress());
            } else {
                log.warn("Skipping packet: " + payload);
            }
        } catch (IllegalRawDataException e) {
            log.error("Exception occurred while processing a packet. Exception was: " + e);
            System.exit(-2);
        }
    }

    public static void processEthernetPacket(Packet packet) {
        if (packet == null) {
            return; // skip empty packets
        }
        try {
            log.info("Converting to ethernet packet");
            EthernetPacket ethernetPacket = EthernetPacket.newPacket(packet.getRawData(), 0, packet.length());
            EthernetPacket.EthernetHeader ethernetHeader = ethernetPacket.getHeader();
            MacAddress sourceMac = ethernetHeader.getSrcAddr();
            log.info("Source MAC: " + sourceMac);
            MacAddress destMac = ethernetHeader.getDstAddr();
            log.info("Destination MAC: " + destMac);
            EtherType etherType = ethernetHeader.getType();
            log.info("EtherType: " + etherType.toString());
            Packet payload = ethernetPacket.getPayload();
            if (etherType == EtherType.IPV4) {
                processIpv4Packet(payload);
            } else if (etherType == EtherType.IPV6) {
                processIpv6Packet(payload);
            } else {
                nonIpPacketCount++;
                log.warn("Skipping packet with EtherType: " + etherType);
            }
        } catch (IllegalRawDataException e) {
            log.error("Exception occurred while processing a packet. Exception was: " + e);
            System.exit(-2);
        }
    }

    public static PcapFileSummary processPcapFile(File pcapFile) {
        PcapFileSummary pcapFileSummary = new PcapFileSummary();
        try {
            log.info("Opening pcap file: " + pcapFile.getAbsolutePath());
            PcapHandle pcapHandle = Pcaps.openOffline(pcapFile.getAbsolutePath());
            DataLinkType dataLinkType = pcapHandle.getDlt();
            log.info("DataLinkType is: " + dataLinkType);
            if (dataLinkType == DataLinkType.EN10MB) { // Ethernet
                Packet packet;
                for (packet = pcapHandle.getNextPacket(); packet != null; packet = pcapHandle.getNextPacket()) {
                    pcapFileSummary.packetCount++;
                    log.info("======= Processing packet " + pcapFileSummary.packetCount + " =======");
                    processEthernetPacket(packet);
                }
            }
            log.info("Unique IP addresses: " + UniqueIpAddresses.size());
            log.info("TCP Handshakes: ");
            log.info("UDP Sources: " + UdpSources.size());
            log.info("Non-IP Packet count: " + nonIpPacketCount);
            log.info("Total Packet count: " + pcapFileSummary.packetCount);
        } catch (PcapNativeException | NotOpenException e) {
            log.error("Exception occurred while processing pcapFile: " + pcapFile + ".  Exception was: " + e);
        }
        return pcapFileSummary;
    }

    public static void processPcapFiles(List<File> pcapFiles) {
        for (File pcapFile : pcapFiles) {
            processPcapFile(pcapFile);
        }
    }
}
