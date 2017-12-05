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

import com.liquidfortress.packetanalyzer.ip.IpPacketProcessor;
import com.liquidfortress.packetanalyzer.main.Main;
import com.liquidfortress.packetanalyzer.statistics.UdpSources;
import com.liquidfortress.packetanalyzer.statistics.UniqueIpAddresses;
import com.liquidfortress.packetanalyzer.tcp.TcpConnections;
import org.apache.logging.log4j.core.Logger;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.DataLinkType;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.util.MacAddress;

import java.io.File;
import java.util.List;

public class PcapFileProcessor {
    private static Logger log = Main.log;

    private static long nonIpPacketCount = 0;

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
                IpPacketProcessor.processIpv4Packet(payload);
            } else if (etherType == EtherType.IPV6) {
                IpPacketProcessor.processIpv6Packet(payload);
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
            log.info("TCP Handshakes: " + TcpConnections.size());
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
