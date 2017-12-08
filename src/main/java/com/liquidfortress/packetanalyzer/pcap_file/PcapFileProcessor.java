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

import com.liquidfortress.packetanalyzer.arp.ArpPacketProcessor;
import com.liquidfortress.packetanalyzer.cli_args.ValidatedArgs;
import com.liquidfortress.packetanalyzer.ip.IpPacketProcessor;
import com.liquidfortress.packetanalyzer.main.Main;
import com.liquidfortress.packetanalyzer.main.Mode;
import com.liquidfortress.packetanalyzer.tcp.TcpConnectionTracker;
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
import java.sql.Timestamp;

public class PcapFileProcessor {
    private static Logger log = Main.log;


    public static void processEthernetPacket(Packet packet, PcapFileSummary pcapFileSummary, Mode mode) {
        if (packet == null) {
            return; // skip empty packets
        }
        try {
            log.trace("Converting to ethernet packet");
            EthernetPacket ethernetPacket = EthernetPacket.newPacket(packet.getRawData(), 0, packet.length());
            EthernetPacket.EthernetHeader ethernetHeader = ethernetPacket.getHeader();
            MacAddress sourceMac = ethernetHeader.getSrcAddr();
            log.trace("Source MAC: " + sourceMac);
            MacAddress destMac = ethernetHeader.getDstAddr();
            log.trace("Destination MAC: " + destMac);
            EtherType etherType = ethernetHeader.getType();
            log.trace("EtherType: " + etherType.toString());
            Packet payload = ethernetPacket.getPayload();
            if (etherType == EtherType.IPV4) {
                IpPacketProcessor.processIpv4Packet(payload, pcapFileSummary, mode, sourceMac);
            } else if (etherType == EtherType.IPV6) {
                IpPacketProcessor.processIpv6Packet(payload, pcapFileSummary, mode, sourceMac);
            } else if ((mode == Mode.POSSIBLE_ATTACKS_ANALYSIS) && (etherType == EtherType.ARP)) {
                pcapFileSummary.nonIpPacketCount++;
                ArpPacketProcessor.processArpPacket(payload, pcapFileSummary);
            } else {
                pcapFileSummary.nonIpPacketCount++;
                log.trace("Skipping packet with EtherType: " + etherType);
            }
        } catch (IllegalRawDataException e) {
            log.error("Exception occurred while processing a packet. Exception was: " + e);
            System.exit(-2);
        }
    }

    public static PcapFileSummary processPcapFile(File pcapFile, Mode mode) {
        PcapFileSummary pcapFileSummary = new PcapFileSummary(pcapFile.getAbsolutePath());
        try {
            log.trace("Opening pcap file: " + pcapFile.getAbsolutePath());
            PcapHandle pcapHandle = Pcaps.openOffline(pcapFile.getAbsolutePath());
            DataLinkType dataLinkType = pcapHandle.getDlt();
            log.trace("DataLinkType is: " + dataLinkType);
            if (dataLinkType == DataLinkType.EN10MB) { // Ethernet
                Packet packet;
                Timestamp timestamp;
                for (packet = pcapHandle.getNextPacket(); packet != null; packet = pcapHandle.getNextPacket()) {
                    timestamp = pcapHandle.getTimestamp();
                    pcapFileSummary.packetCount++;
                    log.trace("======= Processing packet " + pcapFileSummary.packetCount + " =======");
                    log.trace("Packet capture timestamp: " + timestamp);
                    processEthernetPacket(packet, pcapFileSummary, mode);
                }
                if (mode == Mode.BASIC_ANALYSIS) {
                    printMode1Output(pcapFileSummary);
                } else if (mode == Mode.DETAILED_ANALYSIS) {
                    printMode1Output(pcapFileSummary);
                    printMode2Output(pcapFileSummary);
                } else if (mode == Mode.POSSIBLE_ATTACKS_ANALYSIS) {
                    printMode3Output(pcapFileSummary);
                }
            }
        } catch (PcapNativeException | NotOpenException e) {
            log.error("Exception occurred while processing pcapFile: " + pcapFile + ".  Exception was: " + e);
        }
        return pcapFileSummary;
    }

    public static void processPcapFiles(ValidatedArgs validatedArgs) {
        for (File pcapFile : validatedArgs.inputFiles) {
            processPcapFile(pcapFile, validatedArgs.mode);
        }
    }

    private static void printMode1Output(PcapFileSummary pcapFileSummary) {
        log.info("==== Summary for: " + pcapFileSummary.filename + " ====");
        log.info("Unique IP addresses: " + pcapFileSummary.uniqueIpAddresses.size());
        log.info("TCP Handshakes: " + pcapFileSummary.tcpConnectionCount);
        log.info("UDP Sources: " + pcapFileSummary.udpSources.size());
        log.info("Non-IP Packet count: " + pcapFileSummary.nonIpPacketCount);
        log.info("Total Packet count: " + pcapFileSummary.packetCount);
    }

    private static void printMode2Output(PcapFileSummary pcapFileSummary) {
        log.info("==== Completed TCP Connections (open and closed) ====");
        pcapFileSummary.closedTcpConnections.forEach((TcpConnectionTracker tracker) -> {
            log.info(tracker.toString());
        });
        log.info("==== Opened TCP Connections (opened but not closed) ====");
        pcapFileSummary.activeTcpConnections.values().forEach((TcpConnectionTracker tracker) -> {
            log.info(tracker.toString());
        });
        log.info(pcapFileSummary.ipProtocolCounter.toString());
    }

    private static void printMode3Output(PcapFileSummary pcapFileSummary) {
        log.info("==== Attack Summary for: " + pcapFileSummary.filename + " ====");
        pcapFileSummary.attackSummaries.forEach((AttackSummary attackSummary) -> {
            log.info(attackSummary.toString());
        });
    }
}
