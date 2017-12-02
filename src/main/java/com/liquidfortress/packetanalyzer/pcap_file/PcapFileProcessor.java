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
import com.liquidfortress.packetanalyzer.main.UniqueIpAddresses;
import com.liquidfortress.packetanalyzer.packet.*;
import org.apache.logging.log4j.core.Logger;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.DataLinkType;
import org.pcap4j.util.Packets;

import java.io.File;
import java.util.Iterator;
import java.util.List;

public class PcapFileProcessor {
    private static Logger log = Main.log;

    public static void processPacketSummary(PacketSummary packetSummary) {

    }

    public static void processPacket(Packet packet) {
        if (packet == null) {
            throw new IllegalArgumentException("Cannot process null packet!");
        }
        Iterator<Packet> packetIterator = packet.iterator();
        Packet currentPacket = packet;
        do {
            PacketSummary packetSummary;
            if (Packets.containsEthernetPacket(currentPacket)) {
                packetSummary = EthernetPacketProcessor.process(currentPacket);
            } else if (Packets.containsIpV4Packet(currentPacket)) {
                packetSummary = Ipv4PacketProcessor.process(currentPacket);
            } else if (Packets.containsIpV6Packet(currentPacket)) {
                packetSummary = Ipv6PacketProcessor.process(currentPacket);
            } else if (Packets.containsTcpPacket(currentPacket)) {
                packetSummary = TcpPacketProcessor.process(currentPacket);
            } else if (Packets.containsUdpPacket(currentPacket)) {
                packetSummary = UdpPacketProcessor.process(currentPacket);
            } else {
                throw new IllegalArgumentException("No processor to handle packet type: " + packet.getHeader());
            }
            processPacketSummary(packetSummary);
        } while (packetIterator.hasNext());       
    }

    public static PcapFileSummary processPcapFile(File pcapFile) {
        PcapFileSummary pcapFileSummary = new PcapFileSummary();
        try {
            log.info("Opening pcap file: " + pcapFile.getAbsolutePath());
            PcapHandle pcapHandle = Pcaps.openOffline(pcapFile.getAbsolutePath());
            DataLinkType dataLinkType = pcapHandle.getDlt();
            log.info("DataLinkType is: " + dataLinkType);

            Packet packet;
            for (packet = pcapHandle.getNextPacket(); packet != null; packet = pcapHandle.getNextPacket()) {
                pcapFileSummary.packetCount++;
                //processPacket(packet);
            }
            log.info("Packet count: " + pcapFileSummary.packetCount);
            log.info("Unique IP addresses: " + UniqueIpAddresses.size());
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
