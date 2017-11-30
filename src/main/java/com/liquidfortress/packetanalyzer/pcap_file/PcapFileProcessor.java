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

import com.liquidfortress.packetanalyzer.Main;
import com.liquidfortress.packetanalyzer.util.Inet4AddressComparator;
import org.apache.logging.log4j.core.Logger;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.DataLinkType;

import java.io.File;
import java.net.Inet4Address;
import java.util.List;
import java.util.concurrent.ConcurrentSkipListSet;

public class PcapFileProcessor {
    private static Logger log = Main.log;


    private static ConcurrentSkipListSet<Inet4Address> uniqueIpv4Addresses =
            new ConcurrentSkipListSet<>(new Inet4AddressComparator());

    public static PacketSummary processPacket(Packet packet) {
        PacketSummary packetSummary = new PacketSummary();
        try {
            log.info("Converting to ethernet packet");
            EthernetPacket ethernetPacket = EthernetPacket.newPacket(packet.getRawData(), 0, packet.length());
            EthernetPacket.EthernetHeader ethernetHeader = ethernetPacket.getHeader();
            int ethernetHeaderLength = ethernetHeader.length();
            log.info("Getting ethernet payload");
            Packet ethPayloadPacket = ethernetPacket.getPayload();
            log.info("Converting to IPv4 packet");
            IpV4Packet ipV4Packet = IpV4Packet.newPacket(ethPayloadPacket.getRawData(), 0, ethPayloadPacket.length());
            IpV4Packet.IpV4Header ipV4Header = ipV4Packet.getHeader();
            log.info("Getting IPv4 addresses");
            Inet4Address sourceAddress = ipV4Header.getSrcAddr();
            Inet4Address destAddress = ipV4Header.getDstAddr();
            log.info("Adding IPv4 addresses to set");
            uniqueIpv4Addresses.add(sourceAddress);
            uniqueIpv4Addresses.add(destAddress);

        } catch (IllegalRawDataException e) {
            log.error("Exception occurred while processing a packet. Exception was: " + e);
            System.exit(-2);
        }
        return packetSummary;
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
                PacketSummary packetSummary = processPacket(packet);
            }
            log.info("Packet count: " + pcapFileSummary.packetCount);
            log.info("Unique IPv4 addresses: " + uniqueIpv4Addresses.size());
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
