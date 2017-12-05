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

package com.liquidfortress.packetanalyzer.tcp;

import com.liquidfortress.packetanalyzer.main.Main;
import org.apache.logging.log4j.core.Logger;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.namednumber.TcpPort;

/**
 * TcpPacketProcessor
 * <p/>
 * Processes TCP packets
 */
public class TcpPacketProcessor {
    private static Logger log = Main.log;

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
            // Track TCP connection state
            IpAddressPair addressPair = new IpAddressPair(tcpSource, tcpDestination);
            TcpConnectionTracker tcpConnectionTracker = TcpConnections.get(addressPair);
            if (tcpConnectionTracker == null) {
                tcpConnectionTracker = new TcpConnectionTracker(tcpSource, tcpDestination);
                if (syn) { // step 1
                    tcpConnectionTracker.setStep1ClientSequenceNumber(sequenceNumber);
                    TcpConnections.put(addressPair, tcpConnectionTracker);
                }
            } else if (!tcpConnectionTracker.isConnected()) {
                if (syn && ack) { // step 2
                    tcpConnectionTracker.setStep2Numbers(acknowledgementNumber, sequenceNumber);
                } else if (ack) { // step 3
                    tcpConnectionTracker.setStep3Numbers(acknowledgementNumber, sequenceNumber);
                }
            }

        } catch (IllegalRawDataException e) {
            log.error("Exception occurred while processing a packet. Exception was: " + e);
            System.exit(-2);
        }
    }
}
