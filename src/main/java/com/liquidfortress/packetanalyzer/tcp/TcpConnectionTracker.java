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

/**
 * TcpConnectionTracker
 * <p/>
 * Records the progress of a single TCP connection
 */
public class TcpConnectionTracker {

    private static final int NOT_DEFINED = -1;
    private final String clientAddress;
    private final String serverAddress;

    private int step1ClientSequenceNumber = NOT_DEFINED; // chosen by client
    private int step2ServerAckNumber = NOT_DEFINED;      // should be step1ClientSequenceNumber + 1
    private int step2ServerSequenceNumber = NOT_DEFINED; // chosen by server
    private int step3ClientSequenceNumber = NOT_DEFINED; // should be step1ClientSequenceNumber + 1
    private int step3ClientAckNumber = NOT_DEFINED;      // should be step2ServerSequenceNumber + 1
    private boolean connected = false;

    public TcpConnectionTracker(String clientAddress, String serverAddress) {
        this.clientAddress = clientAddress;
        this.serverAddress = serverAddress;
    }

    public String getClientAddress() {
        return clientAddress;
    }

    public String getServerAddress() {
        return serverAddress;
    }

    public int getStep1ClientSequenceNumber() {
        return step1ClientSequenceNumber;
    }

    public void setStep1ClientSequenceNumber(int step1ClientSequenceNumber) {
        this.step1ClientSequenceNumber = step1ClientSequenceNumber;
    }

    public int getStep2ServerAckNumber() {
        return step2ServerAckNumber;
    }

    public int getStep2ServerSequenceNumber() {
        return step2ServerSequenceNumber;
    }

    public void setStep2Numbers(int step2ServerAckNumber, int step2ServerSequenceNumber) {
        if (step1ClientSequenceNumber == NOT_DEFINED) {
            throw new IllegalStateException("Step 1 Client Sequence Number not yet set!");
        }
        if (step2ServerAckNumber != (step1ClientSequenceNumber + 1)) {
            throw new IllegalArgumentException("Step 2 Server Ack Number should be Step 1 Client Sequence Number + 1!" +
                    "step1ClientSequenceNumber is: " + step1ClientSequenceNumber +
                    "step2ServerAckNumber argument is: " + step2ServerAckNumber);
        }
        this.step2ServerAckNumber = step2ServerAckNumber;
        this.step2ServerSequenceNumber = step2ServerSequenceNumber;
    }


    public int getStep3ClientSequenceNumber() {
        return step3ClientSequenceNumber;
    }

    public int getStep3ClientAckNumber() {
        return step3ClientAckNumber;
    }

    public void setStep3Numbers(int step3ClientAckNumber, int step3ClientSequenceNumber) {
        if (step1ClientSequenceNumber == NOT_DEFINED) {
            throw new IllegalStateException("Step 1 Client Sequence Number not yet set!");
        }
        if (step2ServerAckNumber == NOT_DEFINED) {
            throw new IllegalStateException("Step 2 Server Ack Number not yet set!");
        }
        if (step2ServerSequenceNumber == NOT_DEFINED) {
            throw new IllegalStateException("Step 2 Server Sequence Number not yet set!");
        }
        if (step3ClientAckNumber != (step2ServerSequenceNumber + 1)) {
            throw new IllegalArgumentException("Step 3 Client Ack Number should be Step 2 Server Sequence Number + 1!" +
                    "step2ServerSequenceNumber is: " + step2ServerSequenceNumber +
                    "step3ClientAckNumber argument is: " + step3ClientAckNumber);
        }
        if (step3ClientSequenceNumber != (step1ClientSequenceNumber + 1)) {
            throw new IllegalArgumentException("Step 3 Client Sequence Number should be Step 1 Client Sequence Number + 1!" +
                    "step1ClientSequenceNumber is: " + step1ClientSequenceNumber +
                    "step3ClientSequenceNumber argument is: " + step3ClientSequenceNumber);
        }
        this.step3ClientAckNumber = step3ClientAckNumber;
        this.step3ClientSequenceNumber = step3ClientSequenceNumber;
        this.connected = true;
    }

    public boolean isConnected() {
        return connected;
    }
}
