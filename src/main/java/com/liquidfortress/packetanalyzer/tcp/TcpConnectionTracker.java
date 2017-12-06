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

import java.time.Instant;

/**
 * TcpConnectionTracker
 * <p/>
 * Records the progress of a single TCP connection
 */
public class TcpConnectionTracker {
    public static final int NOT_DEFINED = -1;
    private static Logger log = Main.log;
    private final String clientAddress;
    private final String serverAddress;

    private int step1ClientSequenceNumber = NOT_DEFINED; // chosen by client
    private int step2ServerAckNumber = NOT_DEFINED;      // should be step1ClientSequenceNumber + 1
    private int step2ServerSequenceNumber = NOT_DEFINED; // chosen by server
    private int step3ClientSequenceNumber = NOT_DEFINED; // should be step1ClientSequenceNumber + 1
    private int step3ClientAckNumber = NOT_DEFINED;      // should be step2ServerSequenceNumber + 1
    private int step4CloseRequestSequenceNumber = NOT_DEFINED;
    private int step5CloseRequestAckNumber = NOT_DEFINED;
    private int step6CloseRequestSequenceNumber = NOT_DEFINED;
    private int step7CloseRequestAckNumber = NOT_DEFINED;
    private boolean connected = false;  // only true if the connection has been established and is open
    private boolean closed = false; // only true after the connection has been closed
    private Instant connectionEstablished;
    private Instant connectionClosed;
    private long totalBytesInFlow = 0;

    public TcpConnectionTracker(String clientAddress, String serverAddress) {
        this.clientAddress = clientAddress;
        this.serverAddress = serverAddress;
    }

    // Accessors

    public String getClientAddress() {
        return clientAddress;
    }

    public String getServerAddress() {
        return serverAddress;
    }

    public int getStep1ClientSequenceNumber() {
        return step1ClientSequenceNumber;
    }

    public int getStep2ServerAckNumber() {
        return step2ServerAckNumber;
    }

    public int getStep2ServerSequenceNumber() {
        return step2ServerSequenceNumber;
    }

    public int getStep3ClientSequenceNumber() {
        return step3ClientSequenceNumber;
    }

    public int getStep3ClientAckNumber() {
        return step3ClientAckNumber;
    }

    public int getStep4CloseRequestSequenceNumber() {
        return step4CloseRequestSequenceNumber;
    }

    public void setStep4CloseRequestSequenceNumber(int step4CloseRequestSequenceNumber) {
        if (this.closed) {
            log.trace("This connection was previously closed!");
            return;
        }
        if (!connected) {
            log.trace("TCP connection was never made!");
            return;
        }
        this.step4CloseRequestSequenceNumber = step4CloseRequestSequenceNumber;
    }

    public int getStep5CloseRequestAckNumber() {
        return step5CloseRequestAckNumber;
    }

    public void setStep5CloseRequestAckNumber(int step5CloseRequestAckNumber) {
        if (this.closed) {
            log.trace("This connection was previously closed!");
            return;
        }
        if (!connected) {
            log.trace("TCP connection was never made!");
            return;
        }
        if (this.step4CloseRequestSequenceNumber == NOT_DEFINED) {
            log.trace("step4CloseRequestSequenceNumber was not set!");
            return;
        }
        this.step5CloseRequestAckNumber = step5CloseRequestAckNumber;
    }

    public int getStep6CloseRequestSequenceNumber() {
        return step6CloseRequestSequenceNumber;
    }

    public void setStep6CloseRequestSequenceNumber(int step6CloseRequestSequenceNumber) {
        if (this.closed) {
            log.trace("This connection was previously closed!");
            return;
        }
        if (!connected) {
            log.trace("TCP connection was never made!");
            return;
        }
        if (this.step4CloseRequestSequenceNumber == NOT_DEFINED) {
            log.trace("step4CloseRequestSequenceNumber was not set!");
            return;
        }
        if (this.step5CloseRequestAckNumber == NOT_DEFINED) {
            log.trace("step5CloseRequestAckNumber was not set!");
            return;
        }
        this.step6CloseRequestSequenceNumber = step6CloseRequestSequenceNumber;
    }

    public int getStep7CloseRequestAckNumber() {
        return step7CloseRequestAckNumber;
    }

    public void setStep7CloseRequestAckNumber(int step7CloseRequestAckNumber) {
        if (this.closed) {
            log.trace("This connection was previously closed!");
            return;
        }
        if (!connected) {
            log.trace("TCP connection was never made!");
            return;
        }
        if (this.step4CloseRequestSequenceNumber == NOT_DEFINED) {
            log.trace("step4CloseRequestSequenceNumber was not set!");
            return;
        }
        if (this.step5CloseRequestAckNumber == NOT_DEFINED) {
            log.trace("step5CloseRequestAckNumber was not set!");
            return;
        }
        if (this.step6CloseRequestSequenceNumber == NOT_DEFINED) {
            log.trace("step6CloseRequestSequenceNumber was not set!");
            return;
        }
        this.step7CloseRequestAckNumber = step7CloseRequestAckNumber;
        this.connectionClosed = Instant.now();
        this.connected = false;
        this.closed = true;
    }

    public boolean isConnected() {
        return connected;
    }

    // Mutators

    public boolean isClosed() {
        return closed;
    }

    public Instant getConnectionEstablished() {
        return connectionEstablished;
    }

    public Instant getConnectionClosed() {
        return connectionClosed;
    }

    public long getTotalBytesInFlow() {
        return totalBytesInFlow;
    }

    public void setStep1ClientSequenceNumber(int step1ClientSequenceNumber) {
        if (this.closed) {
            log.trace("This connection was previously closed!");
            return;
        }
        if (this.connected) {
            log.trace("This connection was previously made!");
            return;
        }
        this.step1ClientSequenceNumber = step1ClientSequenceNumber;
    }

    public void setStep2Numbers(int step2ServerAckNumber, int step2ServerSequenceNumber) {
        if (this.closed) {
            log.trace("This connection was previously closed!");
            return;
        }
        if (this.connected) {
            log.trace("This connection was previously made!");
            return;
        }
        if (step1ClientSequenceNumber == NOT_DEFINED) {
            log.trace("Step 1 Client Sequence Number not yet set!");
            return;
        }
        if (step2ServerAckNumber != (step1ClientSequenceNumber + 1)) {
            log.trace("Step 2 Server Ack Number should be Step 1 Client Sequence Number + 1!" +
                    "step1ClientSequenceNumber is: " + step1ClientSequenceNumber +
                    "step2ServerAckNumber argument is: " + step2ServerAckNumber);
            return;
        }
        this.step2ServerAckNumber = step2ServerAckNumber;
        this.step2ServerSequenceNumber = step2ServerSequenceNumber;
    }

    public void setStep3Numbers(int step3ClientAckNumber, int step3ClientSequenceNumber) {
        if (this.closed) {
            log.trace("This connection was previously closed!");
            return;
        }
        if (this.connected) {
            log.trace("This connection was previously made!");
            return;
        }
        if (step1ClientSequenceNumber == NOT_DEFINED) {
            log.trace("Step 1 Client Sequence Number not yet set!");
            return;
        }
        if (step2ServerAckNumber == NOT_DEFINED) {
            log.trace("Step 2 Server Ack Number not yet set!");
            return;
        }
        if (step2ServerSequenceNumber == NOT_DEFINED) {
            log.trace("Step 2 Server Sequence Number not yet set!");
            return;
        }
        if (step3ClientAckNumber != (step2ServerSequenceNumber + 1)) {
            log.trace("Step 3 Client Ack Number should be Step 2 Server Sequence Number + 1!" +
                    "step2ServerSequenceNumber is: " + step2ServerSequenceNumber +
                    "step3ClientAckNumber argument is: " + step3ClientAckNumber);
            return;
        }
        if (step3ClientSequenceNumber != (step1ClientSequenceNumber + 1)) {
            log.trace("Step 3 Client Sequence Number should be Step 1 Client Sequence Number + 1!" +
                    "step1ClientSequenceNumber is: " + step1ClientSequenceNumber +
                    "step3ClientSequenceNumber argument is: " + step3ClientSequenceNumber);
            return;
        }
        this.step3ClientAckNumber = step3ClientAckNumber;
        this.step3ClientSequenceNumber = step3ClientSequenceNumber;
        this.connected = true;
        this.connectionEstablished = Instant.now();
    }

    public void addFlowBytes(long additionalBytes) {
        if (additionalBytes < 0) {
            log.trace("additionalBytes must be non-negative!");
            return;
        }
        this.totalBytesInFlow += additionalBytes;
    }
}
