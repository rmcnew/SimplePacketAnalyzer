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

import java.util.LinkedList;

/**
 * AttackSummary
 * <p/>
 * Container class that holds the details of an attack
 */
public class AttackSummary {

    private String attackName;
    private LinkedList<String> sourceIpAndPorts = new LinkedList<>();
    private LinkedList<String> targetIpAndPorts = new LinkedList<>();
    private String startTimestamp;
    private String endTimestamp;
    private LinkedList<String> usernameAndPasswords = new LinkedList<>();

    public AttackSummary() {
    }

    public String getAttackName() {
        return attackName;
    }

    public void setAttackName(String attackName) {
        this.attackName = attackName;
    }

    public LinkedList<String> getSourceIpAndPorts() {
        return sourceIpAndPorts;
    }

    public void setSourceIpAndPorts(LinkedList<String> sourceIpAndPorts) {
        this.sourceIpAndPorts = sourceIpAndPorts;
    }

    public LinkedList<String> getTargetIpAndPorts() {
        return targetIpAndPorts;
    }

    public void setTargetIpAndPorts(LinkedList<String> targetIpAndPorts) {
        this.targetIpAndPorts = targetIpAndPorts;
    }

    public String getStartTimestamp() {
        return startTimestamp;
    }

    public void setStartTimestamp(String startTimestamp) {
        this.startTimestamp = startTimestamp;
    }

    public String getEndTimestamp() {
        return endTimestamp;
    }

    public void setEndTimestamp(String endTimestamp) {
        this.endTimestamp = endTimestamp;
    }

    public LinkedList<String> getUsernameAndPasswords() {
        return usernameAndPasswords;
    }

    public void setUsernameAndPasswords(LinkedList<String> usernameAndPasswords) {
        this.usernameAndPasswords = usernameAndPasswords;
    }

    @Override
    public String toString() {
        return "AttackSummary{" +
                "attackName='" + attackName + '\'' +
                ", sourceIpAndPorts=" + sourceIpAndPorts +
                ", targetIpAndPorts=" + targetIpAndPorts +
                ", startTimestamp=" + startTimestamp +
                ", endTimestamp=" + endTimestamp +
                ", usernameAndPasswords=" + usernameAndPasswords +
                '}';
    }
}
