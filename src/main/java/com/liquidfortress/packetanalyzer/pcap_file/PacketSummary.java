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

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * PacketSummary
 * <p/>
 * Results from analyzing one packet
 * PacketSummary is a wrapped HashSet with defined keys for setting and accessing
 * data found during packet analysis.
 */
public class PacketSummary {

    private HashMap<String, String> hashMap = new HashMap<>();

    // delegate methods for the hashMap
    public String get(Object o) {
        return hashMap.get(o);
    }

    public String put(String s, String s2) {
        return hashMap.put(s, s2);
    }

    public boolean containsValue(Object o) {
        return hashMap.containsValue(o);
    }

    public Set<String> keySet() {
        return hashMap.keySet();
    }

    public Collection<String> values() {
        return hashMap.values();
    }

    public Set<Map.Entry<String, String>> entrySet() {
        return hashMap.entrySet();
    }

    public String getOrDefault(Object o, String s) {
        return hashMap.getOrDefault(o, s);
    }

    // Use inner classes as namespaces for the defined keys
    public class Ethernet {
        public static final String SOURCE_MAC = "Source MAC";
        public static final String DESTINATION_MAC = "Destination MAC";
        public static final String ETHERTYPE = "EtherType";
    }
}
