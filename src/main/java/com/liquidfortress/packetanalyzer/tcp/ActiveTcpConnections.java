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

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * ActiveTcpConnections
 * <p/>
 * Tracks the state of multiple TCP connections
 */
public class ActiveTcpConnections {

    private static HashMap<IpAddressPair, TcpConnectionTracker> connections = new HashMap<>();

    public static int size() {
        return connections.size();
    }

    public static TcpConnectionTracker get(Object o) {
        return connections.get(o);
    }

    public static TcpConnectionTracker put(IpAddressPair ipAddressPair, TcpConnectionTracker tcpConnectionTracker) {
        return connections.put(ipAddressPair, tcpConnectionTracker);
    }

    public static Set<IpAddressPair> keySet() {
        return connections.keySet();
    }

    public static Set<Map.Entry<IpAddressPair, TcpConnectionTracker>> entrySet() {
        return connections.entrySet();
    }

    public static TcpConnectionTracker remove(Object o) {
        return connections.remove(o);
    }
}
