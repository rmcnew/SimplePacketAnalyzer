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

import java.util.Iterator;
import java.util.LinkedList;
import java.util.function.Consumer;
import java.util.stream.Stream;

/**
 * ClosedTcpConnections
 * <p/>
 * Stores closed TCP Connection data
 */
public class ClosedTcpConnections {

    private static final LinkedList<TcpConnectionTracker> closedConnections = new LinkedList<>();

    public static int size() {
        return closedConnections.size();
    }

    public static boolean add(TcpConnectionTracker tcpConnectionTracker) {
        return closedConnections.add(tcpConnectionTracker);
    }

    public static Iterator<TcpConnectionTracker> iterator() {
        return closedConnections.iterator();
    }

    public static Stream<TcpConnectionTracker> stream() {
        return closedConnections.stream();
    }

    public static Stream<TcpConnectionTracker> parallelStream() {
        return closedConnections.parallelStream();
    }

    public static void forEach(Consumer<? super TcpConnectionTracker> consumer) {
        closedConnections.forEach(consumer);
    }
}
