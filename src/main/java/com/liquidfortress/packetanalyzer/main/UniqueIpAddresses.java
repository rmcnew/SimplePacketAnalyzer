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

package com.liquidfortress.packetanalyzer.main;

import com.liquidfortress.packetanalyzer.util.Inet4AddressComparator;
import com.liquidfortress.packetanalyzer.util.Inet6AddressComparator;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.util.concurrent.ConcurrentSkipListSet;

/**
 * UniqueIpAddresses
 * <p/>
 * Track unique IP addresses
 */
public class UniqueIpAddresses {

    private static ConcurrentSkipListSet<Inet4Address> uniqueIpv4Addresses =
            new ConcurrentSkipListSet<>(new Inet4AddressComparator());

    private static ConcurrentSkipListSet<Inet6Address> uniqueIpv6Addresses =
            new ConcurrentSkipListSet<>(new Inet6AddressComparator());

    public static int size() {
        return uniqueIpv4Addresses.size() + uniqueIpv6Addresses.size();
    }

    public static boolean add(Inet4Address inet4Address) {
        return uniqueIpv4Addresses.add(inet4Address);
    }

    public static boolean add(Inet6Address inet6Address) {
        return uniqueIpv6Addresses.add(inet6Address);
    }
}


