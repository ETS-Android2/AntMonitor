/*
 *  This file is part of AntMonitor <https://athinagroup.eng.uci.edu/projects/antmonitor/>.
 *  Copyright (C) 2018 Anastasia Shuba and the UCI Networking Group
 *  <https://athinagroup.eng.uci.edu>, University of California, Irvine.
 *
 *  AntMonitor is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, version 2 of the License.
 *
 *  AntMonitor is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with AntMonitor. If not, see <http://www.gnu.org/licenses/>.
 */
package edu.uci.calit2.antmonitor.lib.logging;

import edu.uci.calit2.antmonitor.lib.util.PacketDumpInfo;

/**
 * Returned from a {@link edu.uci.calit2.antmonitor.lib.vpn.PacketFilter}. Lets the system know
 * whether or not to allow the packet through. Children of the class can pass along other info
 * from their {@link edu.uci.calit2.antmonitor.lib.vpn.PacketFilter} implementations to their
 * {@link PacketConsumer} implementations as this object will be wrapped within the corresponding
 * {@link PacketDumpInfo} object when {@link PacketConsumer#consumePacket(PacketDumpInfo)}
 * is invoked.
 *
 * @author Anastasia Shuba
 */
public class PacketAnnotation {

    /** Lets the system know whether or not to allow the packet through */
    private final boolean allowPacket;

    /** Indicates whether the packet is from a decrypted SSL/TLS stream */
    protected final boolean isDecryptedTLS;

    /** Default constructor: allows the packet through */
    public PacketAnnotation() {
        this.allowPacket = true;
        this.isDecryptedTLS = false;
    }

    /**
     * Constructor
     * @param allowPacket pass {@code true} to allow the packet through, and {@code false} otherwise
     */
    public PacketAnnotation(boolean allowPacket) {
        this.allowPacket = allowPacket;
        this.isDecryptedTLS = false;
    }

    /**
     * Constructor
     * @param allowPacket pass {@code true} to allow the packet through, and {@code false} otherwise
     * @param isDecryptedTLS pass {@code true} if packet is from a decrypted SSL/TLS stream, and
     * {@code false} otherwise
     */
    public PacketAnnotation(boolean allowPacket, boolean isDecryptedTLS) {
        this.allowPacket = allowPacket;
        this.isDecryptedTLS = isDecryptedTLS;
    }

    /**
     * @return {@code true} if packet is allowed to go through; {@code false} otherwise
     */
    public boolean isAllowed() { return allowPacket; }

    /**
     * @return {@code true} if packet is from a decrypted SSL/TLS stream; {@code false} otherwise
     */
    public boolean isDecryptedTLS() { return isDecryptedTLS; }
}
