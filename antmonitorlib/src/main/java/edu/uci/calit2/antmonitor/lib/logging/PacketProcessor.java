/*
 *  This file is part of AntMonitor <https://athinagroup.eng.uci.edu/projects/antmonitor/>.
 *  Copyright (C) 2021 Anastasia Shuba and the UCI Networking Group
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


import android.annotation.TargetApi;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.os.Build;
import android.util.Log;
import android.util.Pair;

import java.net.InetSocketAddress;

import edu.uci.calit2.antmonitor.lib.logging.ConnectionValue.MappingErrors;
import edu.uci.calit2.antmonitor.lib.util.IpDatagram;
import edu.uci.calit2.antmonitor.lib.util.PacketDumpInfo;
import edu.uci.calit2.antmonitor.lib.util.PcapngFile;
import edu.uci.calit2.antmonitor.lib.util.Protocol;
import edu.uci.calit2.antmonitor.lib.util.TCPPacket;

import static android.os.Process.INVALID_UID;
import static android.system.OsConstants.IPPROTO_TCP;
import static android.system.OsConstants.IPPROTO_UDP;

/**
 * This class contains various methods for logging, mapping, and parsing packets.
 * These methods are typically called by the basic {@link PacketConsumer} to hide the complexity
 * of the implementation from children of {@link PacketConsumer}.
 *
 * @author Anastasia Shuba
 */
public class PacketProcessor {
    private String TAG = PacketProcessor.class.getSimpleName();

    /*
    Notes on synchronization in this class:
    synchronized on a static method locks the class
    synchronized on an instnace method locks on the instance
     */

    /** Context, used to init various tools */
    private static Context mContext;

    /** Tool used to map packets to apps */
    private static ConnectionFinder mConnFinder;

    /** Manager of pcapng files */
    private static DumperFileStateManager mStateManager;

    /** Manager of pcapng files that host packets from decrypted SSL/TLS streams */
    private static DumperFileStateManager mDecryptedStateManager;

    /** Reference to the singleton */
    private static PacketProcessor processor = null;

    private static ConnectivityManager mConnectivityManager;

    private PacketProcessor(Context context) {
        mContext = context;
        mConnectivityManager =
                (ConnectivityManager) mContext.getSystemService(Context.CONNECTIVITY_SERVICE);
        prepareForMapping();
    }

    /**
     * Retrieves an instance of this class. If no instance exists, it is created.
     * @param context
     * @return an instance of this class.
     */
    public static synchronized PacketProcessor getInstance(Context context) {
        if (processor == null) {
            processor = new PacketProcessor(context);
        }
        return processor;
    }

    private static synchronized void prepareForMapping() {
        if (mConnFinder == null)
            mConnFinder = new ConnectionFinder(mContext);
    }

    private synchronized void prepareForLogging() {
        // Create the log files
        mStateManager = new DumperFileStateManager(mContext, false);
        Pair<PcapngFile, PcapngFile> files = TrafficLogFiles.createNewActiveFileSet(mContext, false);
        mStateManager.setFiles(files);

        mDecryptedStateManager = new DumperFileStateManager(mContext, true);
        Pair<PcapngFile, PcapngFile> decryptedFiles =
                TrafficLogFiles.createNewActiveFileSet(mContext, true);
        mDecryptedStateManager.setFiles(decryptedFiles);
    }

    /**
     * Retrieves the name of the app based on the given uid
     *
     * @param uid - of the app
     * @return the name of the package of the app with the given uid, or "Unknown" if
     * no name could be found for the uid.
     */
    static ConnectionValue getAppNameByUID (PackageManager pm, int uid) {
        /* IMPORTANT NOTE:
         * From https://source.android.com/devices/tech/security/ : "The Android
         * system assigns a unique user ID (UID) to each Android application and
         * runs it as that user in a separate process"
         *
         * However, there is an exception: "A closer relationship with a shared
         * Application Sandbox is allowed via the shared UID feature where two
         * or more applications signed with same developer key can declare a
         * shared UID in their manifest."
         */

        // See if this is root
        if (uid == 0)
            return MappingErrors.CV_INVALID_UID;

        // If we can't find a running app, just get a list of packages that map to the uid
        String[] packages = pm.getPackagesForUid(uid);

        // here we take the first one
        if (packages != null && packages.length > 0) {
            String packageName = packages[0];
            String versionName = "";
            try {
                PackageInfo info = pm.getPackageInfo(packageName, 0);
                versionName = info.versionName;
            } catch (PackageManager.NameNotFoundException e) {
                //Log.d("Could not find versionName for package");
            }
            return new ConnectionValue(packageName, versionName);
        }

        return MappingErrors.CV_NOT_FOUND;
    }

    @TargetApi(Build.VERSION_CODES.Q)
    private static ConnectionValue getAppNameQ (short protocol, int srcPort, String srcIP, int dstPort,
                                               String dstIP) {
        // Only UDP and TCP are supported
        int lookupProtocol = (protocol == IpDatagram.TCP) ? IPPROTO_TCP : IPPROTO_UDP;

        InetSocketAddress local, remote;
        try {
            local = new InetSocketAddress(srcIP, srcPort);
            remote = new InetSocketAddress(dstIP, dstPort);

        } catch (IllegalArgumentException | SecurityException e) {
            return MappingErrors.CV_INVALID_TUPLE;
        }

        int uid = mConnectivityManager.getConnectionOwnerUid(lookupProtocol, local, remote);
        if (uid == INVALID_UID) {
            return MappingErrors.CV_INVALID_UID;
        }
        return getAppNameByUID(mContext.getPackageManager(), uid);
    }

    /**
     * Maps the given packet to an app
     * @param packetDumpInfo the packet which to map
     * @return the name of the app responsible for the packet and its version number.
     *          The app name and the version number are separated by a "#". If the packet
     *          could not be mapped, {@code null} is returned.
     */
    public ConnectionValue mapPacketToApp(PacketDumpInfo packetDumpInfo,
                                          TrafficType trafficDirection) {
        ConnectionValue cv = null;

        short protocolNumber = IpDatagram.readTransportProtocol(packetDumpInfo.getDump());

        // For now we can only map TCP/UDP packets (due to the implementation of ConnectionKey)
        if (protocolNumber ==  Protocol.UDP.getProtocolNumber() ||
                protocolNumber ==  Protocol.TCP.getProtocolNumber()) {

            int srcPort = -1;
            int dstPort = -1;
            String srcAddr = "";
            String dstAddr = "";
            try {
                if (trafficDirection == TrafficType.OUTGOING_PACKETS)
                {
                    srcPort = IpDatagram.readSourcePort(packetDumpInfo.getDump());
                    srcAddr = IpDatagram.readSourceIP(packetDumpInfo.getDump());

                    dstPort = IpDatagram.readDestinationPort(packetDumpInfo.getDump());
                    dstAddr = IpDatagram.readDestinationIP(packetDumpInfo.getDump());
                }
                else
                {
                    srcPort = IpDatagram.readDestinationPort(packetDumpInfo.getDump());
                    srcAddr = IpDatagram.readDestinationIP(packetDumpInfo.getDump());

                    dstPort = IpDatagram.readSourcePort(packetDumpInfo.getDump());
                    dstAddr = IpDatagram.readSourceIP(packetDumpInfo.getDump());
                }

                // Proceed to mapping
                cv = getConnValue(protocolNumber, srcPort, srcAddr, dstPort, dstAddr);

                if (cv == null)
                    cv = MappingErrors.CV_NOT_FOUND;

            } catch (IndexOutOfBoundsException e) {
                // Write that we couldn't map packet due to malformed packet
                return MappingErrors.CV_MALFORMED_PACKET;
            }
        } else {
            // Write that we couldn't map packet due to its use of a transport protocol other than tcp/udp.
            cv = new ConnectionValue(MappingErrors.INVALID_PROTOCOL + protocolNumber, null);
        }

        return cv;
    }

    /**
     * Retrieves {@link ConnectionValue} for the given source and destination tuples
     * @param srcPort port number of the client app
     * @param srcIP source IP of the client app
     * @param dstPort destination port
     * @param dstIP destination IP
     * @return {@link ConnectionValue} containing the app name and version number, if available.
     *          If packet could not be mapped, {@code null} is returned
     */
    public ConnectionValue getConnValue(short protocol, int srcPort, String srcIP, int dstPort,
                                        String dstIP) {
        synchronized (mConnFinder) {
            ConnectionValue connVal = mConnFinder.getConnection(srcPort);

            if (connVal != null) {
                return connVal;
                //Log.d(TAG, "Matched " + srcIp);
            } else {
                // No match. Re-map and try again.
                //Log.d(TAG, "No match for " + connKey
                if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.Q) {
                    connVal = getAppNameQ(protocol, srcPort, srcIP, dstPort, dstIP);
                    mConnFinder.putConnection(srcPort, connVal, true);
                    return connVal;
                } else {
                    mConnFinder.findConnections();
                    connVal = mConnFinder.getConnection(srcPort);
                    if (connVal != null) {
                        return connVal;
                    } else {
                        // Does not make sense to re-try anymore
                        //Log.d(TAG, "Giving up on " + connKey + " no match!");
                        // Until we re-map due to another "cache miss", we
                        // will not attempt to map this key anymore
                        ConnectionValue cv = MappingErrors.CV_NOT_FOUND;
                        mConnFinder.putConnection(srcPort, cv, false);
                        //appName = "No mapping: after 2 attempts.";
                        return null;
                    }
                }
            }
        }
    }

    /**
     * Writes the packet to a pcapng file on disk.
     * @param packet The packet (and its associated metadata) that is to be written to file.
     * @param comment comment to include when logging the packet. Passing {@code null} will log the
     *                packet without annotations.
     * @param trafficDirection indicating whether this packet is incoming or outgoing.
     */
    public synchronized void log(PacketDumpInfo packet, String comment,
                                 TrafficType trafficDirection) {
        // Check if we need to init first
        if (mStateManager == null)
            prepareForLogging();

        if(comment == null)
            comment = "";

        if (packet.getPacketAnnotation().isDecryptedTLS()) {
            PcapngFile file = mDecryptedStateManager.getExistingFile(trafficDirection);
            file.appendEnhancedPacketBlock(packet.getTimestamp(), packet.getCaptureLength(),
                    packet.getOriginalLength(), packet.getDump(), comment);
        } else {
            PcapngFile file = mStateManager.getExistingFile(trafficDirection);
            file.appendEnhancedPacketBlock(packet.getTimestamp(), packet.getCaptureLength(),
                    packet.getOriginalLength(), packet.getDump(), comment);
        }
    }

    /**
     * Convenience method for logging full ICMP, UDP, and HTTP(S) packets.
     * @param packet the original packet containing headers and data
     * @param protocol the protocol
     * @param destinationPort destination port - used to determine whether the packet is
     *                        HTTP/HTTPS (port 80/443) or not.
     * @return the length of the entire packet if the packet is ICMP, UDP, or HTTP(S).
     * Otherwise the length of the headers is returned.
     * @throws IllegalArgumentException if the protocol is unknown
     */
    public int getFullPacketSize(byte[] packet, short protocol, int destinationPort)
        throws IllegalArgumentException {
        int fullLength = packet.length;

        // If ICMP, UDP, or HTTP/HTTPS (based on port), then dump full packet
        if (protocol ==  Protocol.ICMP.getProtocolNumber() ||
                protocol == Protocol.UDP.getProtocolNumber() ||
                destinationPort == 80 || destinationPort == 443) {
            return fullLength;
        }

        // Not port 80/443, just dump headers
        if (protocol ==  Protocol.TCP.getProtocolNumber()) {
            byte headerLength = IpDatagram.readIPHeaderLength(packet);
            short transportHeaderLength = TCPPacket.readHeaderLength(packet, headerLength);
            return (headerLength * 4) + (transportHeaderLength * 4);
        } else {
            throw new IllegalArgumentException("Unknown protocol: " + protocol);
        }
    }

    /**
     * Returns the length of the header(s). If protocol is ICMP, full packet size is returned.
     * @param packet the original packet containing headers and data
     * @param protocol the protocol
     * @return the the length of the header(s). If protocol is ICMP, full packet size is returned.
     * @throws IllegalArgumentException if the protocol is unknown */
    public int getHeadersSize(byte[] packet, short protocol)
        throws IllegalArgumentException {

        // Check if ICMP, otherwise assume it is either TCP or UDP.
        if (protocol == Protocol.ICMP.getProtocolNumber()) {
            return packet.length;
        }

        byte headerLength = IpDatagram.readIPHeaderLength(packet);

        if (protocol == Protocol.TCP.getProtocolNumber()) {
            short transportHeaderLength = TCPPacket.readHeaderLength(packet, headerLength);
            return (headerLength * 4) + (transportHeaderLength * 4);
        } else if (protocol == Protocol.UDP.getProtocolNumber()) {
            return (headerLength * 4) + 8;
        } else {
            throw new IllegalArgumentException("Unknown protocol: " + protocol);
        }
    }

    /**
     * Enum representing the different kinds of traffic.
     */
    public static enum TrafficType {

        /**
         * Represents outgoing traffic/packets.
         */
        OUTGOING_PACKETS {
            @Override
            public String getTrafficTypeString() { return "out"; }
        },

        /**
         * Represents incoming traffic/packets.
         */
        INCOMING_PACKETS {
            @Override
            public String getTrafficTypeString() { return "inc"; }
        };

        /**
         * Gets the proper file extension for this type of dump file (<i>including</i> the dot).
         * @return The proper file extension for this type of dump file (<i>including</i> the dot).
         */
        public abstract String getTrafficTypeString();

    }

    /** Clean up **/
    public synchronized static void shutdown() {
        if (mConnFinder != null) {
            synchronized (mConnFinder) {
                mConnFinder.shutdown();
                mConnFinder = null;
            }
        }

        if (processor != null) {
            // Lock on the instance, as the other logging methods lock on the instance
            synchronized (processor) {
                if (mStateManager != null) {
                    mStateManager.finishLogging();
                    mStateManager = null;

                    mDecryptedStateManager.finishLogging();
                    mDecryptedStateManager = null;
                }
                processor = null;
            }
        }
    }
}
