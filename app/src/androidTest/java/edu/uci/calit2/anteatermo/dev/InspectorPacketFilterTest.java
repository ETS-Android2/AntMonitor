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

package edu.uci.calit2.anteatermo.dev;

import android.app.Application;
import android.test.ApplicationTestCase;

import java.nio.ByteBuffer;
import java.util.ArrayList;

import edu.uci.calit2.anteater.client.android.analysis.ActionReceiver;
import edu.uci.calit2.anteater.client.android.analysis.InspectorPacketFilter;
import edu.uci.calit2.anteater.client.android.database.PrivacyDB;
import edu.uci.calit2.antmonitor.lib.logging.PacketAnnotation;
import edu.uci.calit2.antmonitor.lib.util.AhoCorasickInterface;
import edu.uci.calit2.antmonitor.lib.util.TCPReassemblyInfo;

public class InspectorPacketFilterTest extends ApplicationTestCase<Application> {

    private ByteBuffer m_testByteBuffer = ByteBuffer.allocateDirect(1024 * 16);

    /** Packet filter in test */
    private InspectorPacketFilter m_packetFilter;

    private String m_testStrAllow = "allow_me";
    private String m_testStrHash = "hash_me";
    private String m_testStrBlock = "block_me";

    public InspectorPacketFilterTest() { super(Application.class); }

    protected void setUp() throws Exception {
        super.setUp();
        createApplication();

        // Add strings to the Aho-Corasick search
        String[] testStrs = {m_testStrAllow, m_testStrHash, m_testStrBlock};
        AhoCorasickInterface.getInstance().init(testStrs);

        // Set actions for the strings in the database
        PrivacyDB db = PrivacyDB.getInstance(mContext);
        db.addGlobalFilterAsyncTask(getContext(), null, m_testStrAllow, m_testStrAllow, true,
                ActionReceiver.ACTION_ALLOW, true);
        db.addGlobalFilterAsyncTask(getContext(), null, m_testStrHash, m_testStrHash, true,
                ActionReceiver.ACTION_HASH, true);
        db.addGlobalFilterAsyncTask(getContext(), null, m_testStrBlock, m_testStrBlock, true,
                ActionReceiver.ACTION_DENY, true);

        // Set packet filter
        m_packetFilter = new InspectorPacketFilter(getContext());
    }

    private void acceptDecryptedSSLPacketHelper(String packet, boolean shouldAccept) {
        m_testByteBuffer.position(0);
        m_testByteBuffer.put(packet.getBytes());

        TCPReassemblyInfo tcpInfo = new TCPReassemblyInfo("147.10.10.20", 5100, 443, 1, 1,
                m_testByteBuffer.position());
        PacketAnnotation resultAnnotation = m_packetFilter.acceptDecryptedSSLPacket(m_testByteBuffer, tcpInfo);

        if (shouldAccept)
            assertTrue(resultAnnotation.isAllowed());
        else
            assertFalse(resultAnnotation.isAllowed());
    }

    private void acceptIPDatagramHelper(String packet, boolean shouldAccept) {
        m_testByteBuffer.position(0);
        m_testByteBuffer.put(packet.getBytes());

        PacketAnnotation resultAnnotation = m_packetFilter.acceptIPDatagram(m_testByteBuffer);

        if (shouldAccept)
            assertTrue(resultAnnotation.isAllowed());
        else
            assertFalse(resultAnnotation.isAllowed());
    }

    public void testAcceptDecryptedSSLPacket() {
        // 1) No strings found in packet
        String packet = "GET /o1cbbfc3/49eec09807_v21_phone.jpg HTTP/1.1\\r\\n";
        acceptDecryptedSSLPacketHelper(packet, true);

        // 2) Allowed string in packet
        packet = "GET /o1cbbfc3/49eec09807_v21_phone.jpg?" + m_testStrAllow + " HTTP/1.1\\r\\n";
        acceptDecryptedSSLPacketHelper(packet, true);

        // 3) Hashed string in packet
        packet = "GET /o1cbbfc3/49eec09807_v21_phone.jpg?" + m_testStrHash + " HTTP/1.1\\r\\n";
        acceptDecryptedSSLPacketHelper(packet, true);

        // 4) Blocked string in packet
        packet = "GET /o1cbbfc3/49eec09807_v21_phone.jpg?" + m_testStrBlock + " HTTP/1.1\\r\\n";
        acceptDecryptedSSLPacketHelper(packet, false);
    }

    public void testAcceptIPDatagram() {
        // 1) No strings found in packet
        String packet = "GET /o1cbbfc3/49eec09807_v21_phone.jpg HTTP/1.1\\r\\n";
        acceptIPDatagramHelper(packet, true);

        // 2) Allowed string in packet
        packet = "GET /o1cbbfc3/49eec09807_v21_phone.jpg?" + m_testStrAllow + " HTTP/1.1\\r\\n";
        acceptIPDatagramHelper(packet, true);

        // 3) Hashed string in packet
        packet = "GET /o1cbbfc3/49eec09807_v21_phone.jpg?" + m_testStrHash + " HTTP/1.1\\r\\n";
        acceptIPDatagramHelper(packet, true);

        // 4) Blocked string in packet
        packet = "GET /o1cbbfc3/49eec09807_v21_phone.jpg?" + m_testStrBlock + " HTTP/1.1\\r\\n";
        acceptIPDatagramHelper(packet, false);
    }
}
