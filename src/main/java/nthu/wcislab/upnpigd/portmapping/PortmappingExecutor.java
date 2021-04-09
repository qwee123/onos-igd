package nthu.wcislab.upnpigd.portmapping;

import org.json.JSONObject;
import org.onlab.packet.IpAddress;
import org.onlab.packet.IpPrefix;

import io.netty.handler.ssl.ApplicationProtocolConfig.Protocol;

import java.util.ArrayList;
import java.util.List;
import java.util.Collections;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Iterator;

public class PortmappingExecutor {

    private DatapathExecutable datapath;
    private ConcurrentHashMap<tableIndex, PortmappingEntry> table;
    //init a common index instance, instead of creating/allocating instance everytime for quries and inserts.
    private tableIndex indexer;

    public PortmappingExecutor(DatapathExecutable datapath) {
        this.datapath = datapath;
        this.table = new ConcurrentHashMap<>();
        this.indexer = new tableIndex();
    }

    /*
     * 1. First, check if the table has already contained instance with identical tableIndex.
     *      1.a If no such instance is found, append new entry into the table.
     *      1.b Otherwise, continue to step2.
     *
     * 2. Check if the iaddr/iport pair is identical to the requested one.
     *      2.a If it's different, reject the request.
     *      2.b Otherwise, continue to step3.
     *
     * 3. Iterate through rhost_list and check if any existed rhost has the same value as the requested one
     *      3.a If any match is found, update the timestamp of the matched rhost.
     *      3.b Otherwise, append new rhost to the entry.
     */

    /**
     * Add new portmapping entry to the datapath and the table.
     * @param entry requested entry.
     * @return 1 if action succeeds, 0 if action failed, -1 if conflicted portmapping entry is detected.
     * @throws IllegalArgumentException Throw exception if passed entry contains illegal arguments.
     */
    public int AddEntry(PortmappingEntry entry) throws IllegalArgumentException {

        if (entry.rhost_list.size() != 1 || null == entry.rhost_list.get(0)) {
            throw new IllegalArgumentException("In current version," +
                " rhost argument of AddEntry method should have only one element, and element should not be null");
        }

        PortmappingEntry.RemoteHostDetail rhost = entry.rhost_list.get(0);

        PortmappingEntry old = GetEntry(entry.eport, entry.proto);
        if (null == old) {
            if (!datapath.AddRuleForEntry(entry, rhost)) {
                return 0; //action failed. TBD: Or should be conflictedWithOtherApp
            }
            appendIntoTable(entry);
            return 1;
        }

        if (!old.ihost.equals(entry.ihost) || !(old.iport == entry.iport)) {
            return -1; //existed.
        }

        int index = 0;
        for (PortmappingEntry.RemoteHostDetail rhost_old: old.rhost_list) {
            if (rhost_old.HasSameRhost(rhost)) {
                if (!datapath.UpdateRuleForEntry(entry, rhost)) {
                    return 0;
                }
                old.UpdateRhost(index, rhost);
                return 1;
            }
            index++;
        }

        if (!datapath.AddRuleForEntry(entry, rhost)) {
            return 0;
        }
        old.AppendNewRhost(rhost);
        return 1;
    }

    /**
     * Return the corresponding portmapping entry, return null if no such entry exists.
     * @param eport external port on the IGD device
     * @param proto protocol filtered by the rule, either TCP or UDP
     * @return the entry to which the specified eport and proto is bond, or null if no such entry existed.
     */
    public PortmappingEntry GetEntry(int eport, PortmappingEntry.Protocol proto) {
        indexer.setIndex(eport, proto);
        return table.get(indexer);
    }

    /**
     * Delete entry with specified eport and protocol directly.
     * @param eport external port number
     * @param proto protocol
     * @return 1 if action succeeds, 0 if action failed, -1 if no such entry.
     */
    public int DeleteEntry(int eport, PortmappingEntry.Protocol proto) {
        indexer.setIndex(eport, proto);
        //remove return null if no specified entry is found
        PortmappingEntry entry = table.get(indexer);
        if (entry == null) {
            return -1;
        }

        List<PortmappingEntry.RemoteHostDetail> rhosts = entry.GetAllRemoteHostDetail();
        for (PortmappingEntry.RemoteHostDetail  rhost : rhosts) {
            if (!datapath.DeleteRuleForEntry(entry, rhost)) {
                return 0;
            }
            table.remove(indexer);
        }

        return 1;
    }

    /**
     * Delete entry with specified eport, protocol and rhost.
     * @param eport external port number
     * @param proto protocol
     * @param rhost_str remotehost, should be an IpPrefix in String.
     * @return 1 if action succeeds, 0 if action failed, -1 if no such entry.
     * @throws IllegalArgumentException if rhost is not a valid IPPrefix.
     */
    public int DeleteEntry(int eport, PortmappingEntry.Protocol proto, String rhost_str)
                                                            throws IllegalArgumentException {
        indexer.setIndex(eport, proto);
        PortmappingEntry entry = table.get(indexer);
        if (entry == null) {
            return -1;
        }

        PortmappingEntry.RemoteHostDetail rhost = entry.GetRemoteHostDetail(rhost_str);
        if (rhost == null) {
            return -1;
        }

        if (!datapath.DeleteRuleForEntry(entry, rhost)) {
            return 0;
        }
        entry.DeleteRemoteHost(rhost_str);

        if (entry.GetAllRemoteHostDetail().size() == 0) {
            table.remove(indexer);
        }
        return 1;
    }

    /**
     * Return the corresponding list of portmappings, which satisfy the specified port range and protocol.
     * @param start start port nubmer of the range
     * @param end end port number of the range
     * @param proto protocol to be filtered
     * @return list of portmappings
     * @throws IllegalArgumentException if start > end or start nubmer is not valid or end number is not valid.
     */
    public ArrayList<PortmappingEntry> GetEntryByPortRange(
            int start,
            int end,
            PortmappingEntry.Protocol proto)
            throws IllegalArgumentException {
            return GetEntryByPortRange(start, end, proto, 0);
    }

    /**
     * Return the corresponding list of portmappings, which satisfy the specified port range and protocol.
     * If max number is met, no more entry will be added into the list even if the above conditions are satisfied.
     * @param start start port nubmer of the range
     * @param end end port number of the range
     * @param proto protocol to be filtered
     * @param max max entry number of the return list. 0 stands for no limitation.
     * @return list of portmappings
     * @throws IllegalArgumentException if start > end or start nubmer is not valid or end number is not valid.
     */
    public ArrayList<PortmappingEntry> GetEntryByPortRange(
            int start,
            int end,
            PortmappingEntry.Protocol proto,
            int max)
            throws IllegalArgumentException {

        if (start > end ||
            !PortmappingEntry.isValidPortNubmer(start) ||
            !PortmappingEntry.isValidPortNubmer(end)) {
                throw new IllegalArgumentException("Bad start_port or end_port number.");
        }

        ArrayList<PortmappingEntry> ret = new ArrayList<PortmappingEntry>();

        for (ConcurrentHashMap.Entry<tableIndex, PortmappingEntry> entry: table.entrySet()) {
            PortmappingEntry pm_entry = entry.getValue();
            int eport = pm_entry.eport;
            if (eport < start  || eport > end || pm_entry.GetProtocol() != proto) {
                continue;
            }

            ret.add(pm_entry);

            if (max != 0 && ret.size() >= max) {
                break;
            }
        }
        return ret;
    }

    /**
     * Get PortmappingEntry-rhostdetail by index.
     * @param index index.
     * @return null if out of range. Otherwise, return corresponding entry.
     */
    public PortmappingEntry GetEntryByIndex(PortmappingNumericIndex index) {
        int i = 0, prev_i = 0, tmp = index.index;
        Iterator<PortmappingEntry> it = table.values().iterator();
        while (it.hasNext()) {
            PortmappingEntry ent = it.next();
            i += ent.rhost_list.size();

            if (i > tmp) {
                index.sub_index = tmp - prev_i;
                return ent;
            }
            prev_i = i;
        }
        return null;
    }

    private void appendIntoTable(PortmappingEntry entry) {
        indexer.setIndex(entry.eport, entry.proto);
        table.put(indexer, entry);
    }

    public static class PortmappingEntry {

        public static enum Protocol { TCP, UDP };
        private static int MAXPORTNUMBER = Short.MAX_VALUE * 2 + 1;

        private int eport; //Use int to store unsigned short
        private int iport;
        private ArrayList<RemoteHostDetail> rhost_list;
        private IpAddress ihost;
        private Protocol proto;

        public PortmappingEntry(int eport, int iport,
                        String rhost, String ihost,
                        Protocol proto, int leaseduration) throws IllegalArgumentException {
            rhost_list = new ArrayList<RemoteHostDetail>();
            int timestamp = ((int) System.currentTimeMillis()) / 1000 + leaseduration;

            if (!isValidPortNubmer(eport) || !isValidPortNubmer(iport)) {
                throw new IllegalArgumentException("Illegal Port number");
            }

            this.eport = eport;
            this.iport = iport;
            this.rhost_list.add(new RemoteHostDetail(rhost, timestamp));
            this.ihost = IpAddress.valueOf(ihost);
            this.proto = proto;
        }

        public void UpdateRhost(int index, RemoteHostDetail rhost) {
            this.rhost_list.set(index, rhost);
        }

        public void AppendNewRhost(RemoteHostDetail rhost) {
            this.rhost_list.add(rhost);
        }

        public int GetExternalPort() {
            return this.eport;
        }

        public int GetInternalPort() {
            return this.iport;
        }

        public Protocol GetProtocol() {
            return this.proto;
        }

        public String GetInternalHost() {
            return this.ihost.toString();
        }

        public IpAddress GetInternalHostByIpAddress() {
            return this.ihost;
        }

        /**
         * Get remoteHostDetail with exactly specified rhost prefix.
         * @param rhost_str remotehost prefix in string, e.g. 172.17.0.0/24.
         * @return remoteHostDetail with specified rhost prefix, null if no such remoteHost.
         * @throws IllegalArgumentException if rhost_str is not a valid IpPrefix.
         */
        public RemoteHostDetail GetRemoteHostDetail(String rhost_str) throws IllegalArgumentException {
            IpPrefix rhost_ip = RemoteHostDetail.toIpPrefix(rhost_str);
            for (RemoteHostDetail old_rhost: this.rhost_list) {
                if (old_rhost.HasSameRhost(rhost_ip)) {
                    return old_rhost;
                }
            }
            return null;
        }

        public List<RemoteHostDetail> GetAllRemoteHostDetail() {
            return Collections.unmodifiableList(this.rhost_list);
        }

        public RemoteHostDetail GetRemoteHostDetailByIndex(PortmappingNumericIndex index) {
            try {
                return this.rhost_list.get(index.sub_index);
            } catch (IndexOutOfBoundsException e) {
                return null;
            }
        }

        /**
         * Delete rhost with requested IPprefix rhost_str.
         * @param rhost_str IPprefix.
         * @return false if no such rhost.
         * @throws IllegalArgumentException if rhost_str is not a valid IpPrefix.
         */
        public boolean DeleteRemoteHost(String rhost_str) throws IllegalArgumentException {
            IpPrefix rhost_ip = RemoteHostDetail.toIpPrefix(rhost_str);
            ArrayList<RemoteHostDetail> list = this.rhost_list;
            int len = list.size();
            for (int i = 0; i < len; i++) {
                if (list.get(i).HasSameRhost(rhost_ip)) {
                    list.remove(i);
                    return true;
                }
            }
            return false;
        }

        public static boolean isValidPortNubmer(int portnumber) {
            return portnumber > 0 && portnumber <= MAXPORTNUMBER;
        }

        public static final class RemoteHostDetail {
            private IpPrefix rhost;
            private int timestamp;

            private RemoteHostDetail(String rhost, int timestamp) throws IllegalArgumentException {
                this.rhost = toIpPrefix(rhost);
                this.timestamp = timestamp;
            }

            public String GetRhost() {
                return rhost.toString();
            }

            public IpPrefix GetRhostByIpPrefix() {
                return rhost;
            }

            public int GetLeaseDuration() {
                return timestamp - ((int) System.currentTimeMillis()) / 1000;
            }

            /**
             * Check if the representation of rhost is equivilant.
             * @param req in RemoteHostDetail.
             * @return true if two object have identical rhost, 0 if rhosts are different.
             */
            public boolean HasSameRhost(RemoteHostDetail req) {
                return this.rhost.equals(req.rhost);
            }

            /**
             * Check if the representation of rhost is equivilant.
             * @param req in IpPrefix.
             * @return true if two object have identical rhost, 0 if rhosts are different.
             */
            public boolean HasSameRhost(IpPrefix req) {
                return this.rhost.equals(req);
            }

            private static IpPrefix toIpPrefix(String ip_prefix) throws IllegalArgumentException {
                if (ip_prefix.equals("*") || ip_prefix.isEmpty()) {
                    return IpPrefix.valueOf("0.0.0.0/0");
                } else {
                    return IpPrefix.valueOf(ip_prefix);
                }
            }
        }
    }

    public class PortmappingNumericIndex {

        private int index;
        private int sub_index;

        public PortmappingNumericIndex(int index) {
            this.index = index;
            this.sub_index = 0;
        }
    }

    private class tableIndex {
        private int eport;
        private PortmappingEntry.Protocol proto;

        protected void setIndex(int eport, PortmappingEntry.Protocol proto) {
            this.eport = eport;
            this.proto = proto;
        }

        @Override
        public boolean equals(Object o) {
            if (o == null || !(o instanceof tableIndex)) {
                return false;
            }
            tableIndex index = (tableIndex) o;
            return eport == index.eport && proto == index.proto;
        }

        @Override
        public int hashCode() {
            int result = eport;
            result = 31 * result + proto.hashCode();
            return result;
        }
    }
}