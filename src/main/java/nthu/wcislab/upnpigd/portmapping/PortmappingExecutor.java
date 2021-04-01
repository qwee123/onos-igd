package nthu.wcislab.upnpigd.portmapping;

import org.onlab.packet.IpAddress;
import org.onlab.packet.IpPrefix;

import java.util.ArrayList;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

import org.json.JSONException;
import org.json.JSONObject;

public class PortmappingExecutor {

    public static enum Protocol { TCP, UDP };

    private DatapathExecutable datapath;
    private ConcurrentHashMap<portmappingIndex, PortmappingEntry> table;
    //init a common index instance, instead of creating/allocating instance everytime for quries and inserts 
    private portmappingIndex indexer;

    public PortmappingExecutor(DatapathExecutable datapath) {
        this.datapath = datapath;
        this.table = new ConcurrentHashMap<>();
        this.indexer = new portmappingIndex();
    }

    /*
     * 1. First, check if the table has already contained instance with identical portmappingIndex.
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
     * @param entry
     * @return 1 if action succeeds, 0 if action failed, -1 if conflicted portmapping entry is detected
     * @throws IllegalArgumentException
     */
    public int AddEntry(PortmappingEntry entry) throws IllegalArgumentException {
        
        PortmappingEntry old = GetEntry(entry.eport, entry.proto);
        if (null == old) {
            if (!datapath.AddRuleForEntry(entry)) {
                return 0; //action failed. TBD: Or should be conflictedWithOtherApp
            }
            appendIntoTable(entry);           
            return 1;
        }

        if (!old.ihost.equals(entry.ihost) || !(old.iport == entry.iport)) {
            return -1; //existed.
        }


        if (entry.rhost_list.size() != 1 || null == entry.rhost_list.get(0)) {
            throw new IllegalArgumentException("In current version,"+
                " rhost argument of AddEntry method should have only one element, and element should not be null");
        }
        PortmappingEntry.remoteHostDetail rhost = entry.rhost_list.get(0);

        int index = 0;
        for(PortmappingEntry.remoteHostDetail rhost_old: old.rhost_list) {
            if (rhost_old.HasSameRhost(rhost)) {
                if (!datapath.UpdateRuleForEntry(entry)) {
                    return -1;
                }    
                old.UpdateRhost(index, rhost);
                return 1;
            }
            index++;
        }

        if (!datapath.AddRuleForEntry(entry)) {
            return -1;
        }
        old.AppendNewRhost(rhost);
        return 1;
    }

    /**
     * Return the corresponding portmapping entry, return null if no such entry exists
     * @param eport external port on the IGD device
     * @param proto protocol filtered by the rule, either TCP or UDP
     */
    public PortmappingEntry GetEntry(int eport, Protocol proto) {
        indexer.setIndex(eport, proto);
        return table.get(indexer);
    }

    private void appendIntoTable(PortmappingEntry entry) {
        indexer.setIndex(entry.eport, entry.proto);
        table.put(indexer, entry);
    }

    public static class PortmappingEntry {

        private static int MAXPORTNUMBER = Short.MAX_VALUE * 2 + 1;
    
        private int eport; //Use int to store unsigned short
        private int iport;
        private ArrayList<remoteHostDetail> rhost_list;
        private IpAddress ihost;
        private Protocol proto;

        public PortmappingEntry(int eport, int iport,
                        String rhost, String ihost,
                        Protocol proto, int leaseduration) throws IllegalArgumentException {
            rhost_list = new ArrayList<remoteHostDetail>();
            int timestamp = ((int)System.currentTimeMillis())/1000 + leaseduration;

            if (!isValidPortNubmer(eport) || !isValidPortNubmer(iport)) {
                throw new IllegalArgumentException("Illegal Port number");
            }

            this.eport = eport;
            this.iport = iport;
            this.rhost_list.add(new remoteHostDetail(rhost, timestamp));
            this.ihost = IpAddress.valueOf(ihost);
            this.proto = proto;
        }

        public void UpdateRhost(int index, remoteHostDetail rhost) {
            this.rhost_list.set(index, rhost);
        }

        public void AppendNewRhost(remoteHostDetail rhost) {
            this.rhost_list.add(rhost);
        }

        private boolean isValidPortNubmer(int portnumber) {
            return portnumber > 0 && portnumber < MAXPORTNUMBER;
        }

        private class remoteHostDetail {
            private IpPrefix rhost;
            private int timestamp;

            private remoteHostDetail(String rhost, int timestamp) throws IllegalArgumentException {
                this.rhost = IpPrefix.valueOf(rhost);
                this.timestamp = timestamp;
            }

            /**
             * Check if the representation of rhost is equivilant
             ** @param req
             * @return true if two object have identical rhost, 0 if rhosts are different.
             */
            public boolean HasSameRhost(remoteHostDetail req) {
                return this.rhost.equals(req.rhost);
            }
        }
    
    }

    private class portmappingIndex {
        private int eport;
        private Protocol proto;
        
        protected void setIndex(int eport, Protocol proto) {
            this.eport = eport;
            this.proto = proto;
        }

        @Override
        public boolean equals(Object o) {
            if (o == null || !(o instanceof portmappingIndex)) {
                return false;
            }
            
            portmappingIndex index = (portmappingIndex) o;
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