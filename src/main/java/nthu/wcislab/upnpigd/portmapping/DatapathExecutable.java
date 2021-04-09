package nthu.wcislab.upnpigd.portmapping;

import nthu.wcislab.upnpigd.portmapping.PortmappingExecutor.PortmappingEntry;
import nthu.wcislab.upnpigd.portmapping.PortmappingExecutor.PortmappingEntry.RemoteHostDetail;

public interface DatapathExecutable {
    boolean UpdateRuleForEntry(PortmappingEntry entry, RemoteHostDetail rhost);
    boolean AddRuleForEntry(PortmappingEntry entry, RemoteHostDetail rhost);
    boolean DeleteRuleForEntry(PortmappingEntry entry, RemoteHostDetail rhost);
}
