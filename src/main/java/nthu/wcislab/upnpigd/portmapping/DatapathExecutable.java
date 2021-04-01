package nthu.wcislab.upnpigd.portmapping;

import nthu.wcislab.upnpigd.portmapping.PortmappingExecutor.PortmappingEntry;

public interface DatapathExecutable {
    boolean UpdateRuleForEntry(PortmappingEntry entry);
    boolean AddRuleForEntry(PortmappingEntry entry);
}
