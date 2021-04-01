package nthu.wcislab.upnpigd.requesthandler;

import nthu.wcislab.upnpigd.requesthandler.StatsHandler.InterfaceHandler.InterfaceStats;

public interface OnosAgent {
    InterfaceStats GetIGDExtIfaceStats();
    String GetIGDExtAddr();
    String GetIGDDeviceID();
}
