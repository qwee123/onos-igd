package nthu.wcislab.upnpigd.requesthandler;

import nthu.wcislab.upnpigd.requesthandler.StatsHandler.InterfaceHandler.InterfaceStats;

public interface IfaceWatchable {
    InterfaceStats GetIGDExtIfaceStats();
    String GetIGDExtAddr();
    String GetIGDDeviceID();
}
