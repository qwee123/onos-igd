package nthu.wcislab.upnpigd.portmapping;

public class PortmappingEntry {

    private static int MAXPORTNUMBER = Short.MAX_VALUE * 2 + 1;
    public static enum Protocol { TCP, UDP };

    private String deviceId;
    private int eport; //Use int to store unsigned short
    private int iport;
    private String rhost;
    private String ihost;
    private Protocol proto;
    private int leaseduration;

    public PortmappingEntry(String deviceId,
                    int eport, int iport,
                    String rhost, String ihost,
                    Protocol proto, int leaseduration) {
        this.deviceId = deviceId;
        this.eport = eport;
        this.iport = iport;
        this.rhost = rhost;
        this.ihost = ihost;
        this.proto = proto;
    }

    public static boolean isValidPortNubmer(int portnumber) {
        return portnumber > 0 && portnumber < MAXPORTNUMBER;
    }

}
