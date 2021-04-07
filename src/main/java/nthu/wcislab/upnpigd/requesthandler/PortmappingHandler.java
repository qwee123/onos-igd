package nthu.wcislab.upnpigd.requesthandler;

import nthu.wcislab.upnpigd.portmapping.PortmappingExecutor;
import org.json.JSONObject;

public class PortmappingHandler extends HttpMethodHandler {

    protected static String json_tag_eport = "eport";
    protected static String json_tag_proto = "proto";
    protected static String json_tag_rhost = "rhost";
    protected static String json_tag_ihost = "iaddr";
    protected static String json_tag_iport = "iport";
    protected static String json_tag_duration = "duration";

    protected PortmappingExecutor pm_executor;

    protected PortmappingHandler(PortmappingExecutor pm_executor) {
        this.pm_executor = pm_executor;
    }

    protected JSONObject BuildPortmappingToJson(
            int eport, int iport, String rhost,
            String proto, String ihost, int leaseduration) {

        JSONObject ret = new JSONObject();
        ret.put(json_tag_eport, eport);
        ret.put(json_tag_iport, iport);
        ret.put(json_tag_rhost, rhost);
        ret.put(json_tag_proto, proto);
        ret.put(json_tag_ihost, ihost);
        ret.put(json_tag_duration, leaseduration);
        return ret;
    }
}
