package nthu.wcislab.upnpigd.requesthandler;


import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpResponseStatus;
import org.json.JSONObject;

import static io.netty.util.CharsetUtil.UTF_8;

public final class StatsHandler {

    static final String JSON_TAG_EXT_IP = "ext_ip_addr";
    static final String JSON_TAG_WAN_CONN_STATUS = "wan_conn_status";
    static final String JSON_TAG_IFACE_STATUS = "iface_status";
    static final String JSON_TAG_BAUDRATE = "baudrate";
    static final String JSON_TAG_TOTAL_BYTES_SENT = "total_bytes_sent";
    static final String JSON_TAG_TOTAL_BYTES_RECV = "total_bytes_received";
    static final String JSON_TAG_TOTAL_PKT_SENT = "total_packets_sent";
    static final String JSON_TAG_TOTAL_PKT_RECV = "total_packets_received";

    private StatsHandler(){}

    public static final class InterfaceHandler extends OnosExecutor {

        public InterfaceHandler(OnosAgent agent) {
            super(agent);
        }

        // No input in default
        @Override
        protected FullHttpResponse handleGet(FullHttpRequest request) {

            System.out.println(request.content().toString(UTF_8));
            /*JSONObject jobj = new JSONObject(request.content().toString(UTF_8));
            System.out.println(jobj);*/

            InterfaceStats stats = onos_agent.GetIGDExtIfaceStats();

            JSONObject res_jobj = new JSONObject();

            res_jobj.put(JSON_TAG_IFACE_STATUS, stats.iface_status ? "connected" : "disconnected");
            res_jobj.put(JSON_TAG_BAUDRATE, stats.baudrate);
            res_jobj.put(JSON_TAG_TOTAL_BYTES_SENT, stats.obytes);
            res_jobj.put(JSON_TAG_TOTAL_BYTES_RECV, stats.ibytes);
            res_jobj.put(JSON_TAG_TOTAL_PKT_SENT, stats.opackets);
            res_jobj.put(JSON_TAG_TOTAL_PKT_RECV, stats.ipackets);

            return buildResponse(res_jobj.toString(), HttpResponseStatus.OK);
        }

        public static class InterfaceStats {
            public boolean iface_status; // Connected or Disconnected
            public long opackets; //unsigned int
            public long ipackets;
            public long obytes;
            public long ibytes;
            public long baudrate;
        }
    }

    public static final class ExtIpAddrHandler extends OnosExecutor {

        public ExtIpAddrHandler(OnosAgent agent) {
            super(agent);
        }

        @Override
        protected FullHttpResponse handleGet(FullHttpRequest request) {

            JSONObject res_jobj = new JSONObject();
            res_jobj.put(JSON_TAG_EXT_IP, onos_agent.GetIGDExtAddr());

            return buildResponse(res_jobj.toString(), HttpResponseStatus.OK);
        }
    }

    public static final class WanConnStatus extends OnosExecutor {

        public WanConnStatus(OnosAgent agent) {
            super(agent);
        }

        @Override
        protected FullHttpResponse handleGet(FullHttpRequest request) {

            InterfaceHandler.InterfaceStats stats = onos_agent.GetIGDExtIfaceStats();

            JSONObject res_jobj = new JSONObject();
            res_jobj.put(JSON_TAG_WAN_CONN_STATUS, stats.iface_status ? "connected" : "disconnected");

            return buildResponse(res_jobj.toString(), HttpResponseStatus.OK);
        }
    }
}
