package nthu.wcislab.upnpigd.requesthandler;


import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpResponseStatus;
import org.json.JSONObject;

import static io.netty.util.CharsetUtil.UTF_8;

public class StatsHandler {

    public static class InterfaceHandler extends OnosExecutor {

        public InterfaceHandler(OnosAgent agent) {
            super(agent);
        }

        // No input in default
        public FullHttpResponse handle(FullHttpRequest request) {

            System.out.println(request.content().toString(UTF_8));
            /*JSONObject jobj = new JSONObject(request.content().toString(UTF_8));
            System.out.println(jobj);*/

            InterfaceStats stats = onos_agent.GetIGDExtIfaceStats();

            JSONObject res_jobj = new JSONObject();

            res_jobj.put("iface_status", stats.iface_status ? "connected" : "disconnected");
            res_jobj.put("baudrate", stats.baudrate);
            res_jobj.put("total_bytes_sent", stats.obytes);
            res_jobj.put("total_bytes_received", stats.ibytes);
            res_jobj.put("total_packets_sent", stats.opackets);
            res_jobj.put("total_packets_received", stats.ipackets);

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

    public static class ExtIpAddrHandler extends OnosExecutor {

        public ExtIpAddrHandler(OnosAgent agent) {
            super(agent);
        }

        public FullHttpResponse handle(FullHttpRequest request) {
            System.out.println(request);
            System.out.println(request.content().toString(UTF_8));
            return buildResponse("Alive", HttpResponseStatus.OK);
        }
    }

    public static class WanConnStatus extends OnosExecutor {

        public WanConnStatus(OnosAgent agent) {
            super(agent);
        }

        public FullHttpResponse handle(FullHttpRequest request) {
            System.out.println(request);
            System.out.println(request.content().toString(UTF_8));
            return buildResponse("Alive", HttpResponseStatus.OK);
        }
    }
}
