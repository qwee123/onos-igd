package nthu.wcislab.upnpigd.requesthandler;

import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpResponseStatus;

import org.json.JSONException;
import org.json.JSONObject;

import static io.netty.util.CharsetUtil.UTF_8;
import nthu.wcislab.upnpigd.portmapping.PortmappingExecutor;
import nthu.wcislab.upnpigd.portmapping.PortmappingExecutor.PortmappingEntry;
import nthu.wcislab.upnpigd.portmapping.PortmappingExecutor.Protocol;

public class PortmappingHandler {

    public static final class PortmappingSingleHandler extends OnosExecutor {
        PortmappingExecutor executor;

        public PortmappingSingleHandler(OnosAgent agent, PortmappingExecutor executor) {
            super(agent);
            this.executor = executor;
        }

        @Override
        protected FullHttpResponse handleGet(FullHttpRequest request) {
            return null;
        }

        @Override
        protected FullHttpResponse handlePost(FullHttpRequest request) {
            JSONObject jobj = new JSONObject(request.content().toString(UTF_8));
            PortmappingEntry entry;
            boolean autoselect = false;     

            try {
                entry = new PortmappingEntry(
                        jobj.getInt("eport"), jobj.getInt("iport"),
                        jobj.getString("rhost"), jobj.getString("ihost"),
                        jobj.getString("proto").equals("TCP") ? Protocol.TCP : Protocol.UDP,
                        jobj.getInt("duration"));
                autoselect = jobj.getBoolean("autoselect");

            } catch (JSONException e) {
                log.error("Fail to parse received json object of Post method.");
                log.error("{}", e.getMessage());
                return BADREQUEST.handle(null);
            } catch (IllegalArgumentException e) {
                log.error("Fail to build PortmappingEntry.");
                log.error("{}", e.getMessage());
                return BADREQUEST.handle(null);
            }

            if (autoselect) {
                return handleAddAnyPortmapping(entry);
            } else {
                return handleNormalAddPortmapping(entry);
            }
        }

        @Override
        protected FullHttpResponse handleDelete(FullHttpRequest request) {
            return null;
        }

        private FullHttpResponse handleNormalAddPortmapping(PortmappingEntry entry) {
            int r;
            try {
                r = executor.AddEntry(entry);                
            } catch (IllegalArgumentException e) {
                log.error("IllegalArgument of AddEntry detected!");
                log.error(e.getMessage());
                return INTERNALSERVERERROR.handle(null);
            }

            JSONObject ret_jobj = new JSONObject();
            switch (r) {
                case 1:
                    //Action Succeed
                case -1:
                    //Existed entry
                default:
                    //Action Failed
            }

            return buildResponse(ret_jobj.toString(), HttpResponseStatus.OK);
        }

        private FullHttpResponse handleAddAnyPortmapping(PortmappingEntry entry) {

            /* find available port */

            JSONObject ret_jobj = new JSONObject();

            return buildResponse(ret_jobj.toString(), HttpResponseStatus.OK);
        }
    }

    public static final class PortmappingRangeHandler extends OnosExecutor {

        public PortmappingRangeHandler(OnosAgent agent) {
            super(agent);
        }

        @Override
        protected FullHttpResponse handleGet(FullHttpRequest request) {
            return null;
        }

    }

}
