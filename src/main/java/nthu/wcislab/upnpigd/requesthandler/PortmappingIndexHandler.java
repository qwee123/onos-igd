package nthu.wcislab.upnpigd.requesthandler;

import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpResponseStatus;
import org.json.JSONObject;
import org.json.JSONArray;
import org.json.JSONException;

import nthu.wcislab.upnpigd.portmapping.PortmappingExecutor;
import nthu.wcislab.upnpigd.portmapping.PortmappingExecutor.PortmappingEntry;
import nthu.wcislab.upnpigd.portmapping.PortmappingExecutor.PortmappingNumericIndex;
import nthu.wcislab.upnpigd.portmapping.PortmappingExecutor.PortmappingEntry.Protocol;
import nthu.wcislab.upnpigd.portmapping.PortmappingExecutor.PortmappingEntry.RemoteHostDetail;

import static io.netty.util.CharsetUtil.UTF_8;

public class PortmappingIndexHandler extends PortmappingHandler {

    private static String json_tag_index = "index";

    public PortmappingIndexHandler(PortmappingExecutor pm_executor) {
        super(pm_executor);
    }

    @Override
    protected FullHttpResponse handleGet(FullHttpRequest request) {
        JSONObject jobj = new JSONObject(request.content().toString(UTF_8));
        int index;

        try {
            index = jobj.getInt(json_tag_index);
        } catch (JSONException e) {
            log.error("Fail to parse received json object of Get method.");
            log.error("{}", e.getMessage());
            return BADREQUEST.handle(null);
        }

        /**
         * The following code is a little bit unreasonable, and due to the current structure I can't figure out
         * a correct way to enhance it. Sorry.
         */
        PortmappingNumericIndex pm_index = pm_executor.new PortmappingNumericIndex(index);
        PortmappingEntry entry = pm_executor.GetEntryByIndex(pm_index);
        if (entry == null) {
            return NOTFOUND.handle(null);
        }

        RemoteHostDetail rhostdetail = entry.GetRemoteHostDetailByIndex(pm_index);
        if (rhostdetail == null) {
            log.error("Fail to retrieve rhost detail with sub_index.");
            return INTERNALSERVERERROR.handle(null);
        }

        JSONObject ret = BuildPortmappingToJson(
                entry.GetExternalPort(),
                entry.GetInternalPort(),
                rhostdetail.GetRhost(),
                entry.GetProtocol().toString(),
                entry.GetInternalHost(),
                rhostdetail.GetLeaseDuration()
        );

        return buildResponse(ret, HttpResponseStatus.OK);
    }
}
