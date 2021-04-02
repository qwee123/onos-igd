package nthu.wcislab.upnpigd.requesthandler;

import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpResponseStatus;
import org.json.JSONObject;
import org.json.JSONException;
import static io.netty.util.CharsetUtil.UTF_8;

import nthu.wcislab.upnpigd.portmapping.PortmappingExecutor;
import nthu.wcislab.upnpigd.portmapping.PortmappingExecutor.PortmappingEntry;
import nthu.wcislab.upnpigd.portmapping.PortmappingExecutor.PortmappingEntry.Protocol;
import nthu.wcislab.upnpigd.portmapping.PortmappingExecutor.PortmappingEntry.RemoteHostDetail;

public class PortmappingSingleHandler extends PortmappingHandler {

    private static String json_tag_eport = "eport";
    private static String json_tag_proto = "proto";
    private static String json_tag_rhost = "rhost";
    private static String json_tag_ihost = "iaddr";
    private static String json_tag_iport = "iport";
    private static String json_tag_duration = "duration";
    private static String json_tag_auto = "autoselect"; // To distinquish AddAny and normal Add method
    private static String json_tag_return_code = "return_code";

    private static int success_ret_code = 0;
    private static int conflicted_with_other_app_ret_code = -2;

    public PortmappingSingleHandler(PortmappingExecutor pm_executor) {
        super(pm_executor);
    }

    @Override
    protected FullHttpResponse handleGet(FullHttpRequest request) {
        JSONObject jobj = new JSONObject(request.content().toString(UTF_8));
        int eport;
        Protocol proto;
        String rhost;

        try {
            eport = jobj.getInt(json_tag_eport);
            proto = jobj.getString(json_tag_proto).equals("TCP") ? Protocol.TCP : Protocol.UDP;
            rhost = jobj.getString(json_tag_rhost);
        } catch (JSONException e) {
            log.error("Fail to parse received json object of Get method.");
            log.error("{}", e.getMessage());
            return BADREQUEST.handle(null);
        }

        PortmappingEntry entry = pm_executor.GetEntry(eport, proto);
        if (entry == null) {
            return NOTFOUND.handle(null);
        }

        RemoteHostDetail rhostdetail;
        try {
            rhostdetail = entry.GetRemoteHostDetail(rhost);
        } catch (IllegalArgumentException e) {
            log.error("remotehost is not a valid ip prefix.");
            log.error("{}", e.getMessage());
            return BADREQUEST.handle(null);
        }

        if (rhostdetail == null) {
            return NOTFOUND.handle(null);
        }

        JSONObject ret = new JSONObject();
        ret.put(json_tag_eport, entry.GetExternalPort());
        ret.put(json_tag_iport, entry.GetInternalPort());
        ret.put(json_tag_rhost, rhostdetail.GetRhost());
        ret.put(json_tag_proto, entry.GetProtocol().toString());
        ret.put(json_tag_ihost, entry.GetInternalHost());
        ret.put(json_tag_duration, rhostdetail.GetLeaseDuration());

        return buildResponse(ret, HttpResponseStatus.OK);
    }

    @Override
    protected FullHttpResponse handlePost(FullHttpRequest request) {
        JSONObject jobj = new JSONObject(request.content().toString(UTF_8));
        PortmappingEntry entry;
        boolean autoselect = false;

        try {
            entry = new PortmappingEntry(
                    jobj.getInt(json_tag_eport), jobj.getInt(json_tag_iport),
                    jobj.getString(json_tag_rhost), jobj.getString(json_tag_ihost),
                    jobj.getString(json_tag_proto).equals("TCP") ? Protocol.TCP : Protocol.UDP,
                    jobj.getInt(json_tag_duration));
            autoselect = jobj.getBoolean(json_tag_auto);

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
            r = pm_executor.AddEntry(entry);
        } catch (IllegalArgumentException e) {
            log.error("IllegalArgument of AddEntry detected!");
            log.error(e.getMessage());
            return INTERNALSERVERERROR.handle(null);
        }

        JSONObject ret_jobj = new JSONObject();
        switch (r) {
            case 1:
                ret_jobj.put(json_tag_return_code, success_ret_code);
                ret_jobj.put(json_tag_eport, entry.GetExternalPort());
                return buildResponse(ret_jobj.toString(), HttpResponseStatus.OK);
            case -1:   //Existed entry
                return CONFLICT.handle(null);
            default:
                return INTERNALSERVERERROR.handle(null);
        }
    }

    private FullHttpResponse handleAddAnyPortmapping(PortmappingEntry entry) {

        /* find available port */

        JSONObject ret_jobj = new JSONObject();

        return buildResponse(ret_jobj, HttpResponseStatus.OK);
    }
}