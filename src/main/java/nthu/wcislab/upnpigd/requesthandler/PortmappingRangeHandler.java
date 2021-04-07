package nthu.wcislab.upnpigd.requesthandler;

import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpResponseStatus;
import org.json.JSONObject;
import org.json.JSONArray;
import org.json.JSONException;

import nthu.wcislab.upnpigd.portmapping.PortmappingExecutor;
import nthu.wcislab.upnpigd.portmapping.PortmappingExecutor.PortmappingEntry;
import nthu.wcislab.upnpigd.portmapping.PortmappingExecutor.PortmappingEntry.Protocol;
import nthu.wcislab.upnpigd.portmapping.PortmappingExecutor.PortmappingEntry.RemoteHostDetail;

import static io.netty.util.CharsetUtil.UTF_8;
import java.util.List;
import java.util.ArrayList;

public class PortmappingRangeHandler extends PortmappingHandler {

    private static String json_tag_start = "start_port_num";
    private static String json_tag_end = "end_port_num";
    private static String json_tag_proto = "proto";
    private static String json_tag_max_entry = "max_entry_number";
    private static String json_tag_portmapping = "portmapping";
    private static String json_tag_deleted = "deleted";

    public PortmappingRangeHandler(PortmappingExecutor pm_executor) {
        super(pm_executor);
    }

    @Override
    protected FullHttpResponse handleGet(FullHttpRequest request) {
        JSONObject jobj = new JSONObject(request.content().toString(UTF_8));
        int start_port, end_port, max_entry;
        Protocol proto;

        try {
            proto = jobj.getString(json_tag_proto).toLowerCase().equals("tcp") ? Protocol.TCP : Protocol.UDP;
            start_port = jobj.getInt(json_tag_start);
            end_port = jobj.getInt(json_tag_end);
            max_entry = jobj.getInt(json_tag_max_entry);
        } catch (JSONException e) {
            log.error("Fail to parse received json object of Get method.");
            log.error("{}", e.getMessage());
            return BADREQUEST.handle(null);
        }

        ArrayList<PortmappingEntry> pm_list;
        try {
            pm_list = pm_executor.GetEntryByPortRange(start_port, end_port, proto, max_entry);
        } catch (IllegalArgumentException e) {
            return BADREQUEST.handle(null);
        }

        JSONArray ret_list = new JSONArray();
        for (PortmappingEntry entry: pm_list) {
            List<RemoteHostDetail> rhost_list = entry.GetAllRemoteHostDetail();
            for (RemoteHostDetail rhost: rhost_list) {
                JSONObject jent = BuildPortmappingToJson(
                    entry.GetExternalPort(),
                    entry.GetInternalPort(),
                    rhost.GetRhost(),
                    entry.GetProtocol().toString(),
                    entry.GetInternalHost(),
                    rhost.GetLeaseDuration()
                );
                ret_list.put(jent);
            }
        }

        JSONObject ret = new JSONObject();
        ret.put(json_tag_portmapping, ret_list);

        return buildResponse(ret, HttpResponseStatus.OK);
    }

    @Override
    protected FullHttpResponse handleDelete(FullHttpRequest request) {
        JSONObject jobj = new JSONObject(request.content().toString(UTF_8));
        int start_port, end_port;
        Protocol proto;

        try {
            proto = jobj.getString(json_tag_proto).toLowerCase().equals("tcp") ? Protocol.TCP : Protocol.UDP;
            start_port = jobj.getInt(json_tag_start);
            end_port = jobj.getInt(json_tag_end);
        } catch (JSONException e) {
            log.error("Fail to parse received json object of Get method.");
            log.error("{}", e.getMessage());
            return BADREQUEST.handle(null);
        }

        ArrayList<PortmappingEntry> pm_list;
        try {
            pm_list = pm_executor.GetEntryByPortRange(start_port, end_port, proto);
        } catch (IllegalArgumentException e) {
            return BADREQUEST.handle(null);
        }

        JSONArray ret_list = new JSONArray();
        for (PortmappingEntry entry: pm_list) {
            int eport = entry.GetExternalPort();
            if (pm_executor.DeleteEntry(eport, entry.GetProtocol())) {
                ret_list.put(eport);
            } else {
                log.warn("Fail to delete entry retrieved from get method."
                    + " eport: {}|proto: {}", eport, proto.toString());
            }
        }

        JSONObject ret = new JSONObject();
        ret.put(json_tag_deleted, ret_list);

        return buildResponse(ret, HttpResponseStatus.OK);
    }
}
