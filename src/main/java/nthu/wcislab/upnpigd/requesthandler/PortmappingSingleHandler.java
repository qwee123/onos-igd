package nthu.wcislab.upnpigd.requesthandler;

import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpResponseStatus;
import org.json.JSONObject;
import org.json.JSONArray;
import org.json.JSONException;
import static io.netty.util.CharsetUtil.UTF_8;

import nthu.wcislab.upnpigd.portmapping.PortmappingExecutor;
import nthu.wcislab.upnpigd.portmapping.PortmappingExecutor.PortmappingEntry;
import nthu.wcislab.upnpigd.portmapping.PortmappingExecutor.PortmappingEntry.Protocol;
import nthu.wcislab.upnpigd.portmapping.PortmappingExecutor.PortmappingEntry.RemoteHostDetail;

import java.util.ArrayList;

public class PortmappingSingleHandler extends PortmappingHandler {

    private static String json_tag_return_code = "return_code";
    private static String json_tag_permit_port_range = "permit_port_range";

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
            proto = jobj.getString(json_tag_proto).toLowerCase().equals("tcp") ? Protocol.TCP : Protocol.UDP;
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

    @Override
    protected FullHttpResponse handlePost(FullHttpRequest request) {
        JSONObject jobj = new JSONObject(request.content().toString(UTF_8));

        if (jobj.has(json_tag_permit_port_range)) {
            return handleAddAnyPortmapping(jobj);
        } else {
            return handleNormalAddPortmapping(jobj);
        }
    }

    @Override
    protected FullHttpResponse handleDelete(FullHttpRequest request) {
        JSONObject jobj = new JSONObject(request.content().toString(UTF_8));
        int eport;
        Protocol proto;
        String rhost;

        try {
            eport = jobj.getInt(json_tag_eport);
            proto = jobj.getString(json_tag_proto).toLowerCase().equals("tcp") ? Protocol.TCP : Protocol.UDP;
            rhost = jobj.getString(json_tag_rhost);
        } catch (JSONException e) {
            log.error("Fail to parse received json object of Delete method.");
            log.error("{}", e.getMessage());
            return BADREQUEST.handle(null);
        }

        try {
            switch (pm_executor.DeleteEntry(eport, proto, rhost)) {
                case 1:
                    break;
                case -1:
                    return NOTFOUND.handle(null);
                default:
                    return INTERNALSERVERERROR.handle(null);
            }
        } catch (IllegalArgumentException e) {
            log.error("remotehost is not a valid ip prefix.");
            log.error("{}", e.getMessage());
            return BADREQUEST.handle(null);
        }

        return buildResponse("", HttpResponseStatus.OK);
    }

    private FullHttpResponse handleNormalAddPortmapping(JSONObject request) {
        PortmappingEntry entry;
        try {
            entry = new PortmappingEntry(
                    request.getInt(json_tag_eport), request.getInt(json_tag_iport),
                    request.getString(json_tag_rhost), request.getString(json_tag_ihost),
                    request.getString(json_tag_proto).toLowerCase().equals("tcp") ? Protocol.TCP : Protocol.UDP,
                    request.getInt(json_tag_duration));
        } catch (JSONException e) {
            log.error("Fail to parse received json object of Post method.");
            log.error("{}", e.getMessage());
            return BADREQUEST.handle(null);
        } catch (IllegalArgumentException e) {
            log.error("Fail to build PortmappingEntry.");
            log.error("{}", e.getMessage());
            return BADREQUEST.handle(null);
        }

        return handleNormalAddPortmapping(entry);
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

    private FullHttpResponse handleAddAnyPortmapping(JSONObject request) {
        int eport;
        Protocol proto;
        JSONArray permit_port_range_jobj;
        ArrayList<portRange> permit_port_ranges;

        try {
            permit_port_range_jobj = request.getJSONArray(json_tag_permit_port_range);
            eport = request.getInt(json_tag_eport);
            proto = request.getString(json_tag_proto).toLowerCase().equals("tcp") ? Protocol.TCP : Protocol.UDP;

            permit_port_ranges = new ArrayList<portRange>(permit_port_range_jobj.length());
            permit_port_range_jobj.forEach(portrange -> {
                if (!(portrange instanceof JSONArray)) {
                    throw new JSONException("One of the entry of the allowed_port_range array is not an array.");
                }

                JSONArray range = (JSONArray) portrange;

                if (range.length() != 2) {
                    throw new JSONException("Array of allowed_port_range's entry has incorrect length.");
                }

                int min_port_num = range.getInt(0);
                int max_port_num = range.getInt(1);

                if (max_port_num < min_port_num
                    || !PortmappingExecutor.PortmappingEntry.isValidPortNubmer(max_port_num)
                    || !PortmappingExecutor.PortmappingEntry.isValidPortNubmer(min_port_num)) {
                    throw new JSONException("Invalid port range. Must between 0-65535." +
                        "And the first one must be the minimun port number.");
                }
                permit_port_ranges.add(new portRange(min_port_num, max_port_num));
            });
        } catch (JSONException e) {
            log.error("Fail to parse received json object of Post method.");
            log.error("{}", e.getMessage());
            return BADREQUEST.handle(null);
        }

        eport = findAvailablePort(eport, proto, permit_port_ranges);
        if (eport == -1) {
            return CONFLICT.handle(null);
        }

        PortmappingEntry entry;
        try {
            entry = new PortmappingEntry(
                    eport, request.getInt(json_tag_iport),
                    request.getString(json_tag_rhost), request.getString(json_tag_ihost),
                    proto, request.getInt(json_tag_duration));
        } catch (JSONException e) {
            log.error("Fail to parse received json object of Post method.");
            log.error("{}", e.getMessage());
            return BADREQUEST.handle(null);
        } catch (IllegalArgumentException e) {
            log.error("Fail to build PortmappingEntry.");
            log.error("{}", e.getMessage());
            return BADREQUEST.handle(null);
        }

        return handleNormalAddPortmapping(entry);
    }

    /**
     * This function will first check if the requested eport is available.
     * If it's available, return the requested port.
     * If not, the function will try to find another available port based on list provided.
     * @param eport requested eport.
     * @param proto requested protocol.
     * @param ranges allowed_port_range.
     * @return available ext_port. -1 if no such port found.
     */
    private int findAvailablePort(int eport, Protocol proto, ArrayList<portRange> ranges) {

        if (null == pm_executor.GetEntry(eport, proto)) {
            return eport;
        }

        for (portRange portRange : ranges) {
            for (int i = portRange.min_port; i <= portRange.max_port; i++) {
                if (null == pm_executor.GetEntry(i, proto)) {
                    return i;
                }
            }
        }

        return -1; //no available found.
    }

    private class portRange {
        private int min_port;
        private int max_port;

        protected portRange(int min_port, int max_port) {
            this.min_port = min_port;
            this.max_port = max_port;
        }

    }
}