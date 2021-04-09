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

    private static String json_tag_auto = "autoselect"; // To distinquish AddAny and normal Add method
    private static String json_tag_return_code = "return_code";
    private static String json_tag_permit_port_range = "permit_port_range";
    private static String json_tag_permit_port_range_max = "max";
    private static String json_tag_permit_port_range_min = "min";

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
        boolean autoselect = false;

        try {
            autoselect = jobj.getBoolean(json_tag_auto);
        } catch (JSONException e) {
            log.error("Fail to parse received json object of Post method.");
            log.error("{}", e.getMessage());
            return BADREQUEST.handle(null);
        }

        if (autoselect) {
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
        int eport, max_port_num, min_port_num;
        Protocol proto;
        try {
            eport = request.getInt(json_tag_eport);
            proto = request.getString(json_tag_proto).toLowerCase().equals("tcp") ? Protocol.TCP : Protocol.UDP;
            JSONObject permit_range  = request.getJSONObject(json_tag_permit_port_range);
            max_port_num = permit_range.getInt(json_tag_permit_port_range_max);
            min_port_num = permit_range.getInt(json_tag_permit_port_range_min);
        } catch (JSONException e) {
            log.error("Fail to parse received json object of Post method.");
            log.error("{}", e.getMessage());
            return BADREQUEST.handle(null);
        }

        if (max_port_num < min_port_num
            || !PortmappingExecutor.PortmappingEntry.isValidPortNubmer(max_port_num)
            || !PortmappingExecutor.PortmappingEntry.isValidPortNubmer(min_port_num)) {
            log.error("Invalid port range. Must between 0-65535.");
            return BADREQUEST.handle(null);
        }

        eport = findAvailablePort(eport, proto, max_port_num, min_port_num);
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

    private int findAvailablePort(int eport, Protocol proto, int max, int min) {
        int offset = 1;
        boolean sign = false;
        while (null != pm_executor.GetEntry(eport, proto)) {
            eport += (sign ? offset : -1 * offset);
            sign = !sign;
            offset++;

            if (eport > max || eport < min) {
                break;
            }
        }

        if (eport > max) {
            eport += (sign ? offset : -1 * offset);
            while (eport >= min && null != pm_executor.GetEntry(eport, proto)) {
                eport--;
            }

            if (eport < min) {
                return -1;
            }
        } else if (eport < min) {
            eport += (sign ? offset : -1 * offset);
            while (eport <= max && null != pm_executor.GetEntry(eport, proto)) {
                eport++;
            }

            if (eport > max) {
                return -1;
            }
        }
        return eport;
    }
}