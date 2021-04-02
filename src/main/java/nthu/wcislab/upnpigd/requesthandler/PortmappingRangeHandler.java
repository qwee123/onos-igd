package nthu.wcislab.upnpigd.requesthandler;

import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpResponseStatus;
import org.json.JSONObject;

import nthu.wcislab.upnpigd.portmapping.PortmappingExecutor;

public class PortmappingRangeHandler extends PortmappingHandler {

    public PortmappingRangeHandler(PortmappingExecutor pm_executor) {
        super(pm_executor);
    }

    @Override
    protected FullHttpResponse handleGet(FullHttpRequest request) {
        return null;
    }

}
