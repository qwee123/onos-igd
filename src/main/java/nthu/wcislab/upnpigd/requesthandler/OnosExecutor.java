package nthu.wcislab.upnpigd.requesthandler;

import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpResponseStatus;

public abstract class OnosExecutor extends AbstractRequestHandler {
    protected OnosAgent onos_agent;

    protected OnosExecutor(OnosAgent agent) {
        onos_agent = agent;
    }

    @Override
    protected FullHttpResponse buildResponse(String content, HttpResponseStatus status) {
        return super.buildResponse(content, status);
    }
}
