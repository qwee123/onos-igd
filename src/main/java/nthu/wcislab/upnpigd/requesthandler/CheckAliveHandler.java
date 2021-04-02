package nthu.wcislab.upnpigd.requesthandler;

import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpResponseStatus;


public class CheckAliveHandler extends IfaceWatcher {

    public CheckAliveHandler(IfaceWatchable iface_watcher) {
        super(iface_watcher);
    }

    public FullHttpResponse handle(FullHttpRequest request) {
        return buildResponse("Alive", HttpResponseStatus.OK);
    }
}
