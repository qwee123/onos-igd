package nthu.wcislab.upnpigd.requesthandler;

import nthu.wcislab.upnpigd.portmapping.PortmappingExecutor;

public class PortmappingHandler extends HttpMethodHandler {
    protected PortmappingExecutor pm_executor;

    protected PortmappingHandler(PortmappingExecutor pm_executor) {
        this.pm_executor = pm_executor;
    }
}
