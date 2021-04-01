package nthu.wcislab.upnpigd.requesthandler;

public class OnosExecutor extends HttpMethodHandler {
    protected OnosAgent onos_agent;

    protected OnosExecutor(OnosAgent agent) {
        onos_agent = agent;
    }
}
