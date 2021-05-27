/*
 * Copyright 2021-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package nthu.wcislab.upnpigd;

import org.onosproject.cfg.ComponentConfigService;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.onlab.packet.Ethernet;
import org.onlab.packet.IPv4;
import org.onlab.packet.ARP;
import org.onlab.packet.IpAddress;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.IpPrefix;
import org.onlab.packet.MacAddress;
import org.onlab.packet.TCP;
import org.onlab.packet.TpPort;
import org.onlab.packet.UDP;
import org.onosproject.core.CoreService;
import org.onosproject.core.ApplicationId;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.DeviceId;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.device.PortStatistics;
import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleEvent;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.FlowRuleListener;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.FlowRule.FlowRemoveReason;
import org.onosproject.net.flow.criteria.Criterion.Type;
import org.onosproject.net.host.HostService;
import org.onosproject.net.Host;
import org.onosproject.net.Path;
import org.onosproject.net.topology.PathService;
import org.onosproject.net.Port;
import org.onosproject.net.PortNumber;
import org.onosproject.net.packet.DefaultOutboundPacket;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.Link;

import java.util.Random;
import java.util.Set;
import java.util.List;
import java.nio.ByteBuffer;

import nthu.wcislab.upnpigd.portmapping.DatapathExecutable;
import nthu.wcislab.upnpigd.portmapping.PortmappingExecutor;
import nthu.wcislab.upnpigd.portmapping.PortmappingExecutor.PortmappingEntry;
import nthu.wcislab.upnpigd.portmapping.PortmappingExecutor.PortmappingEntry.Protocol;
import nthu.wcislab.upnpigd.portmapping.PortmappingExecutor.PortmappingEntry.RemoteHostDetail;
import nthu.wcislab.upnpigd.requesthandler.IfaceWatchable;
import nthu.wcislab.upnpigd.requesthandler.StatsHandler.InterfaceHandler.InterfaceStats;

/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true)

public class AppComponent {

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected ComponentConfigService cfgService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected DeviceService deviceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected HostService hostService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PathService pathService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    private ApplicationId appId;

    private final Logger log = LoggerFactory.getLogger(getClass());

    private IGDPacketProcessor processor = new IGDPacketProcessor();

    private HttpServer httpServer;

    private PortmappingProcessor portmappingProcessor;
    private OPFIfaceWatcher ifaceWatcher;
    private PortmappingExecutor portmappingExecutor;
    private IGDFlowRuleListener flowRuleListener = new IGDFlowRuleListener();

    /**
     * Device_id and ext_iface_name should be filled in by onos-cfg.
     * publicAddress and privateAddress should also be filled by config.
     * Belowings are just some temporarily setup, or default config.
     */
    private final DeviceId igd_device_id = DeviceId.deviceId("of:000012bf6e85b74f");
    private final String igd_ext_iface_name = "wan1";
    private final Ip4Address igd_ext_ipaddr = Ip4Address.valueOf("192.168.1.10"); //public address
    private final int idle_timeout = 10;
    private final Ip4Address privateIPaddr = Ip4Address.valueOf("172.16.0.1");
    private final MacAddress privateMac = MacAddress.valueOf(randomMACAddress());
    private final MacAddress publicMac = MacAddress.valueOf(randomMACAddress());
    private final int public_arp_intercept_priority = PacketPriority.HIGH1.priorityValue();
    private final int nat_intercept_priority = PacketPriority.HIGH1.priorityValue();
    private final int nat_redirect_priority = PacketPriority.HIGH2.priorityValue();
    private final int http_port = 40000;

    //should be the same with fwd app, set to 30000 in default
    private final int internal_forward_priority = PacketPriority.MEDIUM.priorityValue();

    private PortNumber igd_ext_port;

    @Activate
    protected void activate() {
        log.info("Activating...");
        appId = coreService.registerApplication("nthu.wcislab.upnpigd");

        packetService.addProcessor(processor, PacketProcessor.director(2));
        flowRuleService.addListener(flowRuleListener);

        log.info("External Mac: {}", publicMac.toString());
        log.info("Internal Mac: {}", privateMac.toString());
        try {
            init();
            requestIntercepts();

            startServer();
            log.info("Started " + appId.id());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Deactivate
    protected void deactivate() {
        withdrawIntercepts();
        flowRuleService.removeFlowRulesById(appId);
        flowRuleService.removeListener(flowRuleListener);
        packetService.removeProcessor(processor);
        processor = null;
        stopServer();
        log.info("Stopped");
    }

    private void requestIntercepts() {
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_ARP);
        packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);
    }

    private void withdrawIntercepts() {
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_ARP);
        packetService.cancelPackets(selector.build(), PacketPriority.REACTIVE, appId);
    }

    private void init() {
        List<Port> port_list = deviceService.getPorts(igd_device_id);

        for (Port port : port_list) {
            if (port.annotations().value("portName").equals(igd_ext_iface_name)) {
                igd_ext_port = port.number();
                log.info("External IGD port detected:\n{}", port.toString());
                break;
            }
        }

        if (igd_ext_port == null) {
            log.error("External IGD port with name {} is not found." +
             "Please check your network topology and then restart the app", igd_ext_iface_name);
             throw new NullPointerException("No IGD external interface found.");
        }

        portmappingProcessor = new PortmappingProcessor();
        ifaceWatcher = new OPFIfaceWatcher();
        portmappingExecutor = new PortmappingExecutor(portmappingProcessor);

        // Drop all packet coming from WAN
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder()
            .matchInPort(igd_ext_port);
        TrafficTreatment.Builder treatment = DefaultTrafficTreatment.builder()
            .drop();
        writeFlowRule(igd_device_id, selector, treatment, PacketPriority.HIGH.priorityValue(), 0, false);

        //But permit arp request for the public interface
        selector.matchEthType(Ethernet.TYPE_ARP)
            .matchArpTpa(igd_ext_ipaddr);
        treatment = DefaultTrafficTreatment.builder()
            .setOutput(PortNumber.CONTROLLER);
        writeFlowRule(igd_device_id, selector, treatment, public_arp_intercept_priority, 0, false);
    }

    private void startServer() {
        httpServer = new HttpServer(http_port);
        try {
            httpServer.run(ifaceWatcher, portmappingExecutor);
        } catch (Exception e) {
            log.info("got exception {}", e);
        }
    }

    private void stopServer() {
        httpServer.stop();
    }

    public void writeFlowRule(DeviceId deviceId, TrafficSelector.Builder selector,
    TrafficTreatment.Builder treatment, int priority, int timeout, boolean idle) {
        if (idle) {
            writeFlowRule(deviceId, selector, treatment, priority, timeout, idle, FlowRemoveReason.IDLE_TIMEOUT);
        } else {
            writeFlowRule(deviceId, selector, treatment, priority, timeout, idle, FlowRemoveReason.NO_REASON);
        }
    }

    public void writeFlowRule(DeviceId deviceId, TrafficSelector.Builder selector,
            TrafficTreatment.Builder treatment, int priority, int timeout, boolean idle, FlowRemoveReason reason) {
        FlowRule.Builder rule_builder = DefaultFlowRule.builder()
            .withSelector(selector.build())
            .withTreatment(treatment.build())
            .withPriority(priority)
            .forDevice(deviceId)
            .fromApp(appId);

        if (idle) { //0 is seen as permanant in idleTimeout function
            rule_builder.withIdleTimeout(timeout);
        } else if (timeout == 0) {
            rule_builder.makePermanent();
        } else {
            rule_builder.makeTemporary(timeout);
        }

        if (!reason.equals(FlowRemoveReason.NO_REASON)) {
            rule_builder.withReason(reason);
        }

        flowRuleService.applyFlowRules(rule_builder.build());
    }

    private class IGDFlowRuleListener implements FlowRuleListener {
        private final String TCP = String.valueOf((int) IPv4.PROTOCOL_TCP);
        private final String UDP = String.valueOf((int) IPv4.PROTOCOL_UDP);

        public void event(FlowRuleEvent event) {
            if (event.subject().appId() != appId.id()) {
                return;
            }

            FlowRule rule = event.subject();

            switch (event.type()) {
                case RULE_ADDED:
                    //log.info("Flow added: {}", rule.toString());
                    return;
                case RULE_REMOVED:
                    FlowRemoveReason reason = rule.reason();
                    switch (reason) {
                        case NO_REASON: //triggered by onos timeout mechanism
                            try {
                                handleFlowRemoved(rule);
                            } catch (IllegalArgumentException e) {
                                log.error("Fail to remove flow {}", rule.toString());
                            }
                            break;
                        case DELETE: //triggered by delete method.
                            log.info("Flow removed: {}", rule.toString());
                            break;
                        case IDLE_TIMEOUT:
                            break;
                        default :
                            log.warn("Unknown flow removed reason :{}", reason.toString());
                            break;
                    }
                    return;
                default:
                    return;
            }
        }

        private void handleFlowRemoved(FlowRule rule) throws IllegalArgumentException {
            Criterion proto_cri, eport_cri, rhost_cri;
            String proto_str, rhost;
            int eport;
            Protocol proto;

            proto_cri = rule.selector().getCriterion(Type.IP_PROTO);
            if (proto_cri == null) {
                log.error("Got unusaual deleted rule: {}. No IP_PROTO found.", rule.toString());
                return;
            }

            proto_str = extractCriterionValue(proto_cri);
            if (proto_str.equals(TCP)) {
                eport_cri = rule.selector().getCriterion(Type.TCP_DST);
                proto = Protocol.TCP;
            } else if (proto_str.equals(UDP)) {
                eport_cri = rule.selector().getCriterion(Type.UDP_DST);
                proto = Protocol.UDP;
            } else {
                log.error("Got unusaual deleted rule: {}. IP_PROTO is neither TCP nor UDP.", rule.toString());
                return;
            }

            if (eport_cri == null) {
                log.error("Got unusaual deleted rule: {}. No EXT_PORT found.", rule.toString());
                return;
            }

            eport = Integer.parseInt(extractCriterionValue(eport_cri));

            rhost_cri = rule.selector().getCriterion(Type.IPV4_SRC);
            if (rhost_cri == null) {
                rhost = "0.0.0.0/0";
            } else {
                rhost = extractCriterionValue(rhost_cri);
            }

            portmappingExecutor.HandleDatapathTimeout(eport, proto, rhost);
            log.info("Flow removed: {}", rule.toString());
        }

        /**
         * Extract Criterion value.
         * @param cri Criterion to be parsed. It should be in format "[tag]:[value]"
         * @return value in type string. Empty string will be returned if fail to extract the value.
         */
        private String extractCriterionValue(Criterion cri) throws IllegalArgumentException {
            try {
                return cri.toString().split(Criterion.SEPARATOR)[1];
            } catch (IndexOutOfBoundsException e) {
                log.error("Fail to extract Criterion value," +
                    " or the criterion does not comply the format [tag]:[value]" +
                    "Got Criterion : {}", cri.toString());
                throw new IllegalArgumentException();
            }
        }
    }

    private class PortmappingProcessor implements DatapathExecutable {

        public boolean UpdateRuleForEntry(PortmappingEntry entry, RemoteHostDetail rhost) {
            return AddRuleForEntry(entry, rhost);
        }

        public boolean AddRuleForEntry(PortmappingEntry entry, RemoteHostDetail rhost) {
            //Check if the internal host exist.
            if (hostService.getHostsByIp(entry.GetInternalHostByIpAddress()).isEmpty()) {
                log.info("Requested internal host does not exist in the LAN.");
                return false;
            }

            TrafficSelector.Builder selector = setInterceptMatchRule(entry, rhost);
            TrafficTreatment.Builder treatment = DefaultTrafficTreatment.builder()
                .setOutput(PortNumber.CONTROLLER);

            int priority = nat_intercept_priority + rhost.GetRhostByIpPrefix().prefixLength();
            writeFlowRule(igd_device_id, selector, treatment, priority, rhost.GetLeaseDuration(), false);
            return true;
        }

        public boolean DeleteRuleForEntry(PortmappingEntry entry, RemoteHostDetail rhost) {
            TrafficSelector.Builder selector = setInterceptMatchRule(entry, rhost);

            int priority = nat_intercept_priority + rhost.GetRhostByIpPrefix().prefixLength();
            FlowRule rule = DefaultFlowRule.builder()
                .withSelector(selector.build())
                .forDevice(igd_device_id)
                .makeTemporary(0)
                .withReason(FlowRemoveReason.DELETE)
                .withPriority(priority)
                .fromApp(appId)
                .build();
            flowRuleService.removeFlowRules(rule);

            return true;
        }

        private TrafficSelector.Builder setInterceptMatchRule(PortmappingEntry entry, RemoteHostDetail rhost) {
            TrafficSelector.Builder selector = DefaultTrafficSelector.builder();

            selector.matchInPort(igd_ext_port)
                .matchEthType(Ethernet.TYPE_IPV4)
                .matchIPDst(igd_ext_ipaddr.toIpPrefix());

            IpPrefix rhost_prefix = rhost.GetRhostByIpPrefix();
            if (!rhost_prefix.equals(IpPrefix.valueOf("0.0.0.0/0"))) {
                selector.matchIPSrc(rhost_prefix);
            }

            if (entry.GetProtocol() == Protocol.TCP) {
                selector.matchIPProtocol(IPv4.PROTOCOL_TCP);
                selector.matchTcpDst(TpPort.tpPort(entry.GetExternalPort()));
            } else {
                selector.matchIPProtocol(IPv4.PROTOCOL_UDP);
                selector.matchUdpDst(TpPort.tpPort(entry.GetExternalPort()));
            }

            return selector;
        }
    }

    private class OPFIfaceWatcher implements IfaceWatchable {
        public InterfaceStats GetIGDExtIfaceStats() {
            Port port = deviceService.getPort(igd_device_id, igd_ext_port);
            PortStatistics stats = deviceService.getStatisticsForPort(igd_device_id, igd_ext_port);

            InterfaceStats ret = new InterfaceStats();
            ret.iface_status = port.isEnabled();
            ret.obytes = stats.bytesSent();
            ret.ibytes = stats.bytesReceived();
            ret.opackets = stats.packetsSent();
            ret.ipackets = stats.packetsReceived();

            /*
            Baud rate is not bit rate. Two values will be identical only if the interface
            transmits siganls only through two symbol(0, 1), so each cycle(?) of modulation
            only contains one bit.

            Anyway, use bitrate instead for now.
            */
            ret.baudrate = port.portSpeed();

            return ret;
        }

        public String GetIGDExtAddr() {
            return igd_ext_ipaddr.toString();
        }

        public String GetIGDDeviceID() {
            return igd_device_id.toString();
        }
    }

    private class IGDPacketProcessor implements PacketProcessor {

        @Override
        public void process(PacketContext packet) {

            InboundPacket pkt = packet.inPacket();
            ConnectPoint cp = pkt.receivedFrom();

            Ethernet frame = pkt.parsed();
            if (frame == null) {
                return;
            }

            MacAddress src_mac = frame.getSourceMAC();

            if (frame.getEtherType() == Ethernet.TYPE_ARP) {
                ARP arp = (ARP) frame.getPayload();
                log.debug(arp.toString());
                if (arp.getOpCode() == ARP.OP_REQUEST) {
                    processARPRequest(frame, arp, cp);
                }
                return;
            }

            if (!(frame.getEtherType() == Ethernet.TYPE_IPV4)) {
                return;
            }

            if (!cp.deviceId().equals(igd_device_id)) {
                log.debug("Got ip packet inside LAN\nDevice: {}\nFrame: {}", cp.toString(), frame.toString());
                return;
            }

            IPv4 ip_payload = (IPv4) frame.getPayload();
            Ip4Address src_addr = Ip4Address.valueOf(ip_payload.getSourceAddress());
            Ip4Address dst_addr = Ip4Address.valueOf(ip_payload.getDestinationAddress());

            if (!dst_addr.equals(igd_ext_ipaddr)) {
                log.debug("Got ip packet with invalid dst ip address.\nPacket: {}", ip_payload.toString());
                return;
            }

            byte protocol = ip_payload.getProtocol();
            Protocol pm_proto;
            int src_port, dst_port;
            if (protocol == IPv4.PROTOCOL_TCP) {
                TCP tcp_payload = (TCP) ip_payload.getPayload();
                pm_proto = Protocol.TCP;
                src_port = tcp_payload.getSourcePort();
                dst_port = tcp_payload.getDestinationPort();
            } else if (protocol == IPv4.PROTOCOL_UDP) {
                UDP udp_payload = (UDP) ip_payload.getPayload();
                pm_proto = Protocol.UDP;
                src_port = udp_payload.getSourcePort();
                dst_port = udp_payload.getDestinationPort();
            } else {
                return;
            }

            PortmappingEntry entry = portmappingExecutor.GetEntry(dst_port, pm_proto);
            if (entry == null) {
                return;
            }
            RemoteHostDetail rhost = entry.GetLongestCoveringRhost(src_addr);
            if (rhost == null) {
                return;
            }

            IpAddress ihost_addr = entry.GetInternalHostByIpAddress();

            Set<Host> hosts = hostService.getHostsByIp(ihost_addr);
            if (hosts.isEmpty()) {
                log.error("No internal host with such ip4 address: {}", ihost_addr.toString());
                return;
            } else if (hosts.size() != 1) {
                log.warn("Multiple internal host with the same ip address: {}.\n" +
                    "However, Only one of them would get redirect.", ihost_addr.toString());
            }
            Host host = hosts.iterator().next(); //only get one host

            Set<Path> paths = pathService.getPaths(igd_device_id, host.id());
            if (paths.isEmpty()) {
                log.error("No available path found between IGD and internal host : {}", host.toString());
                return;
            }

            Path path = paths.iterator().next();
            PortNumber in_port = igd_ext_port;
            PortNumber packetOut_port = PortNumber.FLOOD;
            for (Link link : path.links()) {
                if (link.src().deviceId().equals(igd_device_id)) {
                    setNATRoute(igd_device_id, in_port, link.src().port(),
                            src_mac, host.mac(), src_addr, src_port, entry, rhost.GetLeaseDuration());
                    packetOut_port = link.src().port();
                } else {
                    setInternalRoute(link.src().deviceId(), in_port,
                            link.src().port(), privateMac, host.mac(), rhost.GetLeaseDuration());
                }

                in_port = link.dst().port();
            }

            TrafficTreatment.Builder action = DefaultTrafficTreatment.builder()
                .setEthSrc(privateMac)
                .setEthDst(host.mac())
                .setIpDst(ihost_addr);

            TpPort ihost_port = TpPort.tpPort(entry.GetInternalPort());
            if (entry.GetProtocol() == Protocol.TCP) {
                action.setTcpDst(ihost_port);
            } else {
                action.setUdpDst(ihost_port);
            }

            action.setOutput(packetOut_port);
            packetService.emit(new DefaultOutboundPacket(
                cp.deviceId(),
                action.build(),
                ByteBuffer.wrap(frame.serialize())
            ));
        }

        private void processARPRequest(Ethernet eth_frame, ARP req, ConnectPoint cp) {

            Ip4Address target_addr = Ip4Address.valueOf(req.getTargetProtocolAddress());
            PortNumber in_port = cp.port();

            Ethernet reply;
            if (target_addr.equals(privateIPaddr) &&
                (!cp.deviceId().equals(igd_device_id) || !in_port.equals(igd_ext_port))) {
                //only accept private request from inner port of igd, accept all if from other device
                reply = ARP.buildArpReply(privateIPaddr, privateMac, eth_frame);
            } else if (target_addr.equals(igd_ext_ipaddr) &&
                cp.deviceId().equals(igd_device_id) && in_port.equals(igd_ext_port)) {
                //only accept public request from ext port of igd, accept all if from other device
                reply = ARP.buildArpReply(igd_ext_ipaddr, publicMac, eth_frame);
            } else {
                return;
            }

            TrafficTreatment.Builder action = DefaultTrafficTreatment.builder();
            action.setOutput(in_port);
            packetService.emit(new DefaultOutboundPacket(
              cp.deviceId(),
              action.build(),
              ByteBuffer.wrap(reply.serialize())
            ));
        }

        private void setNATRoute(DeviceId device_id, PortNumber in_port, PortNumber out_port,
                        MacAddress rhost_mac, MacAddress ihost_mac,
                        IpAddress rhost_addr, int rhost_sport,
                        PortmappingEntry entry, int nat_timeout) {
            int timeout = nat_timeout < idle_timeout ? nat_timeout : idle_timeout;

            IpAddress ihost_addr = entry.GetInternalHostByIpAddress();
            TpPort ihost_port = TpPort.tpPort(entry.GetInternalPort());

            //Set Inbound rule
            TrafficSelector.Builder selector = DefaultTrafficSelector.builder()
                .matchInPort(in_port)
                .matchEthType(Ethernet.TYPE_IPV4)
                .matchIPSrc(rhost_addr.toIpPrefix())
                .matchIPDst(igd_ext_ipaddr.toIpPrefix());

            TrafficTreatment.Builder treatment = DefaultTrafficTreatment.builder()
                .setEthSrc(privateMac)
                .setEthDst(ihost_mac)
                .setIpDst(ihost_addr);

            int eport = entry.GetExternalPort();
            if (entry.GetProtocol() == Protocol.TCP) {
                selector.matchIPProtocol(IPv4.PROTOCOL_TCP)
                        .matchTcpDst(TpPort.tpPort(eport));
                //        .matchTcpSrc(TpPort.tpPort(rhost_sport));

                treatment.setTcpDst(ihost_port);
            } else {
                selector.matchIPProtocol(IPv4.PROTOCOL_UDP)
                        .matchUdpDst(TpPort.tpPort(eport));
                //        .matchUdpSrc(TpPort.tpPort(rhost_sport));

                treatment.setUdpDst(ihost_port);
            }

            treatment.setOutput(out_port);

            writeFlowRule(device_id, selector, treatment, nat_redirect_priority, timeout, true);

            //Set Outbound rule
            selector = DefaultTrafficSelector.builder()
                .matchInPort(out_port)
                .matchEthType(Ethernet.TYPE_IPV4)
                .matchIPSrc(ihost_addr.toIpPrefix())
                .matchIPDst(rhost_addr.toIpPrefix());

            treatment = DefaultTrafficTreatment.builder()
                .setEthSrc(publicMac)
                .setEthDst(rhost_mac)
                .setIpSrc(igd_ext_ipaddr);

            if (entry.GetProtocol() == Protocol.TCP) {
                selector.matchIPProtocol(IPv4.PROTOCOL_TCP)
                        .matchTcpSrc(ihost_port);
                //        .matchTcpDst(TpPort.tpPort(rhost_sport));

                treatment.setTcpSrc(TpPort.tpPort(eport));
            } else {
                selector.matchIPProtocol(IPv4.PROTOCOL_UDP)
                        .matchUdpSrc(ihost_port);
                //        .matchUdpDst(TpPort.tpPort(rhost_sport));

                treatment.setUdpSrc(TpPort.tpPort(eport));
            }

            treatment.setOutput(in_port);

            writeFlowRule(device_id, selector, treatment, nat_redirect_priority, timeout, true);
        }

        private void setInternalRoute(DeviceId device_id, PortNumber in_port,
                        PortNumber out_port, MacAddress src_mac, MacAddress dst_mac, int nat_timeout) {
            int timeout = nat_timeout < idle_timeout ? nat_timeout : idle_timeout;
            //Set Inbound rules
            TrafficSelector.Builder selector = DefaultTrafficSelector.builder()
                .matchInPort(in_port)
                .matchEthSrc(src_mac)
                .matchEthDst(dst_mac);

            TrafficTreatment.Builder treatment = DefaultTrafficTreatment.builder()
                .setOutput(out_port);

            writeFlowRule(device_id, selector, treatment, internal_forward_priority, timeout, true);

            //Set Outbound rules
            selector = DefaultTrafficSelector.builder()
                .matchInPort(out_port)
                .matchEthSrc(dst_mac)
                .matchEthDst(src_mac);

            treatment = DefaultTrafficTreatment.builder()
                .setOutput(in_port);

            writeFlowRule(device_id, selector, treatment, internal_forward_priority, timeout, true);
        }
    }

    private String randomMACAddress() {
        Random rand = new Random();
        byte[] macAddr = new byte[6];
        rand.nextBytes(macAddr);

        //zeroing last 2 bytes to make it unicast and locally adminstrated
        macAddr[0] = (byte) (macAddr[0] & (byte) 254);

        StringBuilder sb = new StringBuilder(18);
        for (byte b : macAddr) {

            if (sb.length() > 0) {
                sb.append(":");
            }

            sb.append(String.format("%02x", b));
        }

        return sb.toString();
    }
}
