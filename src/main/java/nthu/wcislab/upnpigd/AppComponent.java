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
import org.onlab.packet.ARP;
import org.onlab.packet.Ip4Address;
import org.onosproject.core.CoreService;
import org.onosproject.core.ApplicationId;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;

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
    protected CoreService coreService;

    private ApplicationId appId;

    private final Logger log = LoggerFactory.getLogger(getClass());

    private IGDPacketProcessor processor = new IGDPacketProcessor();

    private HttpServer httpServer;

    @Activate
    protected void activate() {
        log.info("Activating...");
        appId = coreService.registerApplication("nthu.wcislab.upnpigd");

        packetService.addProcessor(processor, PacketProcessor.director(2));
        requestIntercepts();
        startServer();
        log.info("Started " + appId.id());
    }

    @Deactivate
    protected void deactivate() {
        withdrawIntercepts();
        flowRuleService.removeFlowRulesById(appId);
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

    private void startServer() {
        httpServer = new HttpServer(11426);
        try {
            httpServer.run();
        } catch (Exception e) {
            log.info("got exception {}", e);
        }
    }

    private void stopServer() {
        httpServer.stop();
    }

    private class IGDPacketProcessor implements PacketProcessor {

        @Override
        public void process(PacketContext packet) {

            InboundPacket pkt = packet.inPacket();
            ConnectPoint cp = pkt.receivedFrom();

            Ethernet frame = pkt.parsed();
            if (frame.getEtherType() != Ethernet.TYPE_ARP) {
                return;
            }

            ARP arp_packet = (ARP) frame.getPayload();
            if (arp_packet.getProtocolType() != ARP.PROTO_TYPE_IP) {
                return;
            }

            Ip4Address src_ip4 = Ip4Address.valueOf(arp_packet.getSenderProtocolAddress());
            log.info("Receive ARP packet: ");
            log.info("From switch: {}", cp.deviceId());
            log.info("Sent by:  ip4: {}", src_ip4);
        }
    }
}
