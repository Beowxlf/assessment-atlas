# Existing tools and design references

Research checked against official documentation and vendor pages on October 12, 2026. This is a representative shortlist, not a complete market count, hands-on benchmark, pricing study, or proof of feature parity. None of these products was installed or tested for this project. Edition, version, configuration and access requirements may change capabilities.

The product goal is to combine useful discovery, topology, evidence and assessment-workflow capabilities in one original workspace. The interpretations below guide design research; they do not establish that other products lack those capabilities.

| Tool / source | Documented capability relevant to the concept | Design implication for Assessment Atlas |
| --- | --- | --- |
| [Nmap XML](https://nmap.org/book/output-formats-xml-output.html), [OS detection](https://nmap.org/book/osdetect-usage.html), [Zenmap topology](https://nmap.org/book/zenmap-topology.html) | XML exposes host/service/OS/trace data; OS output includes device/OS matches. Zenmap displays an interactive inventory and traceroute paths; an inventory can exist without traceroute data. | Use structured Nmap evidence to begin mapping. Attribute fingerprints and distinguish routed observations from physical connections. |
| [IVRE principles](https://doc.ivre.rocks/en/latest/overview/principles.html) | Separate scan, passive, consolidated-host and flow data models support network recon/cartography. | Study normalization and views while preserving per-observation provenance and identity uncertainty in our own model. |
| [NetBrain configuration/CLI import](https://www.netbrain.com/docs/12ne3wy0aw/help/HTML/import-configurations-and-cli-data.html) | Imports configurations and command data into device models and L3 topology; L2 topology is not built by default in this documented workflow. | Offline device-output import is a credible product path. Define exact supported inputs and relationship meanings rather than assume router access creates all topology. |
| [Faraday importing](https://docs.faradaysec.com/import/) | Adds vulnerabilities through manual entry, scan-report imports, supported tools, agents and APIs. | Study extensible intake and findings workflows; keep the common model broader than vulnerability aggregation. |
| [Dradis Nmap integration](https://dradis.com/integrations/nmap.html) | Nmap XML creates nodes/details and can be combined with assessment findings and reporting. | Study engagement organization and reports linked to device evidence. |
| [Netdisco](https://netdisco.org/) | Collects IP/MAC data through SNMP, CLI or APIs; supports inventory, historic data and network views. | Study management-source evidence and history; import/collection and device-changing capabilities require separate boundaries. |
| [LibreNMS network map](https://github.com/librenms/librenms/blob/master/doc/Extensions/Network-Map.md) | Dynamic maps use xDP discovery and MAC/ARP matching, with group/neighbor views for larger maps. | Preserve source-specific neighbor meaning and support focused graph views. |
| [runZero network map](https://help.runzero.com/docs/network-map/) | Provides query/filterable topology and path computation through the rendered graph. | Study exploration interactions; computed graph paths must remain distinct from actually tested reachability. |
| [SolarWinds Network Topology Mapper](https://documentation.solarwinds.com/en/success_center/ntm/content/ntm_what_is_solarwinds_network.htm) | Discovers nodes/connectivity using protocols including SNMP, WMI, LLDP, CDP, VMware management and ICMP. | Study heterogeneous collection; document which evidence supports each resulting link. |
| [Auvik network mapping](https://www.auvik.com/network-management-software/network-mapping-software/) | Vendor describes automatic physical/logical/routing views and discovery using neighbor protocols, ARP, forwarding, VLAN and routing data. | Treat vendor capability statements as research leads; validate mappings and export semantics in our own workflow. |
| [UVexplorer discovery](https://api.uvexplorer.com/uvexplorer-network-discovery) | Vendor describes SNMP/WMI/SSH discovery, device details, physical/logical connections, maps and reports. | Study discovery-to-map-to-report continuity without promising universal coverage. |

The originally supplied Dradis URL at `www.dradis.org` could not be retrieved during this check; the official `dradis.com` integration page above was retrieved instead.

## Original implementation and integrations

Capability inspiration is not permission to copy implementation, assets, fixtures or documentation. No package or code from this shortlist is included. Before adding a dependency or reusing material, record its exact version, origin, license/terms, notices, redistribution obligations and compatibility with the owner-selected product license. No license compatibility has been established here.

Prefer supported interchange formats and documented APIs where they fit the requirement. Review API authentication, rate limits, data permissions and contractual restrictions separately from source-code licensing. Integration must not silently transmit engagement evidence or turn an offline import into live discovery.

The shortlist does not justify a claim that this concept is unique, commercially validated or feasible at any given scale. A bounded first-workflow trial and adapter spikes will provide that evidence; see the [roadmap](roadmap.md).
