use iroh::{Endpoint, address_lookup::AddrFilter};
use iroh_mdns_address_lookup::MdnsAddressLookup;
use tracing::{info, warn};

pub(super) fn attach_local_discovery(endpoint: &Endpoint, enabled: bool) -> bool {
    if !enabled {
        info!("local discovery disabled");
        return false;
    }
    let services = match endpoint.address_lookup() {
        Ok(services) => services,
        Err(error) => {
            warn!(error = %error, "unable to attach local discovery; continuing without it");
            return false;
        }
    };
    match MdnsAddressLookup::builder()
        .service_name("syncbox")
        .addr_filter(AddrFilter::ip_only())
        .build(endpoint.id())
    {
        Ok(service) => {
            services.add(service);
            info!("local discovery enabled");
            true
        }
        Err(error) => {
            warn!(error = %error, "unable to start local discovery; continuing without it");
            false
        }
    }
}
