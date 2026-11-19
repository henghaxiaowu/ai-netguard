use std::net::Ipv4Addr;
use windows::Win32::Foundation::ERROR_OBJECT_ALREADY_EXISTS;
use windows::Win32::NetworkManagement::IpHelper::{
    CreateIpForwardEntry2, DeleteIpForwardEntry2, InitializeIpForwardEntry, MIB_IPFORWARD_ROW2,
};
use windows::Win32::Networking::WinSock::{AF_INET, IN_ADDR, IN_ADDR_0};

pub struct RouteManager {
    active_row: Option<MIB_IPFORWARD_ROW2>,
}

impl RouteManager {
    pub fn new() -> Self {
        Self { active_row: None }
    }

    pub fn set_bypass_route(
        &mut self,
        target_ip: &str,
        gateway_ip: &str,
        interface_index: u32,
    ) -> Result<(), String> {
        self.clear_bypass_route();

        let target: Ipv4Addr = target_ip
            .parse()
            .map_err(|_| format!("Invalid target IPv4: {target_ip}"))?;
        let gateway: Ipv4Addr = gateway_ip
            .parse()
            .map_err(|_| format!("Invalid gateway IPv4: {gateway_ip}"))?;

        unsafe {
            let mut row = std::mem::zeroed::<MIB_IPFORWARD_ROW2>();
            InitializeIpForwardEntry(&mut row);

            row.InterfaceIndex = interface_index;
            row.DestinationPrefix.Prefix.si_family = AF_INET;
            row.DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
            row.DestinationPrefix.Prefix.Ipv4.sin_addr = IN_ADDR {
                S_un: IN_ADDR_0 {
                    S_addr: u32::from_ne_bytes(target.octets()),
                },
            };
            row.DestinationPrefix.PrefixLength = 32;

            row.NextHop.si_family = AF_INET;
            row.NextHop.Ipv4.sin_family = AF_INET;
            row.NextHop.Ipv4.sin_addr = IN_ADDR {
                S_un: IN_ADDR_0 {
                    S_addr: u32::from_ne_bytes(gateway.octets()),
                },
            };
            row.Metric = 1;

            let status = CreateIpForwardEntry2(&row);
            if status.0 != 0 && status != ERROR_OBJECT_ALREADY_EXISTS {
                return Err(format!("CreateIpForwardEntry2 failed: {}", status.0));
            }

            self.active_row = Some(row);
            Ok(())
        }
    }

    pub fn clear_bypass_route(&mut self) {
        if let Some(row) = self.active_row.take() {
            unsafe {
                let _ = DeleteIpForwardEntry2(&row);
            }
        }
    }

    pub fn is_active(&self) -> bool {
        self.active_row.is_some()
    }
}

impl Drop for RouteManager {
    fn drop(&mut self) {
        self.clear_bypass_route();
    }
}
