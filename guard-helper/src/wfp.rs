use guard_protocol::ProtectedTarget;
use std::ffi::c_void;
use std::path::Path;
use windows::core::{GUID, PCWSTR, PWSTR};
use windows::Win32::Foundation::{ERROR_SUCCESS, FWP_E_ALREADY_EXISTS, HANDLE};
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmFilterCreateEnumHandle0,
    FwpmFilterDeleteById0, FwpmFilterDestroyEnumHandle0, FwpmFilterEnum0, FwpmFilterGetById0,
    FwpmFreeMemory0, FwpmGetAppIdFromFileName0, FwpmProviderAdd0, FwpmProviderDeleteByKey0,
    FwpmSubLayerAdd0, FwpmSubLayerDeleteByKey0, FwpmTransactionAbort0, FwpmTransactionBegin0,
    FwpmTransactionCommit0, FWPM_CONDITION_ALE_APP_ID, FWPM_CONDITION_FLAGS,
    FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_CONDITION_IP_REMOTE_PORT, FWPM_FILTER0,
    FWPM_FILTER_CONDITION0, FWPM_FILTER_FLAG_PERSISTENT, FWPM_LAYER_ALE_AUTH_CONNECT_V4,
    FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_PROVIDER0, FWPM_PROVIDER_FLAG_PERSISTENT, FWPM_SESSION0,
    FWPM_SESSION_FLAG_DYNAMIC, FWPM_SUBLAYER0, FWPM_SUBLAYER_FLAG_PERSISTENT, FWP_ACTION_BLOCK,
    FWP_ACTION_PERMIT, FWP_BYTE_BLOB, FWP_BYTE_BLOB_TYPE, FWP_CONDITION_FLAG_IS_LOOPBACK,
    FWP_MATCH_EQUAL, FWP_MATCH_FLAGS_ALL_SET, FWP_MATCH_RANGE, FWP_RANGE0, FWP_RANGE_TYPE,
    FWP_UINT16, FWP_UINT32, FWP_UINT8, FWP_V4_ADDR_AND_MASK, FWP_V4_ADDR_MASK, FWP_VALUE0,
};
use windows::Win32::System::Rpc::RPC_C_AUTHN_DEFAULT;

// Dynamic runtime sublayer (auto-cleaned on process exit/crash)
const SUBLAYER_GUID: GUID = GUID::from_u128(0x6f4e7e41_1d2c_4a84_a31b_8e77d2f59b01);

// Persistent offline lock provider & sublayer (survives NetGuard exit & Windows reboot)
const PERSISTENT_PROVIDER_GUID: GUID = GUID::from_u128(0x7d8a1102_4b39_4e51_9c22_1f8a9c30e001);
const PERSISTENT_SUBLAYER_GUID: GUID = GUID::from_u128(0x7d8a1102_4b39_4e51_9c22_1f8a9c30e002);

pub struct WfpManager {
    engine: HANDLE,
    active_filter_ids: Vec<u64>,
    locked_paths: Vec<String>,
    persistent_filter_count: usize,
    persistent_targets: Vec<ProtectedTarget>,
}

impl WfpManager {
    pub fn new() -> Result<Self, String> {
        unsafe {
            let mut session = FWPM_SESSION0::default();
            session.flags = FWPM_SESSION_FLAG_DYNAMIC;
            let mut name_u16 = to_wide("AI-NetGuard Dynamic WFP Session");
            session.displayData.name = PWSTR(name_u16.as_mut_ptr());

            let mut engine = HANDLE::default();
            let status = FwpmEngineOpen0(
                PCWSTR::null(),
                RPC_C_AUTHN_DEFAULT as u32,
                None,
                Some(&session),
                &mut engine,
            );
            if status != ERROR_SUCCESS.0 {
                return Err(format!("FwpmEngineOpen0 failed: 0x{status:08X}"));
            }

            let mut sublayer = FWPM_SUBLAYER0::default();
            sublayer.subLayerKey = SUBLAYER_GUID;
            let mut sl_name = to_wide("AI-NetGuard Zero-Leak Sublayer");
            let mut sl_desc = to_wide("Enforces loopback-only egress for isolated AI clients");
            sublayer.displayData.name = PWSTR(sl_name.as_mut_ptr());
            sublayer.displayData.description = PWSTR(sl_desc.as_mut_ptr());
            sublayer.weight = 0xFFFF;

            let sl_status = FwpmSubLayerAdd0(engine, &sublayer, None);
            if sl_status != ERROR_SUCCESS.0 && sl_status != FWP_E_ALREADY_EXISTS.0 as u32 {
                let _ = FwpmEngineClose0(engine);
                return Err(format!("FwpmSubLayerAdd0 failed: 0x{sl_status:08X}"));
            }

            let persistent_count = count_persistent_filters_internal().unwrap_or(0);

            Ok(Self {
                engine,
                active_filter_ids: Vec::new(),
                locked_paths: Vec::new(),
                persistent_filter_count: persistent_count,
                persistent_targets: Vec::new(),
            })
        }
    }

    pub fn apply_lock(&mut self, targets: &[ProtectedTarget]) -> Result<(), String> {
        let valid_targets = filter_existing_targets(targets);
        if valid_targets.is_empty() {
            return self.clear_lock();
        }

        // Atomic refresh: delete old filters AND insert new filters in the same BFE transaction.
        // If anything fails before commit completes, abort rolls back deletions so old locks stay active.
        unsafe {
            let tx = FwpmTransactionBegin0(self.engine, 0);
            if tx != ERROR_SUCCESS.0 {
                return Err(format!("FwpmTransactionBegin0 failed: 0x{tx:08X}"));
            }

            let mut added_ids = Vec::new();
            let result = (|| -> Result<(), String> {
                for &old_id in &self.active_filter_ids {
                    let _ = FwpmFilterDeleteById0(self.engine, old_id);
                }
                for target in &valid_targets {
                    let app_blob = get_app_id(&target.exe_path)?;
                    let res = add_app_filters(
                        self.engine,
                        SUBLAYER_GUID,
                        None,
                        false,
                        app_blob,
                        target.allow_private_lan,
                        &target.allowed_loopback_ports,
                        &target.allowed_loopback_port_ranges,
                        &mut added_ids,
                    );
                    FwpmFreeMemory0(&mut (app_blob as *mut c_void));
                    res?;
                }
                Ok(())
            })();

            if let Err(err) = result {
                let _ = FwpmTransactionAbort0(self.engine);
                return Err(err);
            }

            let commit = FwpmTransactionCommit0(self.engine);
            if commit != ERROR_SUCCESS.0 {
                let _ = FwpmTransactionAbort0(self.engine);
                return Err(format!("FwpmTransactionCommit0 failed: 0x{commit:08X}"));
            }

            self.active_filter_ids = added_ids;
            self.locked_paths = valid_targets.into_iter().map(|t| t.exe_path).collect();
            Ok(())
        }
    }

    pub fn clear_lock(&mut self) -> Result<(), String> {
        if self.active_filter_ids.is_empty() {
            self.locked_paths.clear();
            return Ok(());
        }
        unsafe {
            let tx = FwpmTransactionBegin0(self.engine, 0);
            if tx != ERROR_SUCCESS.0 {
                return Err(format!("FwpmTransactionBegin0 failed: 0x{tx:08X}"));
            }
            for id in self.active_filter_ids.drain(..) {
                let _ = FwpmFilterDeleteById0(self.engine, id);
            }
            let _ = FwpmTransactionCommit0(self.engine);
        }
        self.locked_paths.clear();
        Ok(())
    }

    pub fn install_persistent_lock(&mut self, targets: &[ProtectedTarget]) -> Result<(), String> {
        let valid_targets = filter_existing_targets(targets);
        if valid_targets.is_empty() {
            return Err("未找到需要持久锁定的 Claude Desktop 可执行文件".into());
        }

        unsafe {
            let p_engine = open_persistent_engine()?;
            let res = (|| -> Result<usize, String> {
                let tx = FwpmTransactionBegin0(p_engine, 0);
                if tx != ERROR_SUCCESS.0 {
                    return Err(format!("FwpmTransactionBegin0 failed: 0x{tx:08X}"));
                }

                let inner = (|| -> Result<usize, String> {
                    let mut provider = FWPM_PROVIDER0::default();
                    provider.providerKey = PERSISTENT_PROVIDER_GUID;
                    let mut p_name = to_wide("AI-NetGuard Offline Guard Provider");
                    let mut p_desc = to_wide("Blocks Claude Desktop unless AI NetGuard is active");
                    provider.displayData.name = PWSTR(p_name.as_mut_ptr());
                    provider.displayData.description = PWSTR(p_desc.as_mut_ptr());
                    provider.flags = FWPM_PROVIDER_FLAG_PERSISTENT;
                    let ps = FwpmProviderAdd0(p_engine, &provider, None);
                    if ps != ERROR_SUCCESS.0 && ps != FWP_E_ALREADY_EXISTS.0 as u32 {
                        return Err(format!("FwpmProviderAdd0 failed: 0x{ps:08X}"));
                    }

                    let mut sublayer = FWPM_SUBLAYER0::default();
                    sublayer.subLayerKey = PERSISTENT_SUBLAYER_GUID;
                    let mut prov_key = PERSISTENT_PROVIDER_GUID;
                    sublayer.providerKey = &mut prov_key;
                    let mut sl_name = to_wide("AI-NetGuard Offline Claude Sublayer");
                    let mut sl_desc = to_wide("Requires AI NetGuard loopback proxy for Claude Desktop");
                    sublayer.displayData.name = PWSTR(sl_name.as_mut_ptr());
                    sublayer.displayData.description = PWSTR(sl_desc.as_mut_ptr());
                    sublayer.flags = FWPM_SUBLAYER_FLAG_PERSISTENT;
                    sublayer.weight = 0xFFFE;
                    let ss = FwpmSubLayerAdd0(p_engine, &sublayer, None);
                    if ss != ERROR_SUCCESS.0 && ss != FWP_E_ALREADY_EXISTS.0 as u32 {
                        return Err(format!("FwpmSubLayerAdd0 (persistent) failed: 0x{ss:08X}"));
                    }

                    // Remove any previous persistent filters from older Claude versions
                    for old_id in list_persistent_filter_ids(p_engine)? {
                        let _ = FwpmFilterDeleteById0(p_engine, old_id);
                    }

                    let mut added = Vec::new();
                    for target in &valid_targets {
                        let app_blob = get_app_id(&target.exe_path)?;
                        let r = add_app_filters(
                            p_engine,
                            PERSISTENT_SUBLAYER_GUID,
                            Some(PERSISTENT_PROVIDER_GUID),
                            true,
                            app_blob,
                            false,
                            &target.allowed_loopback_ports,
                            &[],
                            &mut added,
                        );
                        FwpmFreeMemory0(&mut (app_blob as *mut c_void));
                        r?;
                    }
                    Ok(added.len())
                })();

                match inner {
                    Ok(cnt) => {
                        let c = FwpmTransactionCommit0(p_engine);
                        if c != ERROR_SUCCESS.0 {
                            let _ = FwpmTransactionAbort0(p_engine);
                            return Err(format!("FwpmTransactionCommit0 failed: 0x{c:08X}"));
                        }
                        Ok(cnt)
                    }
                    Err(e) => {
                        let _ = FwpmTransactionAbort0(p_engine);
                        Err(e)
                    }
                }
            })();

            let _ = FwpmEngineClose0(p_engine);
            let count = res?;
            self.persistent_filter_count = count;
            self.persistent_targets = valid_targets;
            Ok(())
        }
    }

    /// Re-tighten any active persistent lock to 0 open loopback ports before Guard exits
    /// so an idle or crashed NetGuard cannot leave loopback proxy ports open for squatting.
    pub fn lock_persistent_offline(&mut self) -> Result<(), String> {
        if self.persistent_filter_count == 0 || self.persistent_targets.is_empty() {
            return Ok(());
        }
        let offline_targets: Vec<ProtectedTarget> = self
            .persistent_targets
            .iter()
            .map(|t| ProtectedTarget {
                exe_path: t.exe_path.clone(),
                allow_private_lan: false,
                allowed_loopback_ports: Vec::new(),
                allowed_loopback_port_ranges: Vec::new(),
            })
            .collect();
        self.install_persistent_lock(&offline_targets)
    }

    pub fn sync_live_status(&mut self) {
        unsafe {
            self.active_filter_ids.retain(|&id| {
                let mut filter_ptr: *mut FWPM_FILTER0 = std::ptr::null_mut();
                let status = FwpmFilterGetById0(self.engine, id, &mut filter_ptr);
                if !filter_ptr.is_null() {
                    FwpmFreeMemory0(&mut (filter_ptr as *mut c_void));
                }
                status == ERROR_SUCCESS.0
            });
            if self.active_filter_ids.is_empty() {
                self.locked_paths.clear();
            }
            if let Ok(cnt) = count_persistent_filters_internal() {
                self.persistent_filter_count = cnt;
                if cnt == 0 {
                    self.persistent_targets.clear();
                }
            }
        }
    }

    pub fn remove_persistent_lock(&mut self) -> Result<(), String> {
        unsafe {
            let p_engine = open_persistent_engine()?;
            let res = (|| -> Result<(), String> {
                let tx = FwpmTransactionBegin0(p_engine, 0);
                if tx != ERROR_SUCCESS.0 {
                    return Err(format!("FwpmTransactionBegin0 failed: 0x{tx:08X}"));
                }

                for id in list_persistent_filter_ids(p_engine)? {
                    let _ = FwpmFilterDeleteById0(p_engine, id);
                }
                let _ = FwpmSubLayerDeleteByKey0(p_engine, &PERSISTENT_SUBLAYER_GUID);
                let _ = FwpmProviderDeleteByKey0(p_engine, &PERSISTENT_PROVIDER_GUID);

                let c = FwpmTransactionCommit0(p_engine);
                if c != ERROR_SUCCESS.0 {
                    let _ = FwpmTransactionAbort0(p_engine);
                    return Err(format!("FwpmTransactionCommit0 failed: 0x{c:08X}"));
                }
                Ok(())
            })();
            let _ = FwpmEngineClose0(p_engine);
            res?;
            self.persistent_filter_count = 0;
            self.persistent_targets.clear();
            Ok(())
        }
    }

    pub fn filter_count(&self) -> usize {
        self.active_filter_ids.len()
    }

    pub fn is_active(&self) -> bool {
        !self.active_filter_ids.is_empty()
    }

    pub fn persistent_filter_count(&self) -> usize {
        self.persistent_filter_count
    }

    pub fn is_persistent_active(&self) -> bool {
        self.persistent_filter_count > 0
    }

    pub fn locked_paths(&self) -> Vec<String> {
        self.locked_paths.clone()
    }
}

impl Drop for WfpManager {
    fn drop(&mut self) {
        let _ = self.clear_lock();
        unsafe {
            if !self.engine.is_invalid() {
                let _ = FwpmEngineClose0(self.engine);
            }
        }
    }
}

fn filter_existing_targets(targets: &[ProtectedTarget]) -> Vec<ProtectedTarget> {
    targets
        .iter()
        .filter_map(|t| {
            let trimmed = t.exe_path.trim();
            (!trimmed.is_empty() && Path::new(trimmed).exists()).then(|| ProtectedTarget {
                exe_path: trimmed.to_string(),
                allow_private_lan: t.allow_private_lan,
                allowed_loopback_ports: t.allowed_loopback_ports.clone(),
                allowed_loopback_port_ranges: t.allowed_loopback_port_ranges.clone(),
            })
        })
        .collect()
}

unsafe fn open_persistent_engine() -> Result<HANDLE, String> {
    let mut session = FWPM_SESSION0::default();
    let mut name_u16 = to_wide("AI-NetGuard Persistent WFP Session");
    session.displayData.name = PWSTR(name_u16.as_mut_ptr());
    let mut engine = HANDLE::default();
    let status = FwpmEngineOpen0(
        PCWSTR::null(),
        RPC_C_AUTHN_DEFAULT as u32,
        None,
        Some(&session),
        &mut engine,
    );
    if status != ERROR_SUCCESS.0 {
        return Err(format!("FwpmEngineOpen0 (persistent) failed: 0x{status:08X}"));
    }
    Ok(engine)
}

unsafe fn list_persistent_filter_ids(engine: HANDLE) -> Result<Vec<u64>, String> {
    let mut enum_handle = HANDLE::default();
    let status = FwpmFilterCreateEnumHandle0(engine, None, &mut enum_handle);
    if status != ERROR_SUCCESS.0 {
        return Err(format!("FwpmFilterCreateEnumHandle0 failed: 0x{status:08X}"));
    }

    let mut ids = Vec::new();
    loop {
        let mut entries: *mut *mut FWPM_FILTER0 = std::ptr::null_mut();
        let mut returned = 0u32;
        let es = FwpmFilterEnum0(engine, enum_handle, 256, &mut entries, &mut returned);
        if es != ERROR_SUCCESS.0 || returned == 0 || entries.is_null() {
            break;
        }
        let slice = std::slice::from_raw_parts(entries, returned as usize);
        for &ptr in slice {
            if !ptr.is_null() {
                let f = &*ptr;
                if !f.providerKey.is_null() && *f.providerKey == PERSISTENT_PROVIDER_GUID {
                    ids.push(f.filterId);
                }
            }
        }
        FwpmFreeMemory0(&mut (entries as *mut c_void));
        if returned < 256 {
            break;
        }
    }
    let _ = FwpmFilterDestroyEnumHandle0(engine, enum_handle);
    Ok(ids)
}

unsafe fn count_persistent_filters_internal() -> Result<usize, String> {
    let engine = open_persistent_engine()?;
    let res = list_persistent_filter_ids(engine).map(|v| v.len());
    let _ = FwpmEngineClose0(engine);
    res
}

#[allow(clippy::too_many_arguments)]
unsafe fn add_app_filters(
    engine: HANDLE,
    sublayer_key: GUID,
    provider_key: Option<GUID>,
    persistent: bool,
    app_blob: *mut FWP_BYTE_BLOB,
    allow_private_lan: bool,
    allowed_loopback_ports: &[u16],
    allowed_loopback_port_ranges: &[(u16, u16)],
    out_ids: &mut Vec<u64>,
) -> Result<(), String> {
    let plan = plan_app_filters(
        allow_private_lan,
        allowed_loopback_ports,
        allowed_loopback_port_ranges,
    );
    for layer in [FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6] {
        // Empty `loopback_ports` and `loopback_port_ranges` emits 0 permits -> full block.
        for &port in &plan.loopback_ports {
            let mut conds = [
                app_id_condition(app_blob),
                loopback_condition(),
                remote_port_condition(port),
            ];
            out_ids.push(add_filter(
                engine,
                sublayer_key,
                provider_key,
                persistent,
                layer,
                15,
                FWP_ACTION_PERMIT,
                &mut conds,
                "AI-NetGuard Permit Loopback Port",
            )?);
        }

        for &(low, high) in &plan.loopback_port_ranges {
            let mut low_val = FWP_VALUE0::default();
            low_val.r#type = FWP_UINT16;
            low_val.Anonymous.uint16 = low;
            let mut high_val = FWP_VALUE0::default();
            high_val.r#type = FWP_UINT16;
            high_val.Anonymous.uint16 = high;
            let mut range = FWP_RANGE0 {
                valueLow: low_val,
                valueHigh: high_val,
            };
            let mut conds = [
                app_id_condition(app_blob),
                loopback_condition(),
                remote_port_range_condition(&mut range),
            ];
            out_ids.push(add_filter(
                engine,
                sublayer_key,
                provider_key,
                persistent,
                layer,
                15,
                FWP_ACTION_PERMIT,
                &mut conds,
                "AI-NetGuard Permit Loopback Port Range",
            )?);
        }

        if plan.private_lan_v4 && layer == FWPM_LAYER_ALE_AUTH_CONNECT_V4 {
            for (addr, mask) in [
                (0x0A00_0000u32, 0xFF00_0000u32),
                (0xAC10_0000u32, 0xFFF0_0000u32),
                (0xC0A8_0000u32, 0xFFFF_0000u32),
            ] {
                let mut addr_mask = FWP_V4_ADDR_AND_MASK { addr, mask };
                let mut lan_conds = [
                    app_id_condition(app_blob),
                    remote_v4_condition(&mut addr_mask),
                ];
                out_ids.push(add_filter(
                    engine,
                    sublayer_key,
                    provider_key,
                    persistent,
                    layer,
                    14,
                    FWP_ACTION_PERMIT,
                    &mut lan_conds,
                    "AI-NetGuard Permit Private LAN",
                )?);
            }
        }

        if plan.block_direct_egress {
            let mut block_cond = [app_id_condition(app_blob)];
            out_ids.push(add_filter(
                engine,
                sublayer_key,
                provider_key,
                persistent,
                layer,
                10,
                FWP_ACTION_BLOCK,
                &mut block_cond,
                "AI-NetGuard Block Direct Egress",
            )?);
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
unsafe fn add_filter(
    engine: HANDLE,
    sublayer_key: GUID,
    provider_key: Option<GUID>,
    persistent: bool,
    layer: GUID,
    weight: u8,
    action: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_ACTION_TYPE,
    conditions: &mut [FWPM_FILTER_CONDITION0],
    label: &str,
) -> Result<u64, String> {
    let mut name_u16 = to_wide(label);
    let mut filter = FWPM_FILTER0::default();
    filter.layerKey = layer;
    filter.subLayerKey = sublayer_key;
    let mut prov_copy = provider_key.unwrap_or_default();
    if provider_key.is_some() {
        filter.providerKey = &mut prov_copy;
    }
    if persistent {
        filter.flags = FWPM_FILTER_FLAG_PERSISTENT;
    }
    filter.displayData.name = PWSTR(name_u16.as_mut_ptr());
    filter.action.r#type = action;
    filter.weight.r#type = FWP_UINT8;
    filter.weight.Anonymous.uint8 = weight;
    filter.filterCondition = conditions.as_mut_ptr();
    filter.numFilterConditions = conditions.len() as u32;

    let mut filter_id = 0u64;
    let status = FwpmFilterAdd0(engine, &filter, None, Some(&mut filter_id));
    if status != ERROR_SUCCESS.0 {
        return Err(format!("FwpmFilterAdd0 ({label}) failed: 0x{status:08X}"));
    }
    Ok(filter_id)
}

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

unsafe fn get_app_id(exe_path: &str) -> Result<*mut FWP_BYTE_BLOB, String> {
    let wide = to_wide(exe_path);
    let mut blob: *mut FWP_BYTE_BLOB = std::ptr::null_mut();
    let status = FwpmGetAppIdFromFileName0(PCWSTR(wide.as_ptr()), &mut blob);
    if status != ERROR_SUCCESS.0 || blob.is_null() {
        return Err(format!(
            "FwpmGetAppIdFromFileName0({exe_path}) failed: 0x{status:08X}"
        ));
    }
    Ok(blob)
}

unsafe fn app_id_condition(app_blob: *mut FWP_BYTE_BLOB) -> FWPM_FILTER_CONDITION0 {
    let mut cond = FWPM_FILTER_CONDITION0::default();
    cond.fieldKey = FWPM_CONDITION_ALE_APP_ID;
    cond.matchType = FWP_MATCH_EQUAL;
    cond.conditionValue.r#type = FWP_BYTE_BLOB_TYPE;
    cond.conditionValue.Anonymous.byteBlob = app_blob;
    cond
}

unsafe fn loopback_condition() -> FWPM_FILTER_CONDITION0 {
    let mut cond = FWPM_FILTER_CONDITION0::default();
    cond.fieldKey = FWPM_CONDITION_FLAGS;
    cond.matchType = FWP_MATCH_FLAGS_ALL_SET;
    cond.conditionValue.r#type = FWP_UINT32;
    cond.conditionValue.Anonymous.uint32 = FWP_CONDITION_FLAG_IS_LOOPBACK;
    cond
}

unsafe fn remote_v4_condition(addr_mask: *mut FWP_V4_ADDR_AND_MASK) -> FWPM_FILTER_CONDITION0 {
    let mut cond = FWPM_FILTER_CONDITION0::default();
    cond.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
    cond.matchType = FWP_MATCH_EQUAL;
    cond.conditionValue.r#type = FWP_V4_ADDR_MASK;
    cond.conditionValue.Anonymous.v4AddrMask = addr_mask;
    cond
}

unsafe fn remote_port_condition(port: u16) -> FWPM_FILTER_CONDITION0 {
    let mut cond = FWPM_FILTER_CONDITION0::default();
    cond.fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
    cond.matchType = FWP_MATCH_EQUAL;
    cond.conditionValue.r#type = FWP_UINT16;
    cond.conditionValue.Anonymous.uint16 = port;
    cond
}

unsafe fn remote_port_range_condition(range: *mut FWP_RANGE0) -> FWPM_FILTER_CONDITION0 {
    let mut cond = FWPM_FILTER_CONDITION0::default();
    cond.fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
    cond.matchType = FWP_MATCH_RANGE;
    cond.conditionValue.r#type = FWP_RANGE_TYPE;
    cond.conditionValue.Anonymous.rangeValue = range;
    cond
}

#[derive(Debug, PartialEq, Eq)]
struct AppFilterPlan {
    loopback_ports: Vec<u16>,
    loopback_port_ranges: Vec<(u16, u16)>,
    private_lan_v4: bool,
    block_direct_egress: bool,
}

fn plan_app_filters(
    allow_private_lan: bool,
    allowed_loopback_ports: &[u16],
    allowed_loopback_port_ranges: &[(u16, u16)],
) -> AppFilterPlan {
    let valid_ranges = allowed_loopback_port_ranges
        .iter()
        .copied()
        .filter(|&(low, high)| low > 0 && low <= high)
        .collect();
    AppFilterPlan {
        loopback_ports: allowed_loopback_ports.to_vec(),
        loopback_port_ranges: valid_ranges,
        private_lan_v4: allow_private_lan,
        block_direct_egress: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_loopback_ports_grants_zero_permits() {
        let offline = plan_app_filters(false, &[], &[]);
        assert!(offline.loopback_ports.is_empty());
        assert!(offline.loopback_port_ranges.is_empty());
        assert!(!offline.private_lan_v4);
        assert!(offline.block_direct_egress);

        let cli = plan_app_filters(true, &[17890], &[]);
        assert_eq!(cli.loopback_ports, vec![17890]);
        assert!(cli.loopback_port_ranges.is_empty());
        assert!(cli.private_lan_v4);
        assert!(cli.block_direct_egress);
    }

    #[test]
    fn validates_loopback_port_ranges() {
        let browser = plan_app_filters(
            false,
            &[17891],
            &[(49152, 65535), (0, 100), (60000, 1000)],
        );
        assert_eq!(browser.loopback_ports, vec![17891]);
        assert_eq!(browser.loopback_port_ranges, vec![(49152, 65535)]);
        assert!(!browser.private_lan_v4);
        assert!(browser.block_direct_egress);
    }
}
