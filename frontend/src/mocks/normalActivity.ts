export type AssetGroup = 'Windows 服务器' | '终端工作站' | 'Linux 服务器' | '数据库资产' | '网络设备' | '安全设备'

export interface NormalActivityEvent {
  id: string
  time: string
  host: string
  assetGroup: AssetGroup
  source: string
  action: string
}

const n = (id: string, time: string, host: string, assetGroup: AssetGroup, source: string, action: string): NormalActivityEvent => ({
  id,
  time,
  host,
  assetGroup,
  source,
  action,
})

export const normalActivityEvents: NormalActivityEvent[] = [
  n('N-0001', '00:08:12', 'DC-01', 'Windows 服务器', 'Windows EVTX', 'LOGIN_SUCCESS'),
  n('N-0002', '00:21:45', 'WS-021', '终端工作站', 'EDR', 'PROCESS_START'),
  n('N-0003', '00:37:16', 'FW-01', '安全设备', 'Firewall', 'ALLOW_SESSION'),
  n('N-0004', '00:54:03', 'DB-01', '数据库资产', 'Linux Audit', 'DB_QUERY'),
  n('N-0005', '01:06:51', 'SW-CORE-01', '网络设备', 'Network Flow', 'NETWORK_FLOW'),
  n('N-0006', '01:31:22', 'APP-01', 'Linux 服务器', 'Linux Audit', 'SERVICE_HEARTBEAT'),
  n('N-0007', '01:46:09', 'WS-034', '终端工作站', 'Windows EVTX', 'LOGIN_SUCCESS'),
  n('N-0008', '02:03:17', 'DC-02', 'Windows 服务器', 'Windows EVTX', 'KERBEROS_TICKET'),
  n('N-0009', '02:27:35', 'FW-02', '安全设备', 'Firewall', 'ALLOW_SESSION'),
  n('N-0010', '02:43:28', 'WS-018', '终端工作站', 'EDR', 'PROCESS_START'),
  n('N-0011', '03:02:41', 'DB-02', '数据库资产', 'Linux Audit', 'DB_QUERY'),
  n('N-0012', '03:39:02', 'APP-02', 'Linux 服务器', 'Network Flow', 'INTERNAL_CONNECT'),
  n('N-0013', '04:08:55', 'WS-041', '终端工作站', 'Windows EVTX', 'LOGIN_SUCCESS'),
  n('N-0014', '04:24:11', 'SW-ACCESS-03', '网络设备', 'Network Flow', 'NETWORK_FLOW'),
  n('N-0015', '04:49:38', 'DC-01', 'Windows 服务器', 'Windows EVTX', 'SERVICE_LOGON'),
  n('N-0016', '05:03:49', 'WS-008', '终端工作站', 'EDR', 'PROCESS_START'),
  n('N-0017', '05:41:07', 'DB-01', '数据库资产', 'Linux Audit', 'DB_QUERY'),
  n('N-0018', '06:12:31', 'APP-03', 'Linux 服务器', 'Linux Audit', 'FILE_READ'),
  n('N-0019', '06:28:44', 'WS-055', '终端工作站', 'Windows EVTX', 'LOGIN_SUCCESS'),
  n('N-0020', '06:53:12', 'FW-01', '安全设备', 'Firewall', 'ALLOW_SESSION'),
  n('N-0021', '07:07:36', 'WS-013', '终端工作站', 'EDR', 'PROCESS_START'),
  n('N-0022', '07:31:19', 'DC-02', 'Windows 服务器', 'Windows EVTX', 'KERBEROS_TICKET'),
  n('N-0023', '08:02:47', 'SW-CORE-01', '网络设备', 'Network Flow', 'NETWORK_FLOW'),
  n('N-0024', '08:26:13', 'DB-03', '数据库资产', 'Linux Audit', 'DB_QUERY'),
  n('N-0025', '08:45:26', 'WS-063', '终端工作站', 'Windows EVTX', 'LOGIN_SUCCESS'),
  n('N-0026', '09:04:58', 'APP-01', 'Linux 服务器', 'Network Flow', 'INTERNAL_CONNECT'),
  n('N-0027', '09:27:32', 'WS-024', '终端工作站', 'EDR', 'PROCESS_START'),
  n('N-0028', '09:52:41', 'FW-02', '安全设备', 'Firewall', 'ALLOW_SESSION'),
  n('N-0029', '10:11:09', 'DC-01', 'Windows 服务器', 'Windows EVTX', 'SERVICE_LOGON'),
  n('N-0030', '10:42:18', 'WS-072', '终端工作站', 'Windows EVTX', 'LOGIN_SUCCESS'),
  n('N-0031', '11:03:36', 'DB-02', '数据库资产', 'Linux Audit', 'DB_QUERY'),
  n('N-0032', '11:24:53', 'SW-ACCESS-01', '网络设备', 'Network Flow', 'NETWORK_FLOW'),
  n('N-0033', '11:42:27', 'WS-031', '终端工作站', 'EDR', 'PROCESS_START'),
  n('N-0034', '12:08:15', 'APP-02', 'Linux 服务器', 'Linux Audit', 'SERVICE_HEARTBEAT'),
  n('N-0035', '12:27:44', 'WS-016', '终端工作站', 'Windows EVTX', 'LOGIN_SUCCESS'),
  n('N-0036', '12:58:03', 'FW-01', '安全设备', 'Firewall', 'ALLOW_SESSION'),
  n('N-0037', '13:19:26', 'DC-02', 'Windows 服务器', 'Windows EVTX', 'KERBEROS_TICKET'),
  n('N-0038', '13:43:51', 'WS-087', '终端工作站', 'EDR', 'PROCESS_START'),
  n('N-0039', '14:06:22', 'DB-01', '数据库资产', 'Linux Audit', 'DB_QUERY'),
  n('N-0040', '14:41:18', 'SW-CORE-01', '网络设备', 'Network Flow', 'NETWORK_FLOW'),
  n('N-0041', '15:02:37', 'WS-044', '终端工作站', 'Windows EVTX', 'LOGIN_SUCCESS'),
  n('N-0042', '15:29:05', 'APP-03', 'Linux 服务器', 'Network Flow', 'INTERNAL_CONNECT'),
  n('N-0043', '15:53:16', 'FW-02', '安全设备', 'Firewall', 'ALLOW_SESSION'),
  n('N-0044', '16:22:48', 'WS-052', '终端工作站', 'EDR', 'PROCESS_START'),
  n('N-0045', '16:49:10', 'DC-01', 'Windows 服务器', 'Windows EVTX', 'SERVICE_LOGON'),
  n('N-0046', '17:14:33', 'DB-03', '数据库资产', 'Linux Audit', 'DB_QUERY'),
  n('N-0047', '17:36:29', 'WS-065', '终端工作站', 'Windows EVTX', 'LOGIN_SUCCESS'),
  n('N-0048', '18:03:17', 'SW-ACCESS-02', '网络设备', 'Network Flow', 'NETWORK_FLOW'),
  n('N-0049', '18:42:51', 'APP-01', 'Linux 服务器', 'Linux Audit', 'FILE_READ'),
  n('N-0050', '19:06:22', 'WS-075', '终端工作站', 'EDR', 'PROCESS_START'),
  n('N-0051', '19:31:47', 'FW-01', '安全设备', 'Firewall', 'ALLOW_SESSION'),
  n('N-0052', '19:54:08', 'DC-02', 'Windows 服务器', 'Windows EVTX', 'KERBEROS_TICKET'),
  n('N-0053', '20:21:36', 'WS-081', '终端工作站', 'Windows EVTX', 'LOGIN_SUCCESS'),
  n('N-0054', '20:47:19', 'DB-02', '数据库资产', 'Linux Audit', 'DB_QUERY'),
  n('N-0055', '21:09:42', 'APP-02', 'Linux 服务器', 'Network Flow', 'INTERNAL_CONNECT'),
  n('N-0056', '21:34:05', 'WS-027', '终端工作站', 'EDR', 'PROCESS_START'),
  n('N-0057', '22:02:28', 'SW-CORE-01', '网络设备', 'Network Flow', 'NETWORK_FLOW'),
  n('N-0058', '22:26:44', 'FW-02', '安全设备', 'Firewall', 'ALLOW_SESSION'),
  n('N-0059', '22:48:13', 'WS-009', '终端工作站', 'Windows EVTX', 'LOGIN_SUCCESS'),
  n('N-0060', '23:16:31', 'DC-01', 'Windows 服务器', 'Windows EVTX', 'SERVICE_LOGON'),
  n('N-0061', '23:33:27', 'DB-01', '数据库资产', 'Linux Audit', 'DB_QUERY'),
  n('N-0062', '23:51:06', 'APP-03', 'Linux 服务器', 'Linux Audit', 'SERVICE_HEARTBEAT'),
]
