#!/usr/bin/env python3

from prometheus_client import start_http_server, Gauge, Enum, REGISTRY, GC_COLLECTOR, PLATFORM_COLLECTOR, PROCESS_COLLECTOR
import requests
import json
import hashlib
import time
import os

REGISTRY.unregister(GC_COLLECTOR)
REGISTRY.unregister(PLATFORM_COLLECTOR)
REGISTRY.unregister(PROCESS_COLLECTOR)

class LoginFailedError(Exception):
    pass

class EndpointDataFetchError(Exception):
    pass

# Device Credentials
ZTE_HOSTNAME = os.environ.get('ZTE_HOSTNAME', 'http://192.168.0.1')
ZTE_PASSWORD = os.environ.get('ZTE_PASSWORD')
REFRESH_INTERVAL = int(os.environ.get('REFRESH_INTERVAL', '10'))

metrics = {
    'puknumber': Gauge('puknumber', 'PUK number'),
    'pinnumber': Gauge('pinnumber', 'PIN number'),
    'wifi_chip_temp': Gauge('wifi_chip_temp', 'WiFi chip temperature'),
    'therm_pa_level': Gauge('therm_pa_level', 'Thermal PA level'),
    'therm_pa_frl_level': Gauge('therm_pa_frl_level', 'Thermal PA FRL level'),
    'therm_tj_level': Gauge('therm_tj_level', 'Thermal TJ level'),
    'pm_sensor_pa1': Gauge('pm_sensor_pa1', 'PM sensor PA1'),
    'pm_sensor_mdm': Gauge('pm_sensor_mdm', 'PM sensor MDM'),
    'pm_modem_5g': Gauge('pm_modem_5g', 'PM modem 5G'),
    #'guest_switch': Gauge('guest_switch', 'Guest switch'),
    'wifi_chip1_ssid2_max_access_num': Gauge('wifi_chip1_ssid2_max_access_num', 'WiFi chip 1 SSID2 max access number'),
    'wifi_chip2_ssid2_max_access_num': Gauge('wifi_chip2_ssid2_max_access_num', 'WiFi chip 2 SSID2 max access number'),
    'apn_interface_version': Gauge('apn_interface_version', 'APN interface version'),
    'rssi': Gauge('rssi', 'RSSI'),
    'rscp': Gauge('rscp', 'RSCP'),
    'lte_rsrp': Gauge('lte_rsrp', 'LTE RSRP'),
    'wifi_chip1_ssid1_max_access_num': Gauge('wifi_chip1_ssid1_max_access_num', 'WiFi chip 1 SSID1 max access number'),
    'm_HideSSID': Gauge('m_HideSSID', 'M HideSSID'),
    'wifi_chip2_ssid1_max_access_num': Gauge('wifi_chip2_ssid1_max_access_num', 'WiFi chip 2 SSID1 max access number'),
    'Z5g_snr': Gauge('Z5g_snr', 'Z5g SNR'),
    'Z5g_rsrp': Gauge('Z5g_rsrp', 'Z5g RSRP'),
    'lte_snr': Gauge('lte_snr', 'LTE SNR'),
    'lte_ca_pcell_band': Gauge('lte_ca_pcell_band', 'LTE CA PCell band'),
    'lte_ca_pcell_bandwidth': Gauge('lte_ca_pcell_bandwidth', 'LTE CA PCell bandwidth'),
    'lte_ca_scell_band': Gauge('lte_ca_scell_band', 'LTE CA SCell band'),
    'lte_ca_scell_bandwidth': Gauge('lte_ca_scell_bandwidth', 'LTE CA SCell bandwidth'),
    'lte_ca_pcell_arfcn': Gauge('lte_ca_pcell_arfcn', 'LTE CA PCell ARFCN'),
    'lte_ca_scell_arfcn': Gauge('lte_ca_scell_arfcn', 'LTE CA SCell ARFCN'),
    'wifi_chip1_ssid1_switch_onoff': Gauge('wifi_chip1_ssid1_switch_onoff', 'WiFi chip 1 SSID1 switch on/off'),
    'wifi_chip2_ssid1_switch_onoff': Gauge('wifi_chip2_ssid1_switch_onoff', 'WiFi chip 2 SSID1 switch on/off'),
    'wifi_chip1_ssid2_switch_onoff': Gauge('wifi_chip1_ssid2_switch_onoff', 'WiFi chip 1 SSID2 switch on/off'),
    'wifi_chip2_ssid2_switch_onoff': Gauge('wifi_chip2_ssid2_switch_onoff', 'WiFi chip 2 SSID2 switch on/off'),
    'Z5g_SINR': Gauge('Z5g_SINR', 'Z5g SINR'),
    'pin_status': Gauge('pin_status', 'PIN status'),
    'battery_value': Gauge('battery_value', 'Battery value'),
    'ppp_dial_conn_fail_counter': Gauge('ppp_dial_conn_fail_counter', 'PPP dial connection fail counter'),
    'signalbar': Gauge('signalbar', 'Signal bar'),
    'spn_b1_flag': Gauge('spn_b1_flag', 'SPN B1 flag'),
    'spn_b2_flag': Gauge('spn_b2_flag', 'SPN B2 flag'),
    'monthly_tx_bytes': Gauge('monthly_tx_bytes', 'Monthly transmitted bytes'),
    'monthly_rx_bytes': Gauge('monthly_rx_bytes', 'Monthly received bytes'),
    'dhcp_wan_status': Gauge('dhcp_wan_status', 'DHCP WAN status'),
    'static_wan_status': Gauge('static_wan_status', 'Static WAN status'),
    'rmcc': Gauge('rmcc', 'RMCC'),
    'rmnc': Gauge('rmnc', 'RMNC'),
    'mdm_mcc': Gauge('mdm_mcc', 'MDM MCC'),
    'mdm_mnc': Gauge('mdm_mnc', 'MDM MNC'),
    'EX_SSID1': Gauge('EX_SSID1', 'EX SSID1'),
    'EX_wifi_profile': Gauge('EX_wifi_profile', 'EX WiFi profile'),
    'RadioOff': Gauge('RadioOff', 'Radio off'),
    'wifi_chip1_ssid1_access_sta_num': Gauge('wifi_chip1_ssid1_access_sta_num', 'WiFi chip 1 SSID1 access STA number'),
    'wifi_chip2_ssid1_access_sta_num': Gauge('wifi_chip2_ssid1_access_sta_num', 'WiFi chip 2 SSID1 access STA number'),
    'station_mac': Gauge('station_mac', 'Station MAC address'),
    'wifi_access_sta_num': Gauge('wifi_access_sta_num', 'WiFi access STA number'),
    'battery_charging': Gauge('battery_charging', 'Battery charging'),
    'battery_vol_percent': Gauge('battery_vol_percent', 'Battery voltage percentage'),
    'battery_pers': Gauge('battery_pers', 'Battery percentage'),
    'realtime_tx_bytes': Gauge('realtime_tx_bytes', 'Real-time transmitted bytes'),
    'realtime_rx_bytes': Gauge('realtime_rx_bytes', 'Real-time received bytes'),
    'realtime_time': Gauge('realtime_time', 'Real-time time'),
    'realtime_tx_thrpt': Gauge('realtime_tx_thrpt', 'Real-time transmission throughput'),
    'realtime_rx_thrpt': Gauge('realtime_rx_thrpt', 'Real-time reception throughput'),
    'monthly_time': Gauge('monthly_time', 'Monthly time'),
    'date_month': Gauge('date_month', 'Date month'),
    'data_volume_limit_switch': Gauge('data_volume_limit_switch', 'Data volume limit switch'),
    'data_volume_limit_size': Gauge('data_volume_limit_size', 'Data volume limit size'),
    'data_volume_alert_percent': Gauge('data_volume_alert_percent', 'Data volume alert percentage'),
    'data_volume_limit_unit': Gauge('data_volume_limit_unit', 'Data volume limit unit'),
    'upg_roam_switch': Gauge('upg_roam_switch', 'Upgrade roam switch'),
    'ssid': Gauge('ssid', 'SSID'),
    'wifi_enable': Gauge('wifi_enable', 'WiFi enable'),
    'wifi_5g_enable': Gauge('wifi_5g_enable', 'WiFi 5G enable'),
    'privacy_read_flag': Gauge('privacy_read_flag', 'Privacy read flag'),
    'is_night_mode': Gauge('is_night_mode', 'Is night mode'),
    'sms_received_flag': Gauge('sms_received_flag', 'SMS received flag'),
    'sts_received_flag': Gauge('sts_received_flag', 'STS received flag'),
    'sms_unread_num': Gauge('sms_unread_num', 'SMS unread number'),
    'sms_dev_unread_num': Gauge('sms_dev_unread_num', 'SMS device unread number'),
    'sms_sim_unread_num': Gauge('sms_sim_unread_num', 'SMS SIM unread number'),
    'wifi_chip1_ssid2_access_sta_num': Gauge('wifi_chip1_ssid2_access_sta_num', 'WiFi chip 1 SSID2 access STA number'),
    'wifi_chip2_ssid2_access_sta_num': Gauge('wifi_chip2_ssid2_access_sta_num', 'WiFi chip 2 SSID2 access STA number'),
    'lte_rssi': Gauge('lte_rssi', 'LTE RSSI'),
    'ZCELLINFO_band': Gauge('ZCELLINFO_band', 'ZCELLINFO band'),
    'Z5g_dlEarfcn': Gauge('Z5g_dlEarfcn', 'Z5g DL EARFCN'),
    'lte_ca_scell_info': Gauge('lte_ca_scell_info', 'LTE CA SCell info'),
    'Z5g_CELL_ID': Gauge('Z5g_CELL_ID', 'Z5g CELL ID'),
    'ecio': Gauge('ecio', 'ECIO'),
    'wan_active_channel': Gauge('wan_active_channel', 'WAN active channel'),
    'nr5g_action_channel': Gauge('nr5g_action_channel', 'NR5g action channel'),
    'psw_fail_num_str': Gauge('psw_fail_num_str', 'Password fail number'),
    'login_lock_time': Gauge('login_lock_time', 'Login lock time'),
    'SleepStatusForSingleChipCpe': Gauge('SleepStatusForSingleChipCpe', 'Sleep status for single-chip CPE'),
    'pin_save_flag': Gauge('pin_save_flag', 'PIN save flag'),
    'sms_nv_total': Gauge('sms_nv_total', 'SMS NV total'),
    'sms_sim_total': Gauge('sms_sim_total', 'SMS SIM total'),
    'sms_nv_rev_total': Gauge('sms_nv_rev_total', 'SMS NV received total'),
    'sms_nv_send_total': Gauge('sms_nv_send_total', 'SMS NV sent total'),
    'sms_nv_draftbox_total': Gauge('sms_nv_draftbox_total', 'SMS NV draft box total'),
    'sms_sim_rev_total': Gauge('sms_sim_rev_total', 'SMS SIM received total'),
    'sms_sim_send_total': Gauge('sms_sim_send_total', 'SMS SIM sent total'),
    'sms_sim_draftbox_total': Gauge('sms_sim_draftbox_total', 'SMS SIM draft box total'),
    'wifi_sta_connection': Gauge('wifi_sta_connection', 'WiFi STA connection'),
}

cell_metrics = Gauge(
    "cell_metrics",
    "Cellular Metrics",
    [
        "modem_main_state",
        "imei",
        "network_type",
        "imsi",
        "sim_imsi",
        "msisdn",
        "wan_ipaddr",
        "static_wan_ipaddr",
        "ipv6_wan_ipaddr",
        "ipv6_pdp_type",
        "ipv6_pdp_type_ui",
        "pdp_type",
        "pdp_type_ui",
        "opms_wan_mode",
        "opms_wan_auto_mode",
        "ppp_status",
        "wan_active_band",
        "imei_sv",
        "multi_pdns_wan_ipaddr_2",
        "multi_pdns_ipv6_wan_ipaddr_2",
        "network_provider",
        "simcard_roam",
        "spn_name_data",
        "pppoe_status",
        "sta_ip_status",
        "roam_setting_option",
        "dial_mode",
        "cell_id",
        "nr5g_pci",
        "nr5g_action_band",
        "nr5g_cell_id",
        "wan_lte_ca",
        "lte_multi_ca_scell_info",
        "lte_pci",
    ],
)
wifi_metrics = Gauge(
    "wifi_metrics",
    "WiFi Metrics",
    [
        "wifi_onoff_state",
        "m_SSID2",
        "wifi_chip1_ssid1_wifi_coverage",
        "m_ssid_enable",
        "wifi_chip1_ssid1_ssid",
        "wifi_chip1_ssid1_auth_mode",
        "wifi_chip1_ssid1_password_encode",
        "wifi_chip2_ssid1_ssid",
        "wifi_chip2_ssid1_auth_mode",
        "wifi_chip2_ssid1_password_encode",
        "lan_ipaddr",
        "wlan_mac_address",
        "LocalDomain",
        "wifi_chip1_ssid2_ssid",
        "wifi_chip2_ssid2_ssid",
        "station_ip_addr",
        "wifi_dfs_status",
        "ap_station_mode",
    ],
)
dev_metrics = Gauge(
    "dev_metrics",
    "Device Metrics",
    [
        "cr_version",
        "wa_version",
        "hardware_version",
        "web_version",
        "wa_inner_version",
        "build_version_time",
        "loginfo",
        "new_version_state",
        "current_upgrade_state",
        "is_mandatory",
        "check_web_conflict",
        "vpn_conn_status",
        "wan_connect_status",
        "upgrade_result",
        "Language",
    ],
)

all_metrics = [metric for metric in metrics.values()] + [cell_metrics, wifi_metrics, dev_metrics]

session = requests.Session()

def sha256_encode(string):
    sha256_hash = hashlib.sha256(string.encode()).hexdigest().upper()
    return sha256_hash

def login(ZTE_PASSWORD):
    # Fetch the LD token
    params = {
    	'isTest': 'false',
   	'cmd': 'LD'
    }

    response = session.get(f'{ZTE_HOSTNAME}/goform/goform_get_cmd_process', params=params, headers={'Referer': f'{ZTE_HOSTNAME}/'})
    data = response.json()
    ld_token = data['LD']
    if not ld_token:
        raise LoginFailedError("Failed to fetch LD token.")

    password = sha256_encode(sha256_encode(ZTE_PASSWORD) + ld_token)

    # Perform login request
    login_data = {
        'isTest': 'false',
        'goformId': 'LOGIN',
        'password': f"{password}"
    }

    response = session.post(f'{ZTE_HOSTNAME}/goform/goform_set_cmd_process', headers={'Referer': f'{ZTE_HOSTNAME}/'}, data=login_data)
    result = response.json()['result']

    # Check the login result
    if result != '0':
        raise LoginFailedError("Login failed.")

def get_json_data(url, referer):
    headers = {
        'Referer': referer
    }
    response = session.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        raise EndpointDataFetchError(f"Error: {response.status_code}")

def get_data_from_endpoints():
    endpoints = [
	f'{ZTE_HOSTNAME}/goform/goform_get_cmd_process?isTest=false&cmd=queryAccessPointInfo',
	f'{ZTE_HOSTNAME}/goform/goform_get_cmd_process?isTest=false&cmd=wifi_chip_temp%2Ctherm_pa_level%2Ctherm_pa_frl_level%2Ctherm_tj_level%2Cpm_sensor_pa1%2Cpm_sensor_mdm%2Cpm_modem_5g&multi_data=1',
	f'{ZTE_HOSTNAME}/goform/goform_get_cmd_process?isTest=false&cmd=wifi_onoff_state%2Cguest_switch%2Cwifi_chip1_ssid2_max_access_num%2Cm_SSID2%2Cwifi_chip2_ssid2_max_access_num%2Cwifi_chip1_ssid1_wifi_coverage%2Capn_interface_version%2Cm_ssid_enable%2Cimei%2Cnetwork_type%2Crssi%2Crscp%2Clte_rsrp%2Cimsi%2Csim_imsi%2Ccr_version%2Cwa_version%2Chardware_version%2Cweb_version%2Cwa_inner_version%2Cwifi_chip1_ssid1_max_access_num%2Cwifi_chip1_ssid1_ssid%2Cwifi_chip1_ssid1_auth_mode%2Cwifi_chip1_ssid1_password_encode%2Cwifi_chip2_ssid1_ssid%2Cwifi_chip2_ssid1_auth_mode%2Cm_HideSSID%2Cwifi_chip2_ssid1_password_encode%2Cwifi_chip2_ssid1_max_access_num%2Clan_ipaddr%2Clan_ipaddr%2Cwlan_mac_address%2Cmsisdn%2CLocalDomain%2Cwan_ipaddr%2Cstatic_wan_ipaddr%2Cipv6_wan_ipaddr%2Cipv6_pdp_type%2Cipv6_pdp_type_ui%2Cpdp_type%2Cpdp_type_ui%2Copms_wan_mode%2Copms_wan_auto_mode%2Cppp_status%2CZ5g_snr%2CZ5g_rsrp%2Cwan_lte_ca%2Clte_ca_pcell_band%2Clte_ca_pcell_bandwidth%2Clte_ca_scell_band%2Clte_ca_scell_bandwidth%2Clte_ca_pcell_arfcn%2Clte_ca_scell_arfcn%2Clte_multi_ca_scell_info%2Cwan_active_band%2Cwifi_onoff_state%2Cguest_switch%2Cwifi_chip1_ssid2_max_access_num%2Cwifi_chip2_ssid2_max_access_num%2Cwifi_chip1_ssid1_wifi_coverage%2Cwifi_chip1_ssid1_max_access_num%2Cwifi_chip1_ssid1_ssid%2Cwifi_chip1_ssid1_auth_mode%2Cwifi_chip1_ssid1_password_encode%2Cwifi_chip2_ssid1_ssid%2Cwifi_chip2_ssid1_auth_mode%2Cwifi_chip2_ssid1_password_encode%2Cwifi_chip2_ssid1_max_access_num%2Cwifi_chip1_ssid2_ssid%2Cwifi_chip2_ssid2_ssid%2Cwifi_chip1_ssid1_switch_onoff%2Cwifi_chip2_ssid1_switch_onoff%2Cwifi_chip1_ssid2_switch_onoff%2Cwifi_chip2_ssid2_switch_onoff%2CZ5g_SINR%2Cstation_ip_addr%2Cbuild_version_time%2Cimei_sv%2Cmulti_pdns_wan_ipaddr_2%2Cmulti_pdns_ipv6_wan_ipaddr_2&multi_data=1',
	f'{ZTE_HOSTNAME}/goform/goform_get_cmd_process?multi_data=1&isTest=false&sms_received_flag_flag=0&sts_received_flag_flag=0&cmd=modem_main_state%2Cpin_status%2Copms_wan_mode%2Copms_wan_auto_mode%2Cloginfo%2Cnew_version_state%2Ccurrent_upgrade_state%2Cis_mandatory%2Cwifi_dfs_status%2Cbattery_value%2Cppp_dial_conn_fail_counter%2Cwifi_chip1_ssid1_auth_mode%2Cwifi_chip2_ssid1_auth_mode%2Csignalbar%2Cnetwork_type%2Cnetwork_provider%2Cppp_status%2Csimcard_roam%2Cspn_name_data%2Cspn_b1_flag%2Cspn_b2_flag%2Cwifi_onoff_state%2Cwifi_chip1_ssid1_ssid%2Cwifi_chip2_ssid1_ssid%2Cwan_lte_ca%2Cmonthly_tx_bytes%2Cmonthly_rx_bytes%2Cpppoe_status%2Cdhcp_wan_status%2Cstatic_wan_status%2Crmcc%2Crmnc%2Cmdm_mcc%2Cmdm_mnc%2CEX_SSID1%2Csta_ip_status%2CEX_wifi_profile%2Cm_ssid_enable%2CRadioOff%2Cwifi_chip1_ssid1_access_sta_num%2Cwifi_chip2_ssid1_access_sta_num%2Clan_ipaddr%2Cstation_mac%2Cwifi_access_sta_num%2Cbattery_charging%2Cbattery_vol_percent%2Cbattery_pers%2Crealtime_tx_bytes%2Crealtime_rx_bytes%2Crealtime_time%2Crealtime_tx_thrpt%2Crealtime_rx_thrpt%2Cmonthly_time%2Cdate_month%2Cdata_volume_limit_switch%2Cdata_volume_limit_size%2Cdata_volume_alert_percent%2Cdata_volume_limit_unit%2Croam_setting_option%2Cupg_roam_switch%2Cssid%2Cwifi_enable%2Cwifi_5g_enable%2Ccheck_web_conflict%2Cdial_mode%2Cprivacy_read_flag%2Cis_night_mode%2Cvpn_conn_status%2Cwan_connect_status%2Csms_received_flag%2Csts_received_flag%2Csms_unread_num%2Cwifi_chip1_ssid2_access_sta_num%2Cwifi_chip2_ssid2_access_sta_num',
	f'{ZTE_HOSTNAME}/goform/goform_get_cmd_process?isTest=false&cmd=lan_station_list',
	f'{ZTE_HOSTNAME}/goform/goform_get_cmd_process?isTest=false&cmd=network_type%2Crssi%2Clte_rssi%2Crscp%2Clte_rsrp%2CZ5g_snr%2CZ5g_rsrp%2CZCELLINFO_band%2CZ5g_dlEarfcn%2Clte_ca_pcell_arfcn%2Clte_ca_pcell_band%2Clte_ca_scell_band%2Clte_ca_pcell_bandwidth%2Clte_ca_scell_info%2Clte_ca_scell_bandwidth%2Cwan_lte_ca%2Clte_pci%2CZ5g_CELL_ID%2CZ5g_SINR%2Ccell_id%2Cwan_lte_ca%2Clte_ca_pcell_band%2Clte_ca_pcell_bandwidth%2Clte_ca_scell_band%2Clte_ca_scell_bandwidth%2Clte_ca_pcell_arfcn%2Clte_ca_scell_arfcn%2Clte_multi_ca_scell_info%2Cwan_active_band%2Cnr5g_pci%2Cnr5g_action_band%2Cnr5g_cell_id%2Clte_snr%2Cecio%2Cwan_active_channel%2Cnr5g_action_channel&multi_data=1',
	f'{ZTE_HOSTNAME}/goform/goform_get_cmd_process?isTest=false&cmd=modem_main_state%2Cpuknumber%2Cpinnumber%2Copms_wan_mode%2Cpsw_fail_num_str%2Clogin_lock_time%2CSleepStatusForSingleChipCpe%2Cpin_save_flag&multi_data=1',
	f'{ZTE_HOSTNAME}/goform/goform_get_cmd_process?isTest=false&cmd=sms_capacity_info',
	f'{ZTE_HOSTNAME}/goform/goform_get_cmd_process?isTest=false&cmd=upgrade_result',
	f'{ZTE_HOSTNAME}/goform/goform_get_cmd_process?isTest=false&cmd=Language%2Ccr_version%2Cwa_inner_version&multi_data=1',
	f'{ZTE_HOSTNAME}/goform/goform_get_cmd_process?isTest=false&multi_data=1&cmd=wifi_sta_connection%2Cap_station_mode%2Cm_ssid_enable'
    ]

    data = {}

    for endpoint in endpoints:
        try:
            result = get_json_data(endpoint, f'{ZTE_HOSTNAME}/')
            if result:
                data.update(result)
        except EndpointDataFetchError as e:
            print(str(e))
            continue

    return data

need_to_register_all_metrics:bool = False

def maybe_register_all_metrics():
    global need_to_register_all_metrics
    global all_metrics
    if need_to_register_all_metrics:
        for metric in all_metrics:
            REGISTRY.register(metric)
    need_to_register_all_metrics = False

def unregister_all_metrics():
    global need_to_register_all_metrics
    global all_metrics
    if not need_to_register_all_metrics:
        for metric in all_metrics:
            REGISTRY.unregister(metric)
        need_to_register_all_metrics = True

def collect_data():
    try:
        login(ZTE_PASSWORD)
        data = get_data_from_endpoints()
        if not data:
            unregister_all_metrics()
            return

        cell_metrics.clear()
        cell_metrics.labels(
            modem_main_state=data["modem_main_state"],
            imei=data["imei"],
            network_type=data["network_type"],
            imsi=data["imsi"],
            sim_imsi=data["sim_imsi"],
            msisdn=data["msisdn"],
            wan_ipaddr=data["wan_ipaddr"],
            static_wan_ipaddr=data["static_wan_ipaddr"],
            ipv6_wan_ipaddr=data["ipv6_wan_ipaddr"],
            ipv6_pdp_type=data["ipv6_pdp_type"],
            ipv6_pdp_type_ui=data["ipv6_pdp_type_ui"],
            pdp_type=data["pdp_type"],
            pdp_type_ui=data["pdp_type_ui"],
            opms_wan_mode=data["opms_wan_mode"],
            opms_wan_auto_mode=data["opms_wan_auto_mode"],
            ppp_status=data["ppp_status"],
            wan_active_band=data["wan_active_band"],
            imei_sv=data["imei_sv"],
            multi_pdns_wan_ipaddr_2=data["multi_pdns_wan_ipaddr_2"],
            multi_pdns_ipv6_wan_ipaddr_2=data["multi_pdns_ipv6_wan_ipaddr_2"],
            network_provider=data["network_provider"],
            simcard_roam=data["simcard_roam"],
            spn_name_data=data["spn_name_data"],
            pppoe_status=data["pppoe_status"],
            sta_ip_status=data["sta_ip_status"],
            roam_setting_option=data["roam_setting_option"],
            dial_mode=data["dial_mode"],
            cell_id=data["cell_id"],
            nr5g_pci=data["nr5g_pci"],
            nr5g_action_band=data["nr5g_action_band"],
            nr5g_cell_id=data["nr5g_cell_id"],
            wan_lte_ca=data["wan_lte_ca"],
            lte_multi_ca_scell_info=data["lte_multi_ca_scell_info"],
            lte_pci=data["lte_pci"],
        ).set(0)
        wifi_metrics.clear()
        wifi_metrics.labels(
            wifi_onoff_state=data["wifi_onoff_state"],
            m_SSID2=data["m_SSID2"],
            wifi_chip1_ssid1_wifi_coverage=data["wifi_chip1_ssid1_wifi_coverage"],
            m_ssid_enable=data["m_ssid_enable"],
            wifi_chip1_ssid1_ssid=data["wifi_chip1_ssid1_ssid"],
            wifi_chip1_ssid1_auth_mode=data["wifi_chip1_ssid1_auth_mode"],
            wifi_chip1_ssid1_password_encode=data["wifi_chip1_ssid1_password_encode"],
            wifi_chip2_ssid1_ssid=data["wifi_chip2_ssid1_ssid"],
            wifi_chip2_ssid1_auth_mode=data["wifi_chip2_ssid1_auth_mode"],
            wifi_chip2_ssid1_password_encode=data["wifi_chip2_ssid1_password_encode"],
            lan_ipaddr=data["lan_ipaddr"],
            wlan_mac_address=data["wlan_mac_address"],
            LocalDomain=data["LocalDomain"],
            wifi_chip1_ssid2_ssid=data["wifi_chip1_ssid2_ssid"],
            wifi_chip2_ssid2_ssid=data["wifi_chip2_ssid2_ssid"],
            station_ip_addr=data["station_ip_addr"],
            wifi_dfs_status=data["wifi_dfs_status"],
            ap_station_mode=data["ap_station_mode"],
        ).set(0)
        dev_metrics.clear()
        dev_metrics.labels(
            cr_version=data["cr_version"],
            wa_version=data["wa_version"],
            hardware_version=data["hardware_version"],
            web_version=data["web_version"],
            wa_inner_version=data["wa_inner_version"],
            build_version_time=data["build_version_time"],
            loginfo=data["loginfo"],
            new_version_state=data["new_version_state"],
            current_upgrade_state=data["current_upgrade_state"],
            is_mandatory=data["is_mandatory"],
            check_web_conflict=data["check_web_conflict"],
            vpn_conn_status=data["vpn_conn_status"],
            wan_connect_status=data["wan_connect_status"],
            upgrade_result=data["upgrade_result"],
            Language=data["Language"],
        ).set(0)

        for metric_name, metric in metrics.items():
            metric_value = data.get(metric_name)
            try:
                if metric_value:
                    metric.set(metric_value)
            except Exception as e:
                print(f'{metric_name} has wrong format: {metric_value}')
                print(json.dumps(data, indent=4))

        maybe_register_all_metrics()
    except LoginFailedError as e:
        unregister_all_metrics()
        print(str(e))
    except Exception as e:
        unregister_all_metrics()
        print(f"An error occurred: {str(e)}")

if __name__ == '__main__':
    unregister_all_metrics()
    # Start the Prometheus HTTP server
    start_http_server(8000)

    print("ZTE Exporter for Prometheus has started.")

    # Collect and update the data periodically
    while True:
        collect_data()
        time.sleep(REFRESH_INTERVAL)
