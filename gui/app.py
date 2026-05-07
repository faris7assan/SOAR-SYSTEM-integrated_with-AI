import PySimpleGUI as sg
import threading
import queue
import time
import logging
import os
import sys
import collections

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import AegisNDR
from simulation.attacker import AttackSimulator
import config

# --- Ultimate Pro Theme ---
ULTIMATE_THEME = {
    'BACKGROUND': '#090B0F',
    'TEXT': '#D1D5DB',
    'INPUT': '#111827',
    'TEXT_INPUT': '#FFFFFF',
    'SCROLL': '#111827',
    'BUTTON': ('#FFFFFF', '#2563EB'),
    'PROGRESS': ('#10B981', '#111827'),
    'BORDER': 0,
    'SLIDER_DEPTH': 0,
    'PROGRESS_DEPTH': 0,
}
sg.theme_add_new('AegisUltimate', ULTIMATE_THEME)

# --- Logging ---
log_queue = queue.Queue()
class GUIHandler(logging.Handler):
    def emit(self, record):
        try: log_queue.put(self.format(record))
        except: pass

def setup_gui_logging():
    logger = logging.getLogger()
    handler = GUIHandler()
    handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s', datefmt='%H:%M:%S'))
    logger.addHandler(handler)

# --- State ---
class AppState:
    def __init__(self):
        self.engine = None
        self.simulator = None
        self.running = False
        self.last_alert_time = "None"
        self.threat_history = collections.deque([0]*50, maxlen=50)
        self.last_ui_update = 0

state = AppState()

def engine_worker(interface, mock_mode):
    try:
        state.engine = AegisNDR(interface=interface, mock_mode=mock_mode, api_enabled=True)
        state.simulator = AttackSimulator(state.engine.packet_queue)
        state.engine.start()
        state.running = True
        while state.running and state.engine._running: time.sleep(1)
    except Exception as e:
        logging.error(f"Engine Failure: {e}")
        state.running = False

# --- UI Builders ---

def make_slider_row(label, key, range=(1, 100), default=50):
    return [sg.Text(label, size=(25, 1), font=('Helvetica', 10)), 
            sg.Slider(range=range, default_value=default, orientation='h', key=key, size=(20, 15), enable_events=True),
            sg.Text(str(default), key=f"{key}-VAL", size=(5, 1))]

def create_layout():
    sg.theme('AegisUltimate')
    
    sidebar = [
        [sg.Text('🛡️ AEGIS ULTIMATE', font=('Helvetica', 18, 'bold'), text_color='#3B82F6', pad=(20, 30))],
        [sg.Button('🏠 COMMAND CENTER', key='-NAV-HOME-', size=(22, 1), border_width=0)],
        [sg.Button('🛡️ DETECTION ENGINE', key='-NAV-DET-', size=(22, 1), border_width=0)],
        [sg.Button('🛠️ SYSTEM TUNING', key='-NAV-SET-', size=(22, 1), border_width=0)],
        [sg.Button('📋 INCIDENT LOGS', key='-NAV-LOGS-', size=(22, 1), border_width=0)],
        [sg.VPush()],
        [sg.Text('SYSTEM STATUS', font=('Helvetica', 8), text_color='#6B7280', pad=(20, 0))],
        [sg.Text('● STANDBY', key='-STATUS-', text_color='#9CA3AF', font=('Helvetica', 10, 'bold'), pad=(20, 10))],
        [sg.Button('SHUTDOWN', size=(22, 1), button_color=('#FFFFFF', '#B91C1C'), border_width=0, pad=(0, 20))]
    ]

    # --- HOME PANEL ---
    home_panel = [
        [sg.Text('Active Defense Overview', font=('Helvetica', 20, 'bold'))],
        [sg.Frame('', [[
            sg.Column([[sg.Text('PACKETS', font=('Helvetica', 9)), sg.Text('0', key='-KPI-PKTS-', font=('Helvetica', 18, 'bold'))]], pad=15),
            sg.VerticalSeparator(),
            sg.Column([[sg.Text('FLOWS', font=('Helvetica', 9)), sg.Text('0', key='-KPI-FLOWS-', font=('Helvetica', 18, 'bold'), text_color='#10B981')]], pad=15),
            sg.VerticalSeparator(),
            sg.Column([[sg.Text('ALERTS', font=('Helvetica', 9)), sg.Text('0', key='-KPI-ALERTS-', font=('Helvetica', 18, 'bold'), text_color='#F59E0B')]], pad=15),
        ]], background_color='#111827', border_width=0, expand_x=True)],
        [sg.Text('Live Threat Pulse', font=('Helvetica', 12), pad=((0,0),(20,0)))],
        [sg.Graph(canvas_size=(600, 150), graph_bottom_left=(0, 0), graph_top_right=(600, 100), key='-PULSE-', background_color='#020617', expand_x=True)],
        [sg.Multiline('', size=(80, 8), key='-CON-', autoscroll=True, disabled=True, font=('Courier', 9), background_color='#020617', text_color='#60A5FA')]
    ]

    # --- DETECTION ENGINE PANEL ---
    detection_panel = [
        [sg.Text('Detection Threshold Management', font=('Helvetica', 18, 'bold'))],
        [sg.TabGroup([[
            sg.Tab('Thresholds', [
                make_slider_row('Port Scan Sensitivity', '-CFG-SCAN-', (1, 100), config.PORT_SCAN_THRESHOLD),
                make_slider_row('Brute Force Max Attempts', '-CFG-BRUTE-', (1, 200), config.BRUTE_FORCE_THRESHOLD),
                make_slider_row('DDoS PPS Limit', '-CFG-PPS-', (100, 20000), config.DDOS_PPS_THRESHOLD),
                make_slider_row('Data Exfil Limit (MB)', '-CFG-EXFIL-', (1, 1000), config.EXFIL_BYTES_THRESHOLD // 1_000_000),
            ]),
            sg.Tab('SOAR Policy', [
                make_slider_row('Min Score to Alert', '-CFG-SCORE-A-', (1, 100), config.SCORE_ALERT_THRESHOLD),
                make_slider_row('Min Score to Block', '-CFG-SCORE-B-', (1, 100), config.SCORE_BLOCK_THRESHOLD),
                make_slider_row('Auto-Block Duration (min)', '-CFG-BLOCK-D-', (1, 1440), config.BLOCK_DURATION_SECONDS // 60),
                [sg.Checkbox('Enable Autonomous Response', default=config.RESPONSE_ENABLED, key='-CFG-RESP-', enable_events=True)]
            ])
        ]], expand_x=True)],
        [sg.Button('🚀 ACTIVATE DEFENSE', key='-START-', size=(25, 2), button_color=('#FFFFFF', '#059669')),
         sg.Button('🛑 STOP DEFENSE', key='-STOP-', size=(25, 2), button_color=('#FFFFFF', '#B91C1C'), disabled=True)],
        [sg.Button('⚔️ RUN ATTACK SIMULATION', key='-SIM-', size=(52, 1), button_color=('#FFFFFF', '#7C3AED'), disabled=True)]
    ]

    # --- SYSTEM SETTINGS PANEL ---
    settings_panel = [
        [sg.Text('System & Environment Configuration', font=('Helvetica', 18, 'bold'))],
        [sg.Text('Network Interface:', size=(20, 1)), sg.Combo(['Wi-Fi', 'Ethernet', 'eth0', 'lo'], default_value='Wi-Fi', key='-IFACE-')],
        [sg.Checkbox('Demo Mode (Synthetic Traffic)', default=True, key='-MOCK-')],
        [sg.Text('Capture Filter (BPF):', size=(20, 1)), sg.Input(config.CAPTURE_FILTER, key='-CFG-BPF-', size=(30, 1))],
        [sg.Text('Flow Timeout (Active):', size=(20, 1)), sg.Spin([i for i in range(10, 601)], initial_value=config.FLOW_TIMEOUT_ACTIVE, key='-CFG-T-ACT-')],
        [sg.Button('Apply System Changes', key='-APPLY-SYS-', size=(30, 1), button_color=('#FFFFFF', '#4B5563'))],
        [sg.HorizontalSeparator(pad=(0, 20))],
        [sg.Text('Advanced Access', font=('Helvetica', 14, 'bold'))],
        [sg.Button('🌐 OPEN API DOCUMENTATION', key='-OPEN-API-', size=(30, 1))]
    ]

    # --- LOGS PANEL ---
    logs_panel = [
        [sg.Text('Incident History Explorer', font=('Helvetica', 18, 'bold'))],
        [sg.Table(values=[], headings=['Time', 'Source', 'Alert Type', 'Severity', 'Score'],
                 auto_size_columns=True, justification='left', key='-TABLE-ALERTS-', 
                 num_rows=18, expand_x=True, header_background_color='#111827',
                 background_color='#090B0F', border_width=0)],
        [sg.Button('Export to JSON', key='-EXPORT-'), sg.Button('Clear History', key='-CLEAR-')]
    ]

    layout = [
        [sg.Column(sidebar, background_color='#111827', expand_y=True, pad=(0,0)), 
         sg.Column([
             [sg.Column(home_panel, key='-PANEL-HOME-', expand_x=True, expand_y=True),
              sg.Column(detection_panel, key='-PANEL-DET-', visible=False, expand_x=True, expand_y=True),
              sg.Column(settings_panel, key='-PANEL-SET-', visible=False, expand_x=True, expand_y=True),
              sg.Column(logs_panel, key='-PANEL-LOGS-', visible=False, expand_x=True, expand_y=True)]
         ], expand_x=True, expand_y=True, pad=(30, 30))]
    ]
    return layout

def draw_pulse(graph_elem, values):
    graph_elem.erase()
    if not values: return
    w, h = graph_elem.get_size()
    step = w / len(values)
    for i in range(len(values)-1):
        x1, y1 = i * step, (values[i] / 100) * h
        x2, y2 = (i+1) * step, (values[i+1] / 100) * h
        graph_elem.draw_line((x1, y1), (x2, y2), color='#3B82F6', width=2)

def run_gui():
    setup_gui_logging()
    window = sg.Window('Aegis Ultimate - Total Control Center', create_layout(), finalize=True, resizable=True, size=(1100, 750))
    current_panel = '-PANEL-HOME-'
    
    while True:
        event, values = window.read(timeout=100)
        if event in (sg.WIN_CLOSED, 'SHUTDOWN'):
            if state.running: state.engine.stop()
            break
            
        # --- Nav ---
        if event.startswith('-NAV-'):
            target = {'-NAV-HOME-': '-PANEL-HOME-', '-NAV-DET-': '-PANEL-DET-', '-NAV-SET-': '-PANEL-SET-', '-NAV-LOGS-': '-PANEL-LOGS-'}.get(event)
            if target:
                window[current_panel].update(visible=False)
                window[target].update(visible=True)
                current_panel = target

        # --- Dynamic Config Sync ---
        if event.startswith('-CFG-'):
            val = values[event]
            window[f"{event}-VAL"].update(str(int(val)))
            # Live Sync to config module
            if event == '-CFG-SCAN-': config.PORT_SCAN_THRESHOLD = int(val)
            if event == '-CFG-BRUTE-': config.BRUTE_FORCE_THRESHOLD = int(val)
            if event == '-CFG-PPS-': config.DDOS_PPS_THRESHOLD = int(val)
            if event == '-CFG-EXFIL-': config.EXFIL_BYTES_THRESHOLD = int(val) * 1_000_000
            if event == '-CFG-SCORE-A-': config.SCORE_ALERT_THRESHOLD = int(val)
            if event == '-CFG-SCORE-B-': config.SCORE_BLOCK_THRESHOLD = int(val)
            if event == '-CFG-BLOCK-D-': config.BLOCK_DURATION_SECONDS = int(val) * 60
            if event == '-CFG-RESP-': config.RESPONSE_ENABLED = val

        # --- Engine Control ---
        if event == '-START-':
            window['-START-'].update(disabled=True); window['-STOP-'].update(disabled=False)
            window['-SIM-'].update(disabled=not values['-MOCK-']); window['-STATUS-'].update('● ACTIVE', text_color='#10B981')
            threading.Thread(target=engine_worker, args=(values['-IFACE-'], values['-MOCK-']), daemon=True).start()
            
        if event == '-STOP-':
            if state.engine: state.engine.stop()
            state.running = False
            window['-START-'].update(disabled=False); window['-STOP-'].update(disabled=True)
            window['-STATUS-'].update('● STANDBY', text_color='#9CA3AF')

        if event == '-APPLY-SYS-':
            config.CAPTURE_FILTER = values['-CFG-BPF-']
            config.FLOW_TIMEOUT_ACTIVE = int(values['-CFG-T-ACT-'])
            logging.info("System configuration updated. Changes will apply to new flows.")

        if event == '-SIM-':
            if state.simulator: state.simulator.run_all()

        if event == '-OPEN-API-':
            import webbrowser; webbrowser.open("http://localhost:8000/docs")

        # --- Periodic UI Sync ---
        try:
            while not log_queue.empty(): window['-CON-'].print(log_queue.get_nowait())
        except: pass

        if state.running and state.engine:
            now = time.time()
            if now - state.last_ui_update > 1.0:
                m = state.engine.metrics
                cap = state.engine.capture.stats
                window['-KPI-PKTS-'].update(f"{cap.get('captured', 0):,}")
                window['-KPI-FLOWS-'].update(f"{m.get('flows_processed', 0):,}")
                window['-KPI-ALERTS-'].update(str(m.get('alerts_generated', 0)))
                
                alerts = state.engine.alert_store.get_all(limit=1)
                score = alerts[0]['score'] if alerts else 0
                state.threat_history.append(score)
                draw_pulse(window['-PULSE-'], list(state.threat_history))
                
                if current_panel == '-PANEL-LOGS-':
                    history = state.engine.alert_store.get_all(limit=30)
                    rows = [[time.strftime('%H:%M:%S', time.localtime(a['timestamp'])), a['src_ip'], a['alert_type'], a['severity'], int(a['score'])] for a in history]
                    window['-TABLE-ALERTS-'].update(values=rows)
                
                state.last_ui_update = now

    window.close()

if __name__ == '__main__':
    run_gui()
