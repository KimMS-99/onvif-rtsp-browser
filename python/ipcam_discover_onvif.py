#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IP 카메라(ONVIF) 탐색 + 더블클릭 시 RTSP 재생 (OpenCV)
- WS-Discovery(UDP 3702)로 카메라 검색
- 결과 목록 더블클릭 시 ONVIF로 RTSP URI 획득 후 OpenCV로 재생
- 기본 계정: admin / admin@1234 (GUI에서 변경 가능)
- 의존: onvif-zeep, opencv-python
"""

import socket
import struct
import time
import uuid
import threading
from typing import List, Dict, Optional, Tuple
from xml.etree import ElementTree as ET

# ===== WS-Discovery 상수 =====
WSACTION_PROBE = "http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe"
WSTO = "urn:schemas-xmlsoap-org:ws:2005:04/discovery"
MULTICAST_ADDR = "239.255.255.250"
WS_DISCOVERY_PORT = 3702

NS = {
    "e": "http://www.w3.org/2003/05/soap-envelope",
    "w": "http://schemas.xmlsoap.org/ws/2004/08/addressing",
    "d": "http://schemas.xmlsoap.org/ws/2005/04/discovery",
    "dn": "http://www.onvif.org/ver10/network/wsdl",
    "tds": "http://www.onvif.org/ver10/device/wsdl",
}

def _make_probe_message(message_id: Optional[str] = None, types: str = "dn:NetworkVideoTransmitter") -> bytes:
    mid = message_id or f"uuid:{uuid.uuid4()}"
    xml = (
        '<?xml version="1.0" encoding="utf-8"?>'
        f'<e:Envelope xmlns:e="{NS["e"]}" xmlns:w="{NS["w"]}" '
        f'xmlns:d="{NS["d"]}" xmlns:dn="{NS["dn"]}" xmlns:tds="{NS["tds"]}">'
        "<e:Header>"
        f"<w:MessageID>{mid}</w:MessageID>"
        f"<w:To>{WSTO}</w:To>"
        f"<w:Action>{WSACTION_PROBE}</w:Action>"
        "</e:Header>"
        "<e:Body>"
        "<d:Probe>"
        f"<d:Types>{types}</d:Types>"
        "</d:Probe>"
        "</e:Body>"
        "</e:Envelope>"
    )
    return xml.encode("utf-8")

def _parse_probe_match(data: bytes) -> Dict[str, Optional[str]]:
    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        return {}
    def text_of(elem):
        return elem.text.strip() if elem is not None and elem.text else ""
    pm = root.find(".//{http://schemas.xmlsoap.org/ws/2005/04/discovery}ProbeMatch")
    if pm is None:
        return {}
    urn = text_of(pm.find("{http://schemas.xmlsoap.org/ws/2005/04/discovery}EndpointReference/"
                          "{http://schemas.xmlsoap.org/ws/2004/08/addressing}Address"))
    xaddrs = text_of(pm.find("{http://schemas.xmlsoap.org/ws/2005/04/discovery}XAddrs"))
    scopes = text_of(pm.find("{http://schemas.xmlsoap.org/ws/2005/04/discovery}Scopes"))
    types = text_of(pm.find("{http://schemas.xmlsoap.org/ws/2005/04/discovery}Types"))
    return {"urn": urn, "xaddrs": xaddrs, "scopes": scopes, "types": types}

def _extract_ip_and_port_from_xaddrs(xaddrs: str) -> Tuple[Optional[str], Optional[int]]:
    """
    XAddrs에서 IP와 포트를 추출 (없으면 None). 포트 없으면 80 추정.
    """
    if not xaddrs:
        return None, None
    urls = [u for u in xaddrs.replace("\t", " ").split(" ") if u]
    for u in urls:
        if u.startswith("http://") or u.startswith("https://"):
            rest = u.split("://", 1)[1]
            hostport = rest.split("/")[0]
            if hostport.startswith("["):  # IPv6 제외
                continue
            if ":" in hostport:
                host, p = hostport.split(":", 1)
                if host and all(ch.isdigit() or ch == "." for ch in host):
                    try:
                        return host, int(p)
                    except ValueError:
                        return host, None
            else:
                if all(ch.isdigit() or ch == "." for ch in hostport):
                    return hostport, 80
    return None, None

def discover_onvif_cameras(timeout: float = 3.0, retries: int = 2, types: str = "dn:NetworkVideoTransmitter") -> List[Dict[str, str]]:
    results: Dict[str, Dict[str, str]] = {}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        ttl_bin = struct.pack('@i', 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl_bin)
        sock.settimeout(timeout)
        sock.bind(('', 0))
        probe = _make_probe_message(types=types)
        for _ in range(retries):
            try:
                sock.sendto(probe, (MULTICAST_ADDR, WS_DISCOVERY_PORT))
            except OSError:
                pass
            t_end = time.time() + timeout
            while time.time() < t_end:
                try:
                    data, addr = sock.recvfrom(16384)
                except socket.timeout:
                    break
                except OSError:
                    break
                parsed = _parse_probe_match(data)
                if not parsed:
                    continue
                ip_from_xaddrs, _ = _extract_ip_and_port_from_xaddrs(parsed.get("xaddrs", ""))
                ip = ip_from_xaddrs or addr[0]
                if ip not in results:
                    results[ip] = {
                        "ip": ip,
                        "xaddrs": parsed.get("xaddrs", ""),
                        "scopes": parsed.get("scopes", ""),
                        "types": parsed.get("types", ""),
                        "urn": parsed.get("urn", ""),
                    }
        return list(results.values())
    finally:
        sock.close()

# ===== ONVIF로 RTSP URI 얻기 =====
def get_rtsp_uri_via_onvif(ip: str, username: str, password: str, xaddrs: str = "") -> Optional[str]:
    """
    onvif-zeep 사용. 프로파일[0] 기준으로 RTSP URI 획득. 실패 시 None.
    """
    # 지연 import (필요할 때만)
    from onvif import ONVIFCamera  # pip install onvif-zeep

    # XAddrs 포트 추정 (없으면 80), 일부 장비는 8899/8000도 씀
    _, port_guess = _extract_ip_and_port_from_xaddrs(xaddrs)
    candidate_ports = [p for p in [port_guess, 80, 8899, 8000] if p]
    last_err = None

    for p in candidate_ports:
        try:
            cam = ONVIFCamera(ip, p, username, password)
            media = cam.create_media_service()
            profiles = media.GetProfiles()
            if not profiles:
                continue
            token = profiles[0].token
            req = media.create_type('GetStreamUri')
            req.StreamSetup = {'Stream': 'RTP-Unicast', 'Transport': {'Protocol': 'RTSP'}}
            req.ProfileToken = token
            uri = media.GetStreamUri(req).Uri
            if uri:
                # 계정정보가 포함되지 않는 장비가 있으므로 보강
                if "@" not in uri and "rtsp://" in uri:
                    # rtsp://host:port/.... 형식을 찾아서 삽입
                    prefix, rest = uri.split("://", 1)
                    uri = f"{prefix}://{username}:{password}@{rest}"
                return uri
        except Exception as e:
            last_err = e
            continue
    print(f"[WARN] ONVIF RTSP URI 획득 실패: {last_err}")
    return None

# ===== OpenCV 재생 =====
def play_rtsp_with_opencv(rtsp_uri: str, window_name: str = "IP Camera"):
    import cv2  # pip install opencv-python
    cap = cv2.VideoCapture(rtsp_uri)
    if not cap.isOpened():
        raise RuntimeError("RTSP 연결 실패: " + rtsp_uri)
    cv2.namedWindow(window_name)
    try:
        while True:
            ok, frame = cap.read()
            if not ok:
                break
            cv2.imshow(window_name, frame)
            if cv2.waitKey(1) & 0xFF == 27:  # ESC
                break
    finally:
        cap.release()
        cv2.destroyWindow(window_name)

# ===== Tkinter GUI =====
def run_gui():
    import tkinter as tk
    from tkinter import ttk, messagebox

    root = tk.Tk()
    root.title("IP 카메라 검색기 (ONVIF → RTSP 보기)")
    root.geometry("900x520")

    frm = ttk.Frame(root, padding=10)
    frm.pack(fill="both", expand=True)

    # 상단 컨트롤바
    topbar = ttk.Frame(frm)
    topbar.pack(fill="x", pady=(0, 8))

    timeout_var = tk.StringVar(value="3.0")
    retries_var = tk.StringVar(value="2")
    types_var = tk.StringVar(value="dn:NetworkVideoTransmitter")

    user_var = tk.StringVar(value="admin")
    pwd_var = tk.StringVar(value="admin@1234")

    ttk.Label(topbar, text="Timeout(s):").pack(side="left")
    ttk.Entry(topbar, width=6, textvariable=timeout_var).pack(side="left", padx=(0, 10))

    ttk.Label(topbar, text="Retries:").pack(side="left")
    ttk.Entry(topbar, width=4, textvariable=retries_var).pack(side="left", padx=(0, 10))

    ttk.Label(topbar, text="Types:").pack(side="left")
    ttk.Entry(topbar, width=28, textvariable=types_var).pack(side="left", padx=(0, 10))

    ttk.Label(topbar, text="User:").pack(side="left")
    ttk.Entry(topbar, width=12, textvariable=user_var).pack(side="left", padx=(0, 10))

    ttk.Label(topbar, text="Pass:").pack(side="left")
    ttk.Entry(topbar, width=16, textvariable=pwd_var, show="•").pack(side="left", padx=(0, 10))

    search_btn = ttk.Button(topbar, text="검색", width=12)
    search_btn.pack(side="right")

    # 결과 테이블
    columns = ("ip", "xaddrs", "scopes")
    tree = ttk.Treeview(frm, columns=columns, show="headings", height=16)
    tree.heading("ip", text="IP")
    tree.heading("xaddrs", text="XAddrs (onvif service)")
    tree.heading("scopes", text="Scopes")
    tree.column("ip", width=160, anchor="center")
    tree.column("xaddrs", width=360, anchor="w")
    tree.column("scopes", width=340, anchor="w")
    tree.pack(fill="both", expand=True)

    # 상태바
    status = tk.StringVar()
    ttk.Label(frm, textvariable=status, anchor="w").pack(fill="x", pady=(8, 0))

    # 검색 동작
    def do_search():
        try:
            t = float(timeout_var.get())
            r = int(retries_var.get())
            ty = types_var.get().strip() or "dn:NetworkVideoTransmitter"
        except Exception:
            messagebox.showerror("오류", "Timeout/Retry 값을 확인하세요.")
            return

        for item in tree.get_children():
            tree.delete(item)
        status.set("검색 중... (멀티캐스트 239.255.255.250:3702)")

        search_btn.config(state="disabled")

        def worker():
            try:
                cams = discover_onvif_cameras(timeout=t, retries=r, types=ty)
                err = ""
            except Exception as e:
                cams = []
                err = str(e)

            def update_ui():
                for cam in cams:
                    tree.insert("", "end", values=(cam.get("ip", ""),
                                                   cam.get("xaddrs", ""),
                                                   cam.get("scopes", "")))
                if cams:
                    status.set(f"총 {len(cams)}대 발견 (더블클릭 → RTSP 재생)")
                else:
                    status.set("카메라를 찾지 못했습니다.")
                if err:
                    status.set(status.get() + f" (에러: {err})")
                search_btn.config(state="normal")

            root.after(0, update_ui)

        threading.Thread(target=worker, daemon=True).start()

    search_btn.config(command=do_search)

    # 더블클릭 → RTSP 재생
    def on_item_double_click(event):
        sel = tree.focus()
        if not sel:
            return
        vals = tree.item(sel, "values")
        if not vals:
            return
        ip, xaddrs, _ = vals
        user = user_var.get().strip()
        pwd = pwd_var.get()

        status.set(f"{ip} : ONVIF로 RTSP URI 획득 중...")

        def worker():
            try:
                uri = get_rtsp_uri_via_onvif(ip, user, pwd, xaddrs)
                if not uri:
                    raise RuntimeError("ONVIF RTSP URI를 얻을 수 없습니다.")
                msg = f"RTSP URI: {uri}"
                print(msg)
                # OpenCV 재생 (별 쓰레드에서 실행)
                play_rtsp_with_opencv(uri, window_name=f"Cam {ip}")
                err = ""
            except Exception as e:
                err = str(e)
                uri = None

            def update_ui():
                if err:
                    status.set(f"[실패] {ip} → {err}")
                else:
                    status.set(f"[재생 종료] {ip}")
            root.after(0, update_ui)

        threading.Thread(target=worker, daemon=True).start()

    tree.bind("<Double-1>", on_item_double_click)

    root.mainloop()

# ===== CLI =====
def _cli():
    import argparse, json
    parser = argparse.ArgumentParser(description="ONVIF WS-Discovery로 IP 카메라 검색 (더블클릭 재생은 --gui)")
    parser.add_argument("--timeout", type=float, default=3.0)
    parser.add_argument("--retries", type=int, default=2)
    parser.add_argument("--types", type=str, default="dn:NetworkVideoTransmitter")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--gui", action="store_true")
    args = parser.parse_args()

    if args.gui:
        run_gui()
        return

    cams = discover_onvif_cameras(timeout=args.timeout, retries=args.retries, types=args.types)
    if args.json:
        print(json.dumps(cams, ensure_ascii=False, indent=2))
    else:
        if not cams:
            print("카메라를 찾지 못했습니다.")
        for cam in cams:
            print(f"- IP: {cam['ip']}")
            if cam["xaddrs"]:
                print(f"  XAddrs : {cam['xaddrs']}")
            if cam["scopes"]:
                print(f"  Scopes : {cam['scopes']}")
            if cam["types"]:
                print(f"  Types  : {cam['types']}")
            if cam["urn"]:
                print(f"  URN    : {cam['urn']}")

if __name__ == "__main__":
    _cli()
