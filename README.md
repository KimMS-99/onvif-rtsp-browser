# ONVIF IP Camera Browser (Linux/Ubuntu)

WS-Discovery(UDP 3702)로 ONVIF IP 카메라를 검색하고, 결과를 더블클릭하면 ONVIF Media/Media2에서 RTSP URI를 얻어 OpenCV로 재생합니다.

- 구현 A: C++ / Qt Widgets / OpenCV / tinyxml2 (GUI)
- 구현 B: Python / Tkinter / OpenCV / onvif-zeep (GUI)

기본 계정 예시 admin / admin@1234는 샘플일 뿐입니다. 실제 카메라 계정/비밀번호를 사용하세요.

## 📂 폴더 구조
```bash
repo/
├─ CMakeLists.txt
├─ src/
│  └─ main.cpp                 # C++ 구현 (Qt + OpenCV + tinyxml2)
└─ python/
   └─ ipcam_onvif_browser.py   # Python 구현 (Tkinter + OpenCV + onvif-zeep)
```

C++: repo 루트에서 CMake 빌드
Python: python/ 디렉터리에서 실행

## ✅ 동작 흐름

1. WS-Discovery(239.255.255.250:3702 멀티캐스트)로 카메라 검색
2. GUI 테이블에 표시 → 더블클릭
3. ONVIF Device.GetServices / GetCapabilities로 Media/Media2 XAddr 파악
4. Media.GetProfiles → GetStreamUri로 RTSP URI 획득
5. **OpenCV(VideoCapture)**로 RTSP 스트림 재생

일부 장비는 WS-UsernameToken PasswordDigest(시간 동기화 필요) 또는 PasswordText를 요구합니다. C++ 코드는 둘 다 시도합니다.

## A) C++ (Qt + OpenCV + tinyxml2)
A-1. 의존 패키지 설치 (Ubuntu 22.04+ 기준)
```bash
$ sudo apt update
# Qt6 (권장)
$ sudo apt install -y qt6-base-dev
# OpenCV (개발 헤더/라이브러리)
$ sudo apt install -y libopencv-dev
# tinyxml2 (없어도 됨: CMake가 자동 FetchContent 구성)
$ sudo apt install -y libtinyxml2-dev
# (선택) ffmpeg 및 코덱
$ sudo apt install -y ffmpeg libavcodec-extra
```
배포판/환경에 따라 OpenCV_DIR이나 Qt 경로를 CMake에 넘겨줘야 할 수 있음.
예: -DOpenCV_DIR=/usr/lib/cmake/opencv4

## A-2. 빌드 & 실행
```bash
# repo 루트로 이동
$ cd repo
$ mkdir -p build && cd build

$ cmake .. -DCMAKE_BUILD_TYPE=Release
$ cmake --build . -j

# 실행
$ ./onvif_browser
```
처음 실행 후 카메라가 바로 안 뜨는 경우, 버튼을 다시 눌러 재시도하세요(네트워크/스위치가 멀티캐스트를 느리게 전달하는 경우가 있음).

## B) Python (Tkinter + OpenCV + onvif-zeep)
B-1. 의존 설치
```bash
$ sudo apt update
$ sudo apt install -y python3 python3-pip python3-tk ffmpeg

# (권장) 가상환경
$ python3 -m venv .venv
$ source .venv/bin/activate

$ pip install --upgrade pip
$ pip install onvif-zeep opencv-python
```

opencv-python 휠은 ffmpeg가 내장되어 있어 보통 RTSP가 바로 됩니다.
Tkinter가 없으면 python3-tk 설치 필수.

B-2. 실행
```bash
$ cd repo/python
$ python3 ipcam_onvif_browser.py --gui
```

상단에서 사용자/비밀번호, 타임아웃 등 설정 가능
검색 후 더블클릭 → RTSP 재생(OpenCV 창, ESC로 종료)