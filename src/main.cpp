// ============================================================================
// ONVIF IP 카메라 검색(WS-Discovery) + 더블클릭 시 RTSP 재생(OpenCV)
// - WS-Security UsernameToken (Digest/Text) + HTTP Basic 조합 자동 시도
// - Device.GetServices → Media/Media2 XAddr → GetProfiles → GetStreamUri
// - 401시 즉시 Basic-only 재시도, 카메라 시간으로 PasswordDigest 보정
// - 성공 경로/인증 조합/RTSP를 QSettings 캐시 → 다음엔 먼저 사용
// - 라벨 size 기준 스케일로 "계속 확대" 현상 제거
// ============================================================================

#include <QtWidgets>
#include <QtNetwork>
#include <QtConcurrent>
#include <QFuture>
#include <QDeadlineTimer>
#include <QSslConfiguration>
#include <QCryptographicHash>
#include <QSettings>

#include <tinyxml2.h>
#include <opencv2/opencv.hpp>

#include <thread>
#include <atomic>
#include <random>
#include <map>
#include <array>

// POSIX / BSD sockets (리눅스)
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/time.h>

using namespace tinyxml2;

// ========================= 상수 =========================
static const char* WS_ACTION_PROBE = "http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe";
static const char* WS_TO           = "urn:schemas-xmlsoap-org:ws:2005:04/discovery";
static const char* MULTICAST_ADDR  = "239.255.255.250";
static const uint16_t WS_DISCOVERY_PORT = 3702;

static const char* NS_e   = "http://www.w3.org/2003/05/soap-envelope";
static const char* NS_w   = "http://schemas.xmlsoap.org/ws/2004/08/addressing";
static const char* NS_d   = "http://schemas.xmlsoap.org/ws/2005/04/discovery";
static const char* NS_dn  = "http://www.onvif.org/ver10/network/wsdl";
static const char* NS_tds = "http://www.onvif.org/ver10/device/wsdl";

struct CamInfo {
    QString ip;
    QString xaddrs;
    QString scopes;
    QString types;
    QString urn;
};

// ========================= 유틸 =========================
static QByteArray makeProbeMessage(const QString& types = "dn:NetworkVideoTransmitter") {
    const QString mid = QString("uuid:%1").arg(QUuid::createUuid().toString(QUuid::WithoutBraces));
    QByteArray xml;
    xml += "<?xml version=\"1.0\" encoding=\"utf-8\"?>";
    xml += QString(
        R"(<e:Envelope xmlns:e="%1" xmlns:w="%2" xmlns:d="%3" xmlns:dn="%4" xmlns:tds="%5">
            <e:Header>
                <w:MessageID>%6</w:MessageID>
                <w:To>%7</w:To>
                <w:Action>%8</w:Action>
            </e:Header>
            <e:Body>
                <d:Probe>
                    <d:Types>%9</d:Types>
                </d:Probe>
            </e:Body>
        </e:Envelope>)")
            .arg(NS_e).arg(NS_w).arg(NS_d).arg(NS_dn).arg(NS_tds)
            .arg(mid).arg(WS_TO).arg(WS_ACTION_PROBE).arg(types)
            .toUtf8();
    return xml;
}

static QString textOf(XMLElement* e){
    if(!e || !e->GetText()) return {};
    return QString::fromUtf8(e->GetText()).trimmed();
}

static CamInfo parseProbeMatch(const QByteArray& dat){
    CamInfo out;
    XMLDocument doc; doc.Parse(dat.constData(), dat.size());
    if(doc.Error()) return out;
    XMLElement* probeMatch = nullptr;
    std::function<void(XMLElement*)> dfs = [&](XMLElement* el){
        if(!el) return;
        QString name = el->Name();
        if(name.endsWith(":ProbeMatch")) probeMatch = el;
        for(auto* c = el->FirstChildElement(); c; c = c->NextSiblingElement()) dfs(c);
    };
    dfs(doc.RootElement());
    if(!probeMatch) return out;

    QString urn;
    for(auto* e = probeMatch->FirstChildElement(); e; e = e->NextSiblingElement()){
        QString nm = e->Name();
        if(nm.endsWith(":EndpointReference")){
            for(auto* a = e->FirstChildElement(); a; a = a->NextSiblingElement()){
                if(QString(a->Name()).endsWith(":Address")) urn = textOf(a);
            }
        } else if(nm.endsWith(":XAddrs")) {
            out.xaddrs = textOf(e);
        } else if(nm.endsWith(":Scopes")) {
            out.scopes = textOf(e);
        } else if(nm.endsWith(":Types")){
            out.types = textOf(e);
        }
    }
    out.urn = urn;

    auto extractIp = [](const QString& x)->QString{
        auto parts = x.split(QRegularExpression("\\s+"), Qt::SkipEmptyParts);
        for(const QString& u: parts){
            if(u.startsWith("http://") || u.startsWith("https://")){
                QString rest = u.section("://",1);
                QString hostport = rest.section('/',0,0);
                if(hostport.startsWith('[')) continue; // IPv6 skip
                QString host = hostport.contains(':') ? hostport.section(':',0,0) : hostport;
                QHostAddress ha(host);
                if(ha.protocol() == QAbstractSocket::IPv4Protocol) return host;
            }
        }
        return {};
    };
    out.ip = extractIp(out.xaddrs);
    return out;
}

static std::pair<QString, int> extractIpPortFromXAddrs(const QString& xaddrs){
    QString ip; int port = 0;
    auto parts = xaddrs.split(QRegularExpression("\\s+"), Qt::SkipEmptyParts);
    for(const QString& u: parts){
        if(u.startsWith("http://") || u.startsWith("https://")){
            QString rest = u.section("://",1);
            QString hostport = rest.section('/',0,0);
            if(hostport.startsWith('[')) continue; // IPv6 skip
            if(hostport.contains(':')){
                ip = hostport.section(':',0,0);
                bool ok=false; int p=hostport.section(':',1,1).toInt(&ok); if(ok) {port=p; return {ip,port};}
                else {return {ip,0};}
            } else { ip = hostport; return {ip,80}; }
        }
    }
    return {ip,0};
}

// ========================= WS-Discovery (UDP 멀티캐스트) =========================
static QList<CamInfo> discoverOnvifCameras(double timeoutSec, int retries, const QString& types){
    QList<CamInfo> out;

    int sock = ::socket(AF_INET, SOCK_DGRAM, 0);
    if(sock < 0){ return out; }

    int ttl = 1; setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL, (char*)&ttl, sizeof(ttl));
    struct timeval tv{ (int)timeoutSec, (int)((timeoutSec - (int)timeoutSec)*1e6) };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(tv));

    sockaddr_in local{}; local.sin_family = AF_INET; local.sin_addr.s_addr = htonl(INADDR_ANY); local.sin_port = htons(0);
    ::bind(sock, (sockaddr*)&local, sizeof(local));

    QByteArray probe = makeProbeMessage(types);
    std::map<QString, CamInfo> byIp;

    for(int r=0; r<retries; ++r){
        sockaddr_in maddr{}; maddr.sin_family = AF_INET; maddr.sin_port = htons(WS_DISCOVERY_PORT); maddr.sin_addr.s_addr = inet_addr(MULTICAST_ADDR);
        ::sendto(sock, probe.constData(), (int)probe.size(), 0, (sockaddr*)&maddr, sizeof(maddr));

        auto endAt = QDeadlineTimer(int(timeoutSec*1000));
        while(!endAt.hasExpired()){
            char buf[16384]; sockaddr_in src{}; socklen_t slen=sizeof(src);
            int n = ::recvfrom(sock, buf, sizeof(buf), 0, (sockaddr*)&src, &slen);
            if(n <= 0) break;
            QByteArray dat(buf, n);
            CamInfo ci = parseProbeMatch(dat);
            if(ci.ip.isEmpty()){
                char ipbuf[64]; inet_ntop(AF_INET, &src.sin_addr, ipbuf, sizeof(ipbuf)); ci.ip = ipbuf;
            }
            if(!ci.ip.isEmpty() && !byIp.count(ci.ip)) byIp[ci.ip] = ci;
        }
    }
    ::close(sock);

    for(auto& kv : byIp) out.push_back(kv.second);
    return out;
}

// ========================= HTTP SOAP (SOAP 1.2 → 1.1 재시도) + Optional HTTP Basic =========================
static QByteArray httpPostXml(const QUrl& url,
                              const QByteArray& xmlBody,
                              const QString& soapAction = QString(),
                              int timeoutMs = 6000,
                              bool* okOut=nullptr,
                              QString* errOut=nullptr,
                              const QString& httpBasicUser = QString(),
                              const QString& httpBasicPass = QString())
{
    auto doPost = [&](bool soap12, QByteArray& resp, QString& err)->bool {
        QNetworkAccessManager mgr;
        QNetworkRequest req(url);

        if (soap12) {
            QString ct = "application/soap+xml; charset=utf-8";
            if (!soapAction.isEmpty())
                ct += QString("; action=\"%1\"").arg(soapAction);
            req.setHeader(QNetworkRequest::ContentTypeHeader, ct);
        } else {
            req.setHeader(QNetworkRequest::ContentTypeHeader, "text/xml; charset=utf-8");
            if (!soapAction.isEmpty())
                req.setRawHeader("SOAPAction", QString("\"%1\"").arg(soapAction).toUtf8());
        }

        // HTTP Basic
        if (!httpBasicUser.isEmpty()) {
            QByteArray up = (httpBasicUser + ":" + httpBasicPass).toUtf8();
            req.setRawHeader("Authorization", "Basic " + up.toBase64());
        }

        if (url.scheme().toLower() == "https") {
            QSslConfiguration conf = QSslConfiguration::defaultConfiguration();
            conf.setPeerVerifyMode(QSslSocket::VerifyNone); // 자가서명 허용
            req.setSslConfiguration(conf);
        }

        QEventLoop loop; bool ok=false;
        QTimer timer; timer.setSingleShot(true);
        QObject::connect(&timer, &QTimer::timeout, &loop, [&]{ err = "HTTP timeout"; loop.quit(); });
        QObject::connect(&mgr, &QNetworkAccessManager::finished, &loop, [&](QNetworkReply* r){
            QVariant vCode = r->attribute(QNetworkRequest::HttpStatusCodeAttribute);
            int code = vCode.isValid() ? vCode.toInt() : 0;
            QByteArray body = r->readAll();

            if (r->error() == QNetworkReply::NoError && code >= 200 && code < 300) {
                resp = body; ok = true;
            } else {
                resp = body;
                err = QString("%1%2")
                          .arg(r->error() == QNetworkReply::NoError ? "" : r->errorString() + " | ")
                          .arg(code ? QString("HTTP %1").arg(code) : QString("HTTP ?"));
            }
            r->deleteLater(); loop.quit();
        });

        (void)mgr.post(req, xmlBody);
        timer.start(timeoutMs);
        loop.exec();
        return ok;
    };

    QByteArray resp; QString err;
    bool ok = doPost(true, resp, err);           // SOAP 1.2
    if (!ok) {
        QByteArray resp2; QString err2;
        bool ok2 = doPost(false, resp2, err2);   // SOAP 1.1
        if (okOut) *okOut = ok2;
        if (errOut) *errOut = ok2 ? QString() : err2;
        return ok2 ? resp2 : resp;
    } else {
        if (okOut) *okOut = true;
        if (errOut) *errOut = QString();
        return resp;
    }
}

// ========================= WS-Security UsernameToken =========================
static QString wsseUsernameToken_PasswordText(const QString& user, const QString& pass){
    if(user.isEmpty()) return "";
    return QString(
        R"(<wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
             <wsse:UsernameToken>
               <wsse:Username>%1</wsse:Username>
               <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">%2</wsse:Password>
             </wsse:UsernameToken>
           </wsse:Security>)").arg(user, pass);
}

// PasswordDigest = Base64( SHA1( NonceRaw + Created + Password ) ), Created는 UTC 'Z'
static QString wsseUsernameToken_PasswordDigest_withCreated(const QString& user,
                                                            const QString& pass,
                                                            const QString& createdUtcIso)
{
    if(user.isEmpty() || createdUtcIso.isEmpty()) return "";
    std::array<unsigned char,16> nonceRaw{};
    std::random_device rd; std::mt19937 gen(rd()); std::uniform_int_distribution<int> dis(0,255);
    for (auto& b : nonceRaw) b = static_cast<unsigned char>(dis(gen));
    QByteArray nonceBA(reinterpret_cast<const char*>(nonceRaw.data()), (int)nonceRaw.size());
    QString nonceB64 = nonceBA.toBase64();

    QByteArray toHash = nonceBA + createdUtcIso.toUtf8() + pass.toUtf8();
    QByteArray sha1   = QCryptographicHash::hash(toHash, QCryptographicHash::Sha1);
    QString digestB64 = sha1.toBase64();

    return QString(
        R"(<wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
                         xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
             <wsse:UsernameToken>
               <wsse:Username>%1</wsse:Username>
               <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">%2</wsse:Password>
               <wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">%3</wsse:Nonce>
               <wsu:Created>%4</wsu:Created>
             </wsse:UsernameToken>
           </wsse:Security>)")
        .arg(user, digestB64, nonceB64, createdUtcIso);
}

static QByteArray soapEnvelope(const QString& headerXml, const QString& bodyXml){
    return QString(
        R"(<?xml version="1.0" encoding="utf-8"?>
           <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
                       xmlns:tds="http://www.onvif.org/ver10/device/wsdl"
                       xmlns:trt="http://www.onvif.org/ver10/media/wsdl"
                       xmlns:tr2="http://www.onvif.org/ver20/media/wsdl"
                       xmlns:tt="http://www.onvif.org/ver10/schema">
             <s:Header>%1</s:Header>
             <s:Body>%2</s:Body>
           </s:Envelope>)").arg(headerXml, bodyXml).toUtf8();
}

// ========================= XML helpers =========================
static QString firstText(XMLDocument& doc, const std::vector<const char*>& suffixes){
    QString out;
    std::function<void(XMLElement*)> dfs = [&](XMLElement* el){
        if(!el || !out.isEmpty()) return;
        QString nm = el->Name();
        for (auto* suf : suffixes) {
            if (nm.endsWith(suf) && el->GetText()) { out = el->GetText(); return; }
        }
        for(auto* c = el->FirstChildElement(); c && out.isEmpty(); c = c->NextSiblingElement()) dfs(c);
    };
    dfs(doc.RootElement());
    return out;
}

static QString extractProfileToken(XMLDocument& d){
    QString token;
    std::function<void(XMLElement*)> dfs = [&](XMLElement* el){
        if(!el || !token.isEmpty()) return;
        QString nm = el->Name();
        if (nm.endsWith(":Profiles") || nm.endsWith(":Profile")) {
            const char* t = el->Attribute("token");
            if(t && *t){ token = t; return; }
        }
        for(auto* c = el->FirstChildElement(); c && token.isEmpty(); c = c->NextSiblingElement()) dfs(c);
    };
    dfs(d.RootElement());
    if(!token.isEmpty()) return token;
    token = firstText(d, {":token", ":Token", ":ProfileToken", ":Name"});
    return token;
}

// ========================= 카메라 시간 얻기 =========================
static QString getCameraUtcIso(const QUrl& devUrl,
                               const QString& httpUser, const QString& httpPass)
{
    QByteArray body = QByteArray("<tds:GetSystemDateAndTime/>");
    QString action = "http://www.onvif.org/ver10/device/wsdl/GetSystemDateAndTime";
    bool ok=false; QString err;
    QByteArray resp = httpPostXml(devUrl, soapEnvelope(QString(), body), action,
                                  4000, &ok, &err, httpUser, httpPass);
    if(!ok) return QString();

    XMLDocument d; d.Parse(resp.constData(), resp.size());
    QString yyyy = firstText(d, {":Year"});
    QString mon  = firstText(d, {":Month"});
    QString day  = firstText(d, {":Day"});
    QString hh   = firstText(d, {":Hour"});
    QString mm   = firstText(d, {":Minute"});
    QString ss   = firstText(d, {":Second"});

    if(yyyy.isEmpty()) return QString();
    return QString("%1-%2-%3T%4:%5:%6Z")
            .arg(yyyy,
                 mon.rightJustified(2, '0'),
                 day.rightJustified(2,'0'),
                 hh.rightJustified(2,'0'),
                 mm.rightJustified(2,'0'),
                 ss.rightJustified(2,'0'));
}

// ========================= GetServices → Media XAddr =========================
struct MediaSvc { QUrl url; bool isV20=false; };

// ========================= ONVIF Media/Media2: RTSP URI 얻기 =========================
static QString getRtspUriViaOnvif(const QString& ip, const QString& user, const QString& pass, const QString& xaddrs){
    auto [ipGuess, portGuess] = extractIpPortFromXAddrs(xaddrs);
    QList<int> ports; if(portGuess>0) ports<<portGuess; ports<<80<<8080<<8899<<8000<<85;

    auto tryDevice = [&](const QUrl& devUrl)->QString{
        // 카메라 시간을 얻어 Digest의 Created 보정
        QString camCreated = getCameraUtcIso(devUrl, user, pass);
        const QString wsseDigest = camCreated.isEmpty()
            ? wsseUsernameToken_PasswordDigest_withCreated(user, pass, QDateTime::currentDateTimeUtc().toString("yyyy-MM-ddThh:mm:ss'Z'"))
            : wsseUsernameToken_PasswordDigest_withCreated(user, pass, camCreated);
        const QString wsseText   = wsseUsernameToken_PasswordText(user, pass);

        // 조합: 성공하면 캐시에 저장, 이후엔 그 조합만 먼저 시도
        struct Variant { QString wsse; bool useHttpBasic; const char* name; };
        QVector<Variant> variants = {
            { wsseDigest, true , "wsseDigest+basic" },
            { wsseText  , true , "wsseText+basic"  },
            { QString() , true , "basicOnly"       },
            { wsseDigest, false, "wsseDigest"      },
            { wsseText  , false, "wsseText"        },
            { QString() , false, "noAuth"          },
        };

        // 캐시된 조합 있으면 앞으로
        QSettings st("OnvifRtspBrowser","onvif");
        st.beginGroup(ip);
        QString cachedAuth = st.value("auth/wsse").toString();   // "digest","text","none"
        bool    cachedBasic= st.value("auth/basic", false).toBool();
        st.endGroup();
        if(!cachedAuth.isEmpty()){
            auto key2wsse = [&](const QString& k)->QString{
                if(k=="digest") return wsseDigest;
                if(k=="text")   return wsseText;
                return QString();
            };
            Variant preferred { key2wsse(cachedAuth), cachedBasic, "cached" };
            // 맨 앞에 삽입 (중복 제거는 단순화)
            variants.prepend(preferred);
        }

        auto call = [&](const QUrl& url, const QByteArray& env, const QString& action,
                        const Variant& v, bool* ok, QString* err)->QByteArray{
            QByteArray r = httpPostXml(url, env, action, 6000, ok, err,
                                       v.useHttpBasic ? user : QString(),
                                       v.useHttpBasic ? pass : QString());
            // 401 즉시 Basic-only 재시도
            if(!(*ok) && err->contains("HTTP 401") && !(v.useHttpBasic==true && v.wsse.isEmpty())){
                bool ok2=false; QString e2;
                QByteArray r2 = httpPostXml(url, env, action, 6000, &ok2, &e2, user, pass);
                if(ok2){ *ok=true; *err=QString(); return r2; }
            }
            return r;
        };

        for (const Variant& v : variants) {
            QList<MediaSvc> services;

            // 1) GetServices
            {
                QByteArray body = QByteArray(
                    R"(<tds:GetServices>
                           <tds:IncludeCapability>false</tds:IncludeCapability>
                       </tds:GetServices>)");
                QString action = "http://www.onvif.org/ver10/device/wsdl/GetServices";
                bool ok=false; QString err;
                QByteArray resp = call(devUrl, soapEnvelope(v.wsse, body), action, v, &ok, &err);
                if(ok){
                    XMLDocument d; d.Parse(resp.constData(), resp.size());
                    std::function<void(XMLElement*)> dfs = [&](XMLElement* el){
                        if(!el) return;
                        QString nm = el->Name();
                        if(nm.endsWith(":Service")){
                            QString locNs, locXAddr;
                            for(auto* c=el->FirstChildElement(); c; c=c->NextSiblingElement()){
                                QString cn = c->Name();
                                if(cn.endsWith(":Namespace")) locNs = textOf(c);
                                if(cn.endsWith(":XAddr"))     locXAddr = textOf(c);
                            }
                            if(!locNs.isEmpty() && !locXAddr.isEmpty()){
                                if(locNs.contains("/ver10/media/wsdl")){
                                    services.push_back({ QUrl(locXAddr), false });
                                } else if(locNs.contains("/ver20/media/wsdl")){
                                    services.push_back({ QUrl(locXAddr), true });
                                }
                            }
                        }
                        for(auto* c = el->FirstChildElement(); c; c = c->NextSiblingElement()) dfs(c);
                    };
                    dfs(d.RootElement());
                } else {
                    qWarning() << "[GetServices]" << devUrl << err;
                }
            }

            // 2) 폴백: GetCapabilities 또는 표준 경로
            if(services.isEmpty()){
                QByteArray capBody = QByteArray(
                    R"(<tds:GetCapabilities>
                           <tds:Category>All</tds:Category>
                       </tds:GetCapabilities>)");
                QString action = "http://www.onvif.org/ver10/device/wsdl/GetCapabilities";
                bool ok=false; QString err;
                QByteArray resp = call(devUrl, soapEnvelope(v.wsse, capBody), action, v, &ok, &err);
                if(ok) {
                    XMLDocument d1; d1.Parse(resp.constData(), resp.size());
                    QString mediaX = firstText(d1, {":XAddr"});
                    if(!mediaX.isEmpty()) services.push_back({ QUrl(mediaX), false });
                } else {
                    qWarning() << "[GetCapabilities]" << devUrl << err;
                }
                if(services.isEmpty()){
                    QString base = devUrl.scheme() + "://" + devUrl.host() + ":" + QString::number(devUrl.port());
                    services.push_back({ QUrl(base + "/onvif/Media"), false });
                    services.push_back({ QUrl(base + "/onvif/Media2"), true  });
                }
            }

            // 3) Media/Media2 → GetProfiles → GetStreamUri
            for (const MediaSvc& svc : services) {
                bool ok=false; QString err;

                // GetProfiles
                QString actionProfiles = svc.isV20
                    ? "http://www.onvif.org/ver20/media/wsdl/GetProfiles"
                    : "http://www.onvif.org/ver10/media/wsdl/GetProfiles";
                QByteArray envProfiles = soapEnvelope(v.wsse,
                    svc.isV20 ? QByteArray("<tr2:GetProfiles/>")
                              : QByteArray("<trt:GetProfiles/>"));

                QByteArray r2 = call(svc.url, envProfiles, actionProfiles, v, &ok, &err);
                if(!ok){ qWarning() << "[GetProfiles]" << svc.url << err; continue; }

                XMLDocument d2; d2.Parse(r2.constData(), r2.size());
                QString token = extractProfileToken(d2);
                if(token.isEmpty()){ qWarning() << "ProfileToken not found"; continue; }

                // GetStreamUri
                QString actionStream = svc.isV20
                    ? "http://www.onvif.org/ver20/media/wsdl/GetStreamUri"
                    : "http://www.onvif.org/ver10/media/wsdl/GetStreamUri";

                QString body3 = svc.isV20
                    ? QString(
                        R"(<tr2:GetStreamUri xmlns:tr2="http://www.onvif.org/ver20/media/wsdl" xmlns:tt="http://www.onvif.org/ver10/schema">
                               <tr2:StreamSetup>
                                 <tt:Stream>RTP-Unicast</tt:Stream>
                                 <tt:Transport><tt:Protocol>RTSP</tt:Protocol></tt:Transport>
                               </tr2:StreamSetup>
                               <tr2:ProfileToken>%1</tr2:ProfileToken>
                           </tr2:GetStreamUri>)").arg(token)
                    : QString(
                        R"(<trt:GetStreamUri xmlns:trt="http://www.onvif.org/ver10/media/wsdl" xmlns:tt="http://www.onvif.org/ver10/schema">
                               <trt:StreamSetup>
                                 <tt:Stream>RTP-Unicast</tt:Stream>
                                 <tt:Transport><tt:Protocol>RTSP</tt:Protocol></tt:Transport>
                               </trt:StreamSetup>
                               <trt:ProfileToken>%1</trt:ProfileToken>
                           </trt:GetStreamUri>)").arg(token);

                QByteArray r3 = call(svc.url, soapEnvelope(v.wsse, body3), actionStream, v, &ok, &err);
                if(!ok){ qWarning() << "[GetStreamUri]" << svc.url << err; continue; }

                XMLDocument d3; d3.Parse(r3.constData(), r3.size());
                QString uri = firstText(d3, {":Uri", ":URI"});
                if(!uri.isEmpty()){
                    if(uri.startsWith("rtsp://") && !uri.contains('@') && !user.isEmpty()){
                        uri.replace("rtsp://", QString("rtsp://%1:%2@").arg(user, pass));
                    }
                    // 캐시
                    QSettings st("OnvifRtspBrowser","onvif");
                    st.beginGroup(ip);
                    st.setValue("mediaUrl", svc.url.toString());
                    st.setValue("isV20",   svc.isV20);
                    st.setValue("profile", token);
                    st.setValue("rtsp",    uri);
                    QString wsseKey = v.wsse.isEmpty() ? "none" : (v.wsse.contains("PasswordDigest") ? "digest" : "text");
                    st.setValue("auth/wsse", wsseKey);
                    st.setValue("auth/basic", v.useHttpBasic);
                    st.endGroup();
                    return uri;
                }
            } // services
        } // variants

        return QString();
    };

    for(int p: ports){
        QString scheme = (xaddrs.startsWith("https://", Qt::CaseInsensitive) ? "https" : "http");
        QUrl devUrl(QString("%1://%2:%3/onvif/device_service").arg(scheme, ip).arg(p));
        QString uri = tryDevice(devUrl);
        if(!uri.isEmpty()) return uri;
    }
    return {};
}

// ========================= OpenCV 재생 =========================
static bool openRtsp(cv::VideoCapture& cap, const std::string& uri){
    // 1) 기본(보통 UDP)
    if (cap.open(uri, cv::CAP_FFMPEG)) return true;
    // 2) TCP 강제 재시도
    std::string u2 = uri;
    if (uri.find('?') == std::string::npos) u2 += "?rtsp_transport=tcp";
    else                                    u2 += "&rtsp_transport=tcp";
    cap.release();
    if (cap.open(u2, cv::CAP_FFMPEG)) return true;
    return false;
}

class RtspPlayerWindow : public QDialog{
    Q_OBJECT
public:
    explicit RtspPlayerWindow(const QString& uri, QWidget* parent=nullptr)
        : QDialog(parent), uri_(uri){
        setWindowTitle("IP Camera");
        resize(960,540);
        label_ = new QLabel("Connecting...", this);
        label_->setAlignment(Qt::AlignCenter);
        label_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
        label_->setMinimumSize(QSize(320, 180));
        label_->setScaledContents(false); // 우리가 직접 스케일
        label_->setStyleSheet("background:black; color:white;");
        auto lay = new QVBoxLayout(this);
        lay->setContentsMargins(0,0,0,0);
        lay->addWidget(label_);
        playThread_ = std::thread([this]{ run(); });
    }
    ~RtspPlayerWindow(){ running_ = false; if(playThread_.joinable()) playThread_.join(); }
private:
    void run(){
        cv::VideoCapture cap;
        std::string s = uri_.toStdString();
        if(!openRtsp(cap, s)){
            QMetaObject::invokeMethod(label_, [this]{ label_->setText("RTSP 연결 실패"); });
            return;
        }
        cv::Mat frame;
        while(running_){
            if(!cap.read(frame) || frame.empty()){
                QThread::msleep(10);
                continue;
            }
            cv::Mat rgb; cv::cvtColor(frame, rgb, cv::COLOR_BGR2RGB);
            QImage qimg(rgb.data, rgb.cols, rgb.rows, (int)rgb.step, QImage::Format_RGB888);
            // ★ 라벨의 현재 크기에 맞춰 스케일 (다이얼로그 전체 size()가 아니라 label_->size())
            QSize target = label_->size();
            QImage scaled = qimg.scaled(target, Qt::KeepAspectRatio, Qt::SmoothTransformation);
            QMetaObject::invokeMethod(label_, [this, scaled]{
                label_->setPixmap(QPixmap::fromImage(scaled));
            });
            QThread::msleep(15);
        }
        cap.release();
    }
    QString uri_;
    QLabel* label_{};
    std::thread playThread_;
    std::atomic<bool> running_{true};
};

// ========================= 메인 GUI =========================
class MainWindow : public QMainWindow{
    Q_OBJECT
public:
    MainWindow(){
        setWindowTitle("IP 카메라 검색기 (ONVIF → RTSP 보기)");
        resize(980,620);
        auto central = new QWidget; setCentralWidget(central);
        auto v = new QVBoxLayout(central);

        // Top bar
        auto hb = new QHBoxLayout;
        timeoutEdit_ = new QLineEdit("3.0"); timeoutEdit_->setFixedWidth(60);
        retriesEdit_ = new QLineEdit("2");   retriesEdit_->setFixedWidth(40);
        typesEdit_   = new QLineEdit("dn:NetworkVideoTransmitter"); typesEdit_->setMinimumWidth(260);
        userEdit_    = new QLineEdit("admin"); userEdit_->setFixedWidth(120);
        passEdit_    = new QLineEdit("admin@1234"); passEdit_->setEchoMode(QLineEdit::Password); passEdit_->setFixedWidth(160);
        searchBtn_   = new QPushButton("검색"); searchBtn_->setFixedWidth(100);

        hb->addWidget(new QLabel("Timeout(s):")); hb->addWidget(timeoutEdit_);
        hb->addWidget(new QLabel("Retries:"));    hb->addWidget(retriesEdit_);
        hb->addWidget(new QLabel("Types:"));      hb->addWidget(typesEdit_,1);
        hb->addWidget(new QLabel("User:"));       hb->addWidget(userEdit_);
        hb->addWidget(new QLabel("Pass:"));       hb->addWidget(passEdit_);
        hb->addStretch(); hb->addWidget(searchBtn_);
        v->addLayout(hb);

        // Table
        table_ = new QTableWidget(0,3);
        table_->setSelectionBehavior(QAbstractItemView::SelectRows);
        table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
        QStringList headers{ "IP", "XAddrs (onvif service)", "Scopes"};
        table_->setHorizontalHeaderLabels(headers);
        table_->horizontalHeader()->setStretchLastSection(true);
        table_->setColumnWidth(0,160); table_->setColumnWidth(1,380);
        v->addWidget(table_,1);

        // status
        status_ = new QLabel; v->addWidget(status_);

        connect(searchBtn_, &QPushButton::clicked, this, &MainWindow::onSearch);
        connect(table_, &QTableWidget::cellDoubleClicked, this, &MainWindow::onDoubleClick);
    }

private slots:
    void onSearch(){
        bool ok1=false, ok2=false;
        double t = timeoutEdit_->text().toDouble(&ok1);
        int    r = retriesEdit_->text().toInt(&ok2);
        if(!ok1||!ok2){ QMessageBox::warning(this,"오류","Timeout/Retry 값을 확인하세요."); return; }
        QString types = typesEdit_->text().trimmed(); if(types.isEmpty()) types = "dn:NetworkVideoTransmitter";

        table_->setRowCount(0);
        status_->setText("검색 중... (멀티캐스트 239.255.255.250:3702)");
        searchBtn_->setEnabled(false);

        QFuture<void> fut = QtConcurrent::run([=]{
            QList<CamInfo> cams = discoverOnvifCameras(t, r, types);
            QMetaObject::invokeMethod(this, [=]{
                for(const auto& c : cams){
                    int row = table_->rowCount(); table_->insertRow(row);
                    table_->setItem(row,0,new QTableWidgetItem(c.ip));
                    table_->setItem(row,1,new QTableWidgetItem(c.xaddrs));
                    table_->setItem(row,2,new QTableWidgetItem(c.scopes));
                }
                if(cams.isEmpty()) status_->setText("카메라를 찾지 못했습니다.");
                else status_->setText(QString("총 %1대 발견 (더블클릭 → RTSP 재생)").arg(cams.size()));
                searchBtn_->setEnabled(true);
            });
        });
        Q_UNUSED(fut);
    }

    void onDoubleClick(int row, int /*col*/){
        QString ip = table_->item(row,0)->text();
        QString xaddrs = table_->item(row,1)->text();
        QString user = userEdit_->text().trimmed();
        QString pass = passEdit_->text();

        status_->setText(ip + " : RTSP URI 획득/재사용 중...");

        // 캐시된 RTSP 먼저 사용
        QSettings st("OnvifRtspBrowser","onvif");
        st.beginGroup(ip);
        QString cachedRtsp = st.value("rtsp").toString();
        st.endGroup();
        if(!cachedRtsp.isEmpty()){
            auto dlg = new RtspPlayerWindow(cachedRtsp, this);
            dlg->setAttribute(Qt::WA_DeleteOnClose);
            dlg->show();
            return;
        }

        QFuture<void> fut = QtConcurrent::run([=]{
            QString uri = getRtspUriViaOnvif(ip, user, pass, xaddrs);
            QMetaObject::invokeMethod(this, [=]{
                if(uri.isEmpty()){
                    status_->setText("[실패] " + ip + " → ONVIF RTSP URI를 얻을 수 없습니다.");
                } else {
                    qDebug() << "RTSP URI:" << uri;
                    status_->setText("RTSP 열기: " + uri);
                    auto dlg = new RtspPlayerWindow(uri, this);
                    dlg->setAttribute(Qt::WA_DeleteOnClose);
                    dlg->show();
                }
            });
        });
        Q_UNUSED(fut);
    }

private:
    QLineEdit *timeoutEdit_{}, *retriesEdit_{}, *typesEdit_{}, *userEdit_{}, *passEdit_{};
    QPushButton*   searchBtn_{};
    QTableWidget*  table_{};
    QLabel*        status_{};
};

int main(int argc, char** argv){
    QApplication app(argc, argv);
    QCoreApplication::setOrganizationName("OnvifRtspBrowser");
    QCoreApplication::setApplicationName("onvif");
    MainWindow w; w.show();
    return app.exec();
}

#include "main.moc"
