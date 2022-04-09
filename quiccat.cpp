﻿#include "quiccat.h"

using namespace std;
using namespace std::chrono;

const uint32_t DefaultSendBufferSize = 128 * 1024;
const uint32_t MaxFileNameLength = 255;
const auto UpdateRate = milliseconds(500);

const MsQuicApi* MsQuic;

const MsQuicAlpn Alpn("quiccat");

struct QcConnection {
    MsQuicConnection* Connection;
    MsQuicStream* Stream;
    CXPLAT_EVENT ConnectionShutdownEvent;
    ofstream DestinationFile;
    filesystem::path DestinationPath;
    string FileName;
    uint64_t BytesReceived;
    uint64_t BytesReceivedSnapshot;
    steady_clock::time_point StartTime;
    steady_clock::time_point LastUpdate;
    steady_clock::time_point EndTime;
    unique_ptr<uint8_t[]> SendBuffer;
    CXPLAT_EVENT SendCompleteEvent;
    QUIC_BUFFER SendQuicBuffer;
    uint64_t FileSize = 0;
    uint32_t IdealSendSize = DefaultSendBufferSize;
    uint32_t CurrentSendSize;
    bool SendCanceled = false;
};

struct QcListener {
    MsQuicConnection* Connection;
    MsQuicConfiguration* Config;
    MsQuicListener* Listener;
    CXPLAT_EVENT ConnectionReceivedEvent;
    QcConnection ConnectionContext;
};

void
PrintProgress(
    _In_ const string& FileName,
    _In_ const uint64_t BytesComplete,
    _In_ const uint64_t BytesTotal,
    _In_ const steady_clock::duration ElapsedTime,
    _In_ const uint64_t RateBytes,
    _In_ const steady_clock::duration RateTime
    )
{
    static const int ProgressBarWidth = 48;
    const float ProgressFraction = (float)BytesComplete / BytesTotal;
    const auto BytesRemaining = BytesComplete < BytesTotal ? BytesTotal - BytesComplete : 0;
    const auto EstimatedRemaining = (ElapsedTime / BytesComplete) * BytesRemaining;

    cout << "\r";
    if (FileName.length() < 29) {
        cout << FileName;
    } else {
        cout << FileName.substr(0,26) << "...";
    }
    cout << " [";
    int pos = ProgressBarWidth * ProgressFraction;
    for (int i = 0; i < ProgressBarWidth; ++i) {
        if (i <= pos) {
            cout << "|";
        } else {
            cout << " ";
        }
    }
    cout << "] " << setw(3) << (int)(ProgressFraction * 100.0) << "%";
    cout << " " << setw(5) << duration_cast<minutes>(EstimatedRemaining)
        << setw(3) << duration_cast<seconds>(EstimatedRemaining) - duration_cast<minutes>(EstimatedRemaining);
    if (RateTime > steady_clock::duration(0)) {
        const auto BitsPerSecond =
            (RateBytes * 8 * steady_clock::duration::period::den) /
            (RateTime.count() * steady_clock::duration::period::num);
        if (BitsPerSecond >= 1000000000) {
            cout << " " << setw(5) << setprecision(4) << BitsPerSecond / 1000000000.0 << "Gbps";
        } else if (BitsPerSecond >= 1000000) {
            cout << " " << setw(5) << setprecision(4) << BitsPerSecond / 1000000.0 << "Mbps";
        } else if (BitsPerSecond >= 1000) {
            cout << " " << setw(5) << setprecision(4) << BitsPerSecond / 1000.0 << "Kbps";
        } else {
            cout << " " << setw(5) << BitsPerSecond << "bps";
        }
    }
    cout.flush();
}

QUIC_STATUS
QcFileSendStreamCallback(
    _In_ MsQuicStream* Stream,
    _In_opt_ void* Context,
    _Inout_ QUIC_STREAM_EVENT* Event
    )
{
    auto Connection = (QcConnection*)Context;
    switch (Event->Type) {
    case QUIC_STREAM_EVENT_START_COMPLETE:
        if (QUIC_FAILED(Event->START_COMPLETE.Status)) {
            cout << "Stream start result: " << hex << Event->START_COMPLETE.Status << dec << endl;
            return Event->START_COMPLETE.Status;
        }
        break;
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        if (Event->SEND_COMPLETE.Canceled) {
            Connection->SendCanceled = true;
        }
        CxPlatEventSet(Connection->SendCompleteEvent);
        break;
    case QUIC_STREAM_EVENT_IDEAL_SEND_BUFFER_SIZE:
        if (Connection->IdealSendSize != Event->IDEAL_SEND_BUFFER_SIZE.ByteCount) {
            //cout << "ISB changed; was: " << Connection->IdealSendSize << " now: " << Event->IDEAL_SEND_BUFFER_SIZE.ByteCount << endl;
            Connection->IdealSendSize = Event->IDEAL_SEND_BUFFER_SIZE.ByteCount;
        }
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
QcFileRecvStreamCallback(
    _In_ MsQuicStream* Stream,
    _In_opt_ void* Context,
    _Inout_ QUIC_STREAM_EVENT* Event
    )
{
    auto Connection = (QcConnection*)Context;
    switch (Event->Type) {
    case QUIC_STREAM_EVENT_START_COMPLETE:
        if (QUIC_FAILED(Event->START_COMPLETE.Status)) {
            cout << "Stream start result: " << hex << Event->START_COMPLETE.Status << dec << endl;
            return Event->START_COMPLETE.Status;
        }
        break;
    case QUIC_STREAM_EVENT_RECEIVE: {
        uint16_t Offset = 0;
        auto Now = steady_clock::now();
        if (!Connection->DestinationFile.is_open()) {
            uint8_t FileNameLength = Event->RECEIVE.Buffers[0].Buffer[0];

            if (FileNameLength > Event->RECEIVE.Buffers[0].Length - 1) {
                cout << "File name is not contiguous" << endl;
                Stream->Shutdown(QUIC_STATUS_INVALID_PARAMETER);
                return QUIC_STATUS_INTERNAL_ERROR;
            } else {
                Connection->FileName = string((char*)Event->RECEIVE.Buffers[0].Buffer + 1, FileNameLength);
            }

            if (Connection->FileName.find("..") != string::npos) {
                cout << "File name contains .. " << endl;
                Stream->Shutdown(QUIC_STATUS_INVALID_PARAMETER);
                return QUIC_STATUS_INTERNAL_ERROR;
            }

            if (Connection->FileName.find(Connection->DestinationPath.preferred_separator) != string::npos) {
                cout << "File name contains path separator" << endl;
                Stream->Shutdown(QUIC_STATUS_INVALID_PARAMETER);
                return QUIC_STATUS_INTERNAL_ERROR;
            }

            QUIC_VAR_INT FileLength = 0;
            Offset = 1 + FileNameLength;
            if (!QuicVarIntDecode(
                Event->RECEIVE.Buffers[0].Length,
                Event->RECEIVE.Buffers[0].Buffer,
                &Offset,
                &FileLength)) {
                cout << "Failed to decode File size!" << endl;
                return QUIC_STATUS_INTERNAL_ERROR;
            }
            Connection->FileSize = FileLength;

            cout << "Creating file: " << Connection->DestinationPath / Connection->FileName << endl;

            Connection->DestinationFile.open(
                Connection->DestinationPath / Connection->FileName,
                ios::binary | ios::out);

            if (Connection->DestinationFile.fail()) {
                cout << "Failed to open " << Connection->DestinationPath / Connection->FileName << " for writing!" << endl;
                return QUIC_STATUS_INTERNAL_ERROR;
            }

            Connection->StartTime = Now;
            Connection->LastUpdate = Now;
        }
        for (auto i = 0; i < Event->RECEIVE.BufferCount; ++i) {
            auto WriteLength = Event->RECEIVE.Buffers[i].Length - Offset;
            Connection->DestinationFile.write((char*)Event->RECEIVE.Buffers[i].Buffer + Offset, WriteLength);
            if (Connection->DestinationFile.fail()) {
                cout << "Failed to write to file!" << endl;
                return QUIC_STATUS_INTERNAL_ERROR;
            }
            Offset = 0;
        }
        Connection->BytesReceived += Event->RECEIVE.TotalBufferLength;
        if (Now - Connection->LastUpdate >= UpdateRate || Event->RECEIVE.Flags & QUIC_RECEIVE_FLAG_FIN) {
            PrintProgress(
                Connection->FileName,
                Connection->BytesReceived,
                Connection->FileSize,
                Now - Connection->StartTime,
                Connection->BytesReceived - Connection->BytesReceivedSnapshot,
                Now - Connection->LastUpdate);
            Connection->LastUpdate = Now;
            Connection->BytesReceivedSnapshot = Connection->BytesReceived;
        }
        if (Event->RECEIVE.Flags & QUIC_RECEIVE_FLAG_FIN) {
            Connection->DestinationFile.flush();
            Connection->DestinationFile.close();
            cout << endl;
            CxPlatEventSet(Connection->SendCompleteEvent);
        }
        break;
    }
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        CxPlatEventSet(Connection->SendCompleteEvent);
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
QcServerConnectionCallback(
    _In_ MsQuicConnection* Connection,
    _In_opt_ void* Context,
    _Inout_ QUIC_CONNECTION_EVENT* Event
    )
{
    auto ConnContext = (QcConnection*)Context;
    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        cout << "Connected!" << endl;
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        cout << "Shutdown complete!" << endl;
        break;
    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
        ConnContext->Stream = new(nothrow) MsQuicStream(Event->PEER_STREAM_STARTED.Stream, CleanUpAutoDelete, QcFileRecvStreamCallback, Context);
        break;
    case QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED:
        cout << "Cert received!" << endl;
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
QcClientConnectionCallback(
    _In_ MsQuicConnection* Connection,
    _In_opt_ void* Context,
    _Inout_ QUIC_CONNECTION_EVENT* Event
    )
{
    auto ConnContext = (QcConnection*)Context;
    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        cout << "Connected!" << endl;
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        CxPlatEventSet(ConnContext->ConnectionShutdownEvent);
        break;
    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
        cout << "Peer stream started!" << endl;
        break;
    case QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS:
        cout << "Needs streams!" << endl;
        break;
    case QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED:
        cout << "Cert received!" << endl;
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Function_class_(QUIC_LISTENER_CALLBACK)
QUIC_STATUS
QcListenerCallback(
    _In_ HQUIC Listener,
    _In_opt_ void* Context,
    _Inout_ QUIC_LISTENER_EVENT* Event
    )
{
    QcListener* ListenerContext = (QcListener*)Context;
    if (Event->Type == QUIC_LISTENER_EVENT_NEW_CONNECTION) {
        MsQuicConnection* Conn =
            new(nothrow) MsQuicConnection(
                Event->NEW_CONNECTION.Connection,
                CleanUpAutoDelete,
                QcServerConnectionCallback,
                &ListenerContext->ConnectionContext);
        ListenerContext->Connection = Conn;
        ListenerContext->ConnectionContext.Connection = Conn;
        QUIC_STATUS Status = Conn->SetConfiguration(*ListenerContext->Config);
        if (QUIC_FAILED(Status)) {
            cout << "Failed to set configuration on connection: " << hex << Status << endl;
            return QUIC_STATUS_CONNECTION_REFUSED;
        }
        MsQuic->ListenerStop(*ListenerContext->Listener);
        CxPlatEventSet(ListenerContext->ConnectionReceivedEvent);
        return QUIC_STATUS_SUCCESS;
    } else if (Event->Type == QUIC_LISTENER_EVENT_STOP_COMPLETE) {
        cout << "Listener stopped" << endl;
        return QUIC_STATUS_SUCCESS;
    } else {
        cout << "Unhandled Listener Event: " << hex << Event->Type << endl;
        return QUIC_STATUS_INTERNAL_ERROR;
    }
}

int main(
    _In_ int argc,
    _In_ char** argv
    )
{
    QUIC_STATUS Status;
    MsQuicApi Api;
    if (QUIC_FAILED(Status = Api.GetInitStatus())) {
        cout << "Failed to initialize MsQuic: 0x" << hex << Status << endl;
        return Status;
    }
    MsQuic = &Api;
    const char* ListenAddress;
    const char* TargetAddress;
    const char* FilePath = nullptr;
    const char* DestinationPath = nullptr;
    uint16_t Port = 0;
    MsQuicConnection* ServerConnection = nullptr;
    QUIC_ADDR LocalAddr;

    TryGetValue(argc, argv, "port", &Port);
    if (!TryGetValue(argc, argv, "listen", &ListenAddress)) {
        ListenAddress = nullptr;
    }
    if (!TryGetValue(argc, argv, "target", &TargetAddress)) {
        TargetAddress = nullptr;
    }
    TryGetValue(argc, argv, "file", &FilePath);
    TryGetValue(argc, argv, "destination", &DestinationPath);

    if (TargetAddress && ListenAddress) {
        cout << "Can't set both listen and target addresses!" << endl;
        return QUIC_STATUS_INVALID_PARAMETER;
    } else if (TargetAddress == nullptr && ListenAddress == nullptr) {
        cout << "Must set either listen or target address!" << endl;
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    if (TargetAddress && DestinationPath) {
        cout << "Cannot use -destination with -target; Did you mean -file?" << endl;
        return QUIC_STATUS_INVALID_PARAMETER;
    }
    if (ListenAddress && FilePath) {
        cout << "Cannot use -file with -listen; Did you mean -destination?" << endl;
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    MsQuicRegistration Registration;
    if (!Registration.IsValid()) {
        cout << "Registration failed to open with " << hex << Registration.GetInitStatus() << endl;
        return QUIC_STATUS_INTERNAL_ERROR;
    }

    MsQuicSettings Settings;
    Settings.SetPeerUnidiStreamCount(1);
    Settings.SetKeepAlive(20000);

    if (ListenAddress != nullptr) {
        // server
        QcListener ListenerContext{};
        uint32_t Pkcs12Length = 0;
        unique_ptr<uint8_t[]> Pkcs12;
        MsQuicCredentialConfig Creds;
        QUIC_CERTIFICATE_PKCS12 Pkcs12Info{};
        char Password[64];
        CxPlatRandom(sizeof Password, Password);
        if (!QcGenerateAuthCertificate(Password, Pkcs12, Pkcs12Length)) {
            cout << "Failed to generate auth certificate" << endl;
            return QUIC_STATUS_INTERNAL_ERROR;
        }
        Creds.CertificatePkcs12 = &Pkcs12Info;
        Creds.CertificatePkcs12->Asn1Blob = Pkcs12.get();
        Creds.CertificatePkcs12->Asn1BlobLength = (uint32_t)Pkcs12Length;
        Creds.CertificatePkcs12->PrivateKeyPassword = nullptr;
        Creds.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_PKCS12;
        Creds.Flags = QUIC_CREDENTIAL_FLAG_NONE;
        MsQuicConfiguration Config(Registration, Alpn, Settings, Creds);
        if (!Config.IsValid()) {
            cout << "Configuration failed to init with: " << hex << Config.GetInitStatus() << endl;
            return Config.GetInitStatus();
        }
        ListenerContext.Config = &Config;
        ListenerContext.ConnectionContext.DestinationPath = DestinationPath;
        CxPlatEventInitialize(&(ListenerContext.ConnectionReceivedEvent), false, false);
        CxPlatEventInitialize(&(ListenerContext.ConnectionContext.SendCompleteEvent), false, false);
        MsQuicListener Listener(Registration, QcListenerCallback, &ListenerContext);
        ListenerContext.Listener = &Listener;
        if (!ConvertArgToAddress(ListenAddress, Port, &LocalAddr)) {
            cout << "Failed to convert address: " << ListenAddress << endl;
            return QUIC_STATUS_INVALID_PARAMETER;
        }
        if (QUIC_FAILED(Status = Listener.Start(Alpn, &LocalAddr))) {
            cout << "Failed to start listener: " << hex << Status << endl;
            return Status;
        }
        CxPlatEventWaitForever(ListenerContext.ConnectionReceivedEvent);
        CxPlatEventWaitForever(ListenerContext.ConnectionContext.SendCompleteEvent);

    } else if (TargetAddress != nullptr) {
        // client
        MsQuicCredentialConfig Creds;
        Creds.Type = QUIC_CREDENTIAL_TYPE_NONE;
        Creds.Flags = QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION | QUIC_CREDENTIAL_FLAG_CLIENT;
        MsQuicConfiguration Config(Registration, Alpn, Settings, Creds);
        QcConnection ConnectionContext{};
        CxPlatEventInitialize(&ConnectionContext.SendCompleteEvent, false, false);
        CxPlatEventInitialize(&ConnectionContext.ConnectionShutdownEvent, false, false);
        MsQuicConnection Client(Registration, CleanUpManual, QcClientConnectionCallback, &ConnectionContext);
        MsQuicStream ClientStream(Client, QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL, CleanUpManual, QcFileSendStreamCallback, &ConnectionContext);
        if (QUIC_FAILED(ClientStream.Start(QUIC_STREAM_START_FLAG_SHUTDOWN_ON_FAIL))) {
            cout << "Failed to start stream!" << endl;
            return QUIC_STATUS_INTERNAL_ERROR;
        }
        if (QUIC_FAILED(Client.Start(Config, TargetAddress, Port))) {
            cout << "Failed to start client connection!" << endl;
            return QUIC_STATUS_INTERNAL_ERROR;
        }

        ConnectionContext.CurrentSendSize = ConnectionContext.IdealSendSize;
        ConnectionContext.SendBuffer = make_unique<uint8_t[]>(ConnectionContext.CurrentSendSize);
        ConnectionContext.SendQuicBuffer.Buffer = ConnectionContext.SendBuffer.get();
        uint8_t* BufferCursor = ConnectionContext.SendQuicBuffer.Buffer;

        filesystem::path Path{FilePath};
        if (!filesystem::exists(Path)) {
            cout << Path << " doesn't exist!" << endl;
            return QUIC_STATUS_INVALID_PARAMETER;
        }
        ConnectionContext.FileSize = filesystem::file_size(Path);

        auto FileName = Path.filename().generic_string();

        if (FileName.size() > MaxFileNameLength) {
            cout << "File name is too long! Actual: " << FileName.size() << " Maximum: " << MaxFileNameLength << endl;
            return QUIC_STATUS_INVALID_PARAMETER;
        }
        *BufferCursor = (uint8_t)FileName.size();
        BufferCursor++;

        strncpy((char*)BufferCursor, FileName.c_str(), MaxFileNameLength);
        BufferCursor += FileName.size();

        BufferCursor = QuicVarIntEncode(ConnectionContext.FileSize, BufferCursor);
        ConnectionContext.SendQuicBuffer.Length = 1 + FileName.size() + QuicVarIntSize(ConnectionContext.FileSize);
        uint32_t BufferRemaining = ConnectionContext.CurrentSendSize - ConnectionContext.SendQuicBuffer.Length;

        fstream File(Path, ios::binary | ios::in);
        if (File.fail()) {
            cout << "Failed to open file '" << FilePath << "' for read" << endl;
            return QUIC_STATUS_INVALID_PARAMETER;
        }
        bool EndOfFile = false;
        uint64_t TotalBytesSent = 0;
        uint64_t BytesSentSnapshot = 0;
        auto StartTime = steady_clock::now();
        auto LastUpdate = StartTime;
        do {
            File.read((char*)BufferCursor, BufferRemaining);
            auto BytesRead = File.gcount();
            if (BytesRead < BufferRemaining || File.eof()) {
                EndOfFile = true;
            }
            ConnectionContext.SendQuicBuffer.Length += BytesRead;
            QUIC_SEND_FLAGS Flags = EndOfFile ? QUIC_SEND_FLAG_FIN : QUIC_SEND_FLAG_NONE;
            if (QUIC_FAILED(Status = ClientStream.Send(&ConnectionContext.SendQuicBuffer, 1, Flags))) {
                cout << "StreamSend failed with 0x" << hex << Status << endl;
                return Status;
            }
            CxPlatEventWaitForever(ConnectionContext.SendCompleteEvent);
            TotalBytesSent += ConnectionContext.SendQuicBuffer.Length;
            auto Now = steady_clock::now();
            if (EndOfFile || Now - LastUpdate >= UpdateRate) {
                PrintProgress(
                    FileName,
                    TotalBytesSent,
                    ConnectionContext.FileSize,
                    Now - StartTime,
                    TotalBytesSent - BytesSentSnapshot,
                    Now - LastUpdate);
                LastUpdate = Now;
                BytesSentSnapshot = TotalBytesSent;
                if (EndOfFile) {
                    cout << endl;
                }
            }
            if (ConnectionContext.IdealSendSize != ConnectionContext.CurrentSendSize) {
                ConnectionContext.CurrentSendSize = ConnectionContext.IdealSendSize;
                ConnectionContext.SendBuffer = make_unique<uint8_t[]>(ConnectionContext.CurrentSendSize);
                ConnectionContext.SendQuicBuffer.Buffer = ConnectionContext.SendBuffer.get();
            }
            BufferCursor = ConnectionContext.SendBuffer.get();
            ConnectionContext.SendQuicBuffer.Length = 0;
            BufferRemaining = ConnectionContext.CurrentSendSize;
        } while (!ConnectionContext.SendCanceled && !EndOfFile);
        auto StopTime = steady_clock::now();
        auto ElapsedTime = StopTime - StartTime;
        auto SendRateBps =
            (TotalBytesSent * 8.0 * steady_clock::duration::period::den) /
            (ElapsedTime.count() * steady_clock::duration::period::num);
            // ((TotalBytesSent * 8.0) /
            // (ElapsedTime.count() * steady_clock::duration::period::num)) * steady_clock::duration::period::den;
        cout << dec << TotalBytesSent << " bytes sent in "
            << duration_cast<seconds>(ElapsedTime) << " "
            << duration_cast<milliseconds>(ElapsedTime) - duration_cast<seconds>(ElapsedTime);
        if (SendRateBps >= 1000000000) {
            cout << " (" << setprecision(4) << SendRateBps / 1000000000.0 << "Gbps)" << endl;
        } else if (SendRateBps >= 1000000) {
            cout << " (" << setprecision(4) << SendRateBps / 1000000.0 << "Mbps)" << endl;
        } else if (SendRateBps >= 1000) {
            cout << " (" << setprecision(4) << SendRateBps / 1000.0 << "Kbps)" << endl;
        } else {
            cout << " (" << SendRateBps << "bps)" << endl;
        }

        Client.Shutdown(QUIC_STATUS_SUCCESS);
        cout << "Press any key to exit..." << endl;
        getchar();
    } else {
        cout << "Error! You didn't specify listen or target!" << endl;
        return QUIC_STATUS_INVALID_STATE;
    }

    return 0;
}
