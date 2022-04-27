#include "quiccat.h"

using namespace std;
using namespace std::chrono;

const uint32_t DefaultSendBufferSize = 128 * 1024;
const uint32_t MaxFileNameLength = 255;
const uint32_t RandomPasswordLength = 64;
const auto UpdateRate = milliseconds(500);

const MsQuicApi* MsQuic;

const MsQuicAlpn Alpn("quiccat");

typedef struct QcListener QcListener;

struct QcConnection {
    MsQuicConnection* Connection;
    MsQuicStream* Stream;
    QcListener* Listener;
    CXPLAT_EVENT ConnectionShutdownEvent;
    CXPLAT_EVENT StreamsReadyEvent;
    string Password;
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
    uint64_t FileSize{0};
    uint32_t CurrentSendSize = DefaultSendBufferSize;
    bool SendCanceled = false;
    // stdin/stdout variables
    vector<QUIC_BUFFER> RecvData;
    condition_variable RecvDataCV;
    mutex RecvDataMutex;
};

struct QcListener {
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
    static const int ProgressBarWidth = 40;
    const float ProgressFraction = (float)BytesComplete / BytesTotal;
    const auto BytesRemaining = BytesComplete < BytesTotal ? BytesTotal - BytesComplete : 0;
    const auto EstimatedRemaining = (ElapsedTime / BytesComplete) * BytesRemaining;

    Log() << "\r";
    if (FileName.length() < 29) {
        Log() << FileName;
    } else {
        Log() << FileName.substr(0,26) << "...";
    }
    Log() << " [";
    int pos = (int)(ProgressBarWidth * ProgressFraction);
    for (int i = 0; i < ProgressBarWidth; ++i) {
        if (i <= pos) {
            Log() << "|";
        } else {
            Log() << " ";
        }
    }
    Log() << "] " << setw(3) << (int)(ProgressFraction * 100.0) << "%";
    Log() << " " << setw(3) << duration_cast<minutes>(EstimatedRemaining).count() << "min "
        << setw(2) << (duration_cast<seconds>(EstimatedRemaining) - duration_cast<minutes>(EstimatedRemaining)).count() << "s";
    if (RateTime > steady_clock::duration(0)) {
        const auto BitsPerSecond =
            (RateBytes * 8 * steady_clock::duration::period::den) /
            (RateTime.count() * steady_clock::duration::period::num);
        if (BitsPerSecond >= 1000000000) {
            Log() << " " << setw(5) << setprecision(4) << BitsPerSecond / 1000000000.0 << "Gbps";
        } else if (BitsPerSecond >= 1000000) {
            Log() << " " << setw(5) << setprecision(4) << BitsPerSecond / 1000000.0 << "Mbps";
        } else if (BitsPerSecond >= 1000) {
            Log() << " " << setw(5) << setprecision(4) << BitsPerSecond / 1000.0 << "Kbps";
        } else {
            Log() << " " << setw(5) << BitsPerSecond << "bps";
        }
    }
    Log() << flush;
}

void
PrintTransferSummary(
    _In_ const steady_clock::time_point StartTime,
    _In_ const steady_clock::time_point StopTime,
    _In_ const uint64_t BytesTransferred,
    _In_ const char* DirectionStr
    )
{
    auto ElapsedTime = StopTime - StartTime;
    auto RateBps =
        (BytesTransferred * 8.0 * steady_clock::duration::period::den) /
        (ElapsedTime.count() * steady_clock::duration::period::num);
        // ((BytesTransferred * 8.0) /
        // (ElapsedTime.count() * steady_clock::duration::period::num)) * steady_clock::duration::period::den;
    Log() << dec << BytesTransferred << " bytes " << DirectionStr << " in ";
    if (ElapsedTime >= minutes(1)) {
        Log() << duration_cast<minutes>(ElapsedTime).count() << "min ";
        ElapsedTime -= duration_cast<minutes>(ElapsedTime);
    }
    if (ElapsedTime >= seconds(1)) {
        Log() << duration_cast<seconds>(ElapsedTime).count() << "s ";
        ElapsedTime -= duration_cast<seconds>(ElapsedTime);
    }
    if (ElapsedTime >= milliseconds(1)) {
        Log() << duration_cast<milliseconds>(ElapsedTime).count() << "ms";
    }
    if (RateBps >= 1000000000) {
        Log() << " (" << setprecision(4) << RateBps / 1000000000.0 << "Gbps)" << endl;
    } else if (RateBps >= 1000000) {
        Log() << " (" << setprecision(4) << RateBps / 1000000.0 << "Mbps)" << endl;
    } else if (RateBps >= 1000) {
        Log() << " (" << setprecision(4) << RateBps / 1000.0 << "Kbps)" << endl;
    } else {
        Log() << " (" << RateBps << "bps)" << endl;
    }
}

void
QcReadStdInThread(
    _In_ QcConnection& ConnectionContext)
{
    bool EndOfFile = false;
    QUIC_STATUS Status;
    do {
        size_t ReadBytes = 0;
        if (isatty(fileno(stdin))) {
            if (fgets((char*)ConnectionContext.SendBuffer.get(), DefaultSendBufferSize, stdin) != nullptr) {
                ReadBytes = strlen((char*)ConnectionContext.SendBuffer.get());
            }
        } else {
            ReadBytes = fread(ConnectionContext.SendBuffer.get(), 1, DefaultSendBufferSize, stdin);
        }
        EndOfFile = ReadBytes == 0 || feof(stdin) || ferror(stdin);
        if (ReadBytes > 0) {
            ConnectionContext.SendQuicBuffer.Length = (uint32_t)ReadBytes;
            QUIC_SEND_FLAGS SendFlags = EndOfFile ? QUIC_SEND_FLAG_FIN : QUIC_SEND_FLAG_NONE;
            if (QUIC_FAILED(Status = ConnectionContext.Stream->Send(&ConnectionContext.SendQuicBuffer, 1, SendFlags))) {
                Log() << "StreamSend failed with 0x" << hex << Status << endl;
                ConnectionContext.Stream->Shutdown((QUIC_UINT62)QUIC_STATUS_INTERNAL_ERROR);
                return;
            }
            CxPlatEventWaitForever(ConnectionContext.SendCompleteEvent);
        }
    } while (!EndOfFile);
    if (EndOfFile) {
        ConnectionContext.Stream->Shutdown(QUIC_STATUS_SUCCESS, QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL);
    }
}

QUIC_STATUS
QcStdInStdOutStreamCallback(
    _In_ MsQuicStream* Stream,
    _In_opt_ void* Context,
    _Inout_ QUIC_STREAM_EVENT* Event
    )
{
    auto Connection = (QcConnection*)Context;
    switch (Event->Type) {
    case QUIC_STREAM_EVENT_START_COMPLETE:
        if (QUIC_FAILED(Event->START_COMPLETE.Status)) {
            Log() << "Stream start result: " << hex << Event->START_COMPLETE.Status << dec << endl;
            return Event->START_COMPLETE.Status;
        }
        Connection->StartTime = steady_clock::now();
        break;
    case QUIC_STREAM_EVENT_RECEIVE: {
        QUIC_STATUS Status = QUIC_STATUS_PENDING;
        unique_lock<mutex> Lock(Connection->RecvDataMutex);
        for (unsigned i = 0; i < Event->RECEIVE.BufferCount; ++i) {
            Connection->RecvData.push_back(Event->RECEIVE.Buffers[i]);
        }
        Connection->BytesReceived += Event->RECEIVE.TotalBufferLength;
        if (Event->RECEIVE.Flags & QUIC_RECEIVE_FLAG_FIN) {
            Stream->Shutdown(QUIC_STATUS_SUCCESS | QUIC_STREAM_SHUTDOWN_FLAG_INLINE);
            Status = QUIC_STATUS_SUCCESS;
        } else {
            Lock.unlock();
            Connection->RecvDataCV.notify_one();
        }
        return Status;
    }
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        if (Event->SEND_COMPLETE.Canceled) {
            Connection->SendCanceled = true;
        }
        CxPlatEventSet(Connection->SendCompleteEvent);
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE: {
        Connection->EndTime = steady_clock::now();
        unique_lock<mutex> Lock(Connection->RecvDataMutex);
        Connection->RecvData.push_back({0, nullptr});
        Connection->RecvDataCV.notify_one();
        if (!Event->SHUTDOWN_COMPLETE.ConnectionShutdown) {
            Connection->Connection->Shutdown(QUIC_STATUS_SUCCESS);
        }
        break;
    }
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
QcFileSendStreamCallback(
    _In_ MsQuicStream* /*Stream*/,
    _In_opt_ void* Context,
    _Inout_ QUIC_STREAM_EVENT* Event
    )
{
    auto Connection = (QcConnection*)Context;
    switch (Event->Type) {
    case QUIC_STREAM_EVENT_START_COMPLETE:
        if (QUIC_FAILED(Event->START_COMPLETE.Status)) {
            Log() << "Stream start result: " << hex << Event->START_COMPLETE.Status << dec << endl;
            return Event->START_COMPLETE.Status;
        }
        break;
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        if (Event->SEND_COMPLETE.Canceled) {
            Connection->SendCanceled = true;
        }
        CxPlatEventSet(Connection->SendCompleteEvent);
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        Connection->Connection->Shutdown(QUIC_STATUS_SUCCESS);
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
            Log() << "Stream start result: " << hex << Event->START_COMPLETE.Status << dec << endl;
            return Event->START_COMPLETE.Status;
        }
        break;
    case QUIC_STREAM_EVENT_RECEIVE: {
        uint16_t Offset = 0;
        auto Now = steady_clock::now();
        if (!Connection->DestinationFile.is_open()) {
            uint8_t FileNameLength = Event->RECEIVE.Buffers[0].Buffer[0];

            if (FileNameLength > Event->RECEIVE.Buffers[0].Length - 1) {
                Log() << "File name is not contiguous" << endl;
                Stream->Shutdown((QUIC_UINT62)QUIC_STATUS_INVALID_PARAMETER);
                return QUIC_STATUS_INTERNAL_ERROR;
            } else {
                Connection->FileName = string((char*)Event->RECEIVE.Buffers[0].Buffer + 1, FileNameLength);
            }

            if (Connection->FileName.find("..") != string::npos) {
                Log() << "File name contains .. " << endl;
                Stream->Shutdown((QUIC_UINT62)QUIC_STATUS_INVALID_PARAMETER);
                return QUIC_STATUS_INTERNAL_ERROR;
            }

            if (Connection->FileName.find(Connection->DestinationPath.preferred_separator) != string::npos) {
                Log() << "File name contains path separator" << endl;
                Stream->Shutdown((QUIC_UINT62)QUIC_STATUS_INVALID_PARAMETER);
                return QUIC_STATUS_INTERNAL_ERROR;
            }

            QUIC_VAR_INT FileLength = 0;
            Offset = 1 + FileNameLength;
            if (!QuicVarIntDecode(
                (uint16_t)Event->RECEIVE.Buffers[0].Length,
                Event->RECEIVE.Buffers[0].Buffer,
                &Offset,
                &FileLength)) {
                Log() << "Failed to decode File size!" << endl;
                Stream->Shutdown((QUIC_UINT62)QUIC_STATUS_INTERNAL_ERROR);
                return QUIC_STATUS_INTERNAL_ERROR;
            }
            Connection->FileSize = FileLength;

            Log() << "Creating file: " << Connection->DestinationPath / Connection->FileName << endl;

            Connection->DestinationFile.open(
                Connection->DestinationPath / Connection->FileName,
                ios::binary | ios::out);

            if (Connection->DestinationFile.fail()) {
                Log() << "Failed to open " << Connection->DestinationPath / Connection->FileName << " for writing!" << endl;
                Stream->Shutdown((QUIC_UINT62)QUIC_STATUS_INTERNAL_ERROR);
                return QUIC_STATUS_INTERNAL_ERROR;
            }

            Connection->StartTime = Now;
            Connection->LastUpdate = Now;
        }
        for (unsigned i = 0; i < Event->RECEIVE.BufferCount; ++i) {
            auto WriteLength = Event->RECEIVE.Buffers[i].Length - Offset;
            Connection->DestinationFile.write((char*)Event->RECEIVE.Buffers[i].Buffer + Offset, WriteLength);
            if (Connection->DestinationFile.fail()) {
                Log() << "Failed to write to file!" << endl;
                Stream->Shutdown((QUIC_UINT62)QUIC_STATUS_INTERNAL_ERROR);
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
            if (Event->RECEIVE.Flags & QUIC_RECEIVE_FLAG_FIN) {
                Log() << endl;
            }
        }
        if (Event->RECEIVE.Flags & QUIC_RECEIVE_FLAG_FIN) {
            Connection->EndTime = Now;
            Connection->DestinationFile.flush();
            Connection->DestinationFile.close();
            CxPlatEventSet(Connection->SendCompleteEvent);
        }
        break;
    }
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        CxPlatEventSet(Connection->SendCompleteEvent);
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
QcServerConnectionCallback(
    _In_ MsQuicConnection* /*Connection*/,
    _In_opt_ void* Context,
    _Inout_ QUIC_CONNECTION_EVENT* Event
    )
{
    auto ConnContext = (QcConnection*)Context;
    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        Log() << "Connected!" << endl;
        MsQuic->ListenerStop(*ConnContext->Listener->Listener);
        CxPlatEventSet(ConnContext->Listener->ConnectionReceivedEvent);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        CxPlatEventSet(ConnContext->ConnectionShutdownEvent);
        break;
    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
        ConnContext->Stream =
            new(nothrow) MsQuicStream(
                Event->PEER_STREAM_STARTED.Stream,
                CleanUpAutoDelete,
                ConnContext->DestinationPath.empty() ? QcStdInStdOutStreamCallback : QcFileRecvStreamCallback,
                Context);
        ConnContext->StartTime = steady_clock::now();
        break;
    case QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED:
        if (!QcVerifyCertificate(
            ConnContext->Password,
            Event->PEER_CERTIFICATE_RECEIVED.Certificate)) {
            Log() << "Peer password doesn't match!" << endl;
            return QUIC_STATUS_CONNECTION_REFUSED;
        }
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
QcClientConnectionCallback(
    _In_ MsQuicConnection* /*Connection*/,
    _In_opt_ void* Context,
    _Inout_ QUIC_CONNECTION_EVENT* Event
    )
{
    auto ConnContext = (QcConnection*)Context;
    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        Log() << "Connected!" << endl;
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        CxPlatEventSet(ConnContext->ConnectionShutdownEvent);
        break;
    case QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE:
        CxPlatEventSet(ConnContext->StreamsReadyEvent);
        break;
    case QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED:
        if (!QcVerifyCertificate(
            ConnContext->Password,
            Event->PEER_CERTIFICATE_RECEIVED.Certificate)) {
            Log() << "Peer password doesn't match!" << endl;
            return QUIC_STATUS_CONNECTION_REFUSED;
        }
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
    _In_ HQUIC /*Listener*/,
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
        if (Conn == nullptr) {
            Log() << "Failed to allocate connection tracking structure!" << endl;
            return QUIC_STATUS_CONNECTION_REFUSED;
        }
        ListenerContext->ConnectionContext.Listener = ListenerContext;
        ListenerContext->ConnectionContext.Connection = Conn;
        QUIC_STATUS Status = Conn->SetConfiguration(*ListenerContext->Config);
        if (QUIC_FAILED(Status)) {
            Log() << "Failed to set configuration on connection: " << hex << Status << endl;
            return QUIC_STATUS_CONNECTION_REFUSED;
        }
        return QUIC_STATUS_SUCCESS;
    } else if (Event->Type == QUIC_LISTENER_EVENT_STOP_COMPLETE) {
        return QUIC_STATUS_SUCCESS;
    } else {
        Log() << "Unhandled Listener Event: " << hex << Event->Type << endl;
        return QUIC_STATUS_SUCCESS;
    }
}

int main(
    _In_ int argc,
    _In_ char** argv
    )
{
    QUIC_STATUS Status;
    MsQuicApi Api;
    const char* ListenAddress;
    const char* TargetAddress;
    const char* FilePath = nullptr;
    const char* DestinationPath = nullptr;
    const char* Password = nullptr;
    uint16_t Port = 0;
    QUIC_ADDR LocalAddr;
    uint8_t Wait = false;

    TryGetValue(argc, argv, "port", &Port);
    if (!TryGetValue(argc, argv, "listen", &ListenAddress)) {
        ListenAddress = nullptr;
    }
    if (!TryGetValue(argc, argv, "target", &TargetAddress)) {
        TargetAddress = nullptr;
    }
    TryGetValue(argc, argv, "file", &FilePath);
    TryGetValue(argc, argv, "destination", &DestinationPath);
    TryGetValue(argc, argv, "password", &Password);
    TryGetValue(argc, argv, "wait", &Wait);

    if (TargetAddress && ListenAddress) {
        Log() << "Can't set both listen and target addresses!" << endl;
        return QUIC_STATUS_INVALID_PARAMETER;
    } else if (TargetAddress == nullptr && ListenAddress == nullptr) {
        Log() << "Must set either listen or target address!" << endl;
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    if (TargetAddress && DestinationPath) {
        Log() << "Cannot use -destination with -target; Did you mean -file?" << endl;
        return QUIC_STATUS_INVALID_PARAMETER;
    }
    if (ListenAddress && FilePath) {
        Log() << "Cannot use -file with -listen; Did you mean -destination?" << endl;
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    if (FilePath) {
        auto FileStatus = filesystem::status(FilePath);
        if (FileStatus.type() == filesystem::file_type::not_found) {
            Log() << FilePath << " doesn't exist!" << endl;
            return QUIC_STATUS_INVALID_PARAMETER;
        }
        if (FileStatus.type() == filesystem::file_type::directory ||
            FileStatus.type() == filesystem::file_type::none ||
            FileStatus.type() == filesystem::file_type::unknown) {
            Log() << FilePath << " must be a file, or file-like!" << endl;
            return QUIC_STATUS_INVALID_PARAMETER;
        }
    }

    if (DestinationPath) {
        auto DestinationStatus = filesystem::status(DestinationPath);
        if (DestinationStatus.type() == filesystem::file_type::not_found) {
            Log() << DestinationPath << " doesn't exist!" << endl;
            return QUIC_STATUS_INVALID_PARAMETER;
        }
        if (DestinationStatus.type() != filesystem::file_type::directory) {
            Log() << DestinationPath << " must be a directory!" << endl;
            return QUIC_STATUS_INVALID_PARAMETER;
        }
    }

    if (QUIC_FAILED(Status = Api.GetInitStatus())) {
        Log() << "Failed to initialize MsQuic: 0x" << hex << Status << endl;
        return Status;
    }
    MsQuic = &Api;

    MsQuicRegistration Registration("quiccat", QUIC_EXECUTION_PROFILE_TYPE_MAX_THROUGHPUT);
    if (!Registration.IsValid()) {
        Log() << "Registration failed to open with " << hex << Registration.GetInitStatus() << endl;
        return QUIC_STATUS_INTERNAL_ERROR;
    }

    MsQuicSettings Settings;

    if (ListenAddress != nullptr) {
        // server
        QcListener ListenerContext{};
        uint32_t Pkcs12Length = 0;
        unique_ptr<uint8_t[]> Pkcs12;
        MsQuicCredentialConfig Creds;
        QUIC_CERTIFICATE_PKCS12 Pkcs12Info{};
        string TempPassword;
        Creds.Flags = QUIC_CREDENTIAL_FLAG_NONE;
        if (Password != nullptr) {
            ListenerContext.ConnectionContext.Password = string(Password);
            TempPassword = string(Password);
            Creds.Flags |=
                QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED
                | QUIC_CREDENTIAL_FLAG_REQUIRE_CLIENT_AUTHENTICATION
                | QUIC_CREDENTIAL_FLAG_DEFER_CERTIFICATE_VALIDATION;
        } else {
            char RandomPassword[RandomPasswordLength];
            CxPlatRandom(sizeof RandomPassword, RandomPassword);
            TempPassword = string(RandomPassword, sizeof RandomPassword);
        }
        if (!QcGenerateAuthCertificate(TempPassword, Pkcs12, Pkcs12Length)) {
            Log() << "Failed to generate auth certificate" << endl;
            return QUIC_STATUS_INTERNAL_ERROR;
        }
        Creds.CertificatePkcs12 = &Pkcs12Info;
        Creds.CertificatePkcs12->Asn1Blob = Pkcs12.get();
        Creds.CertificatePkcs12->Asn1BlobLength = (uint32_t)Pkcs12Length;
        Creds.CertificatePkcs12->PrivateKeyPassword = nullptr;
        Creds.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_PKCS12;
        if (DestinationPath != nullptr) {
            // File mode active, allow 1 unidi stream for sending a file.
            Settings.SetPeerUnidiStreamCount(1);
            ListenerContext.ConnectionContext.DestinationPath = DestinationPath;
        } else {
            // stdin/stdout mode active, allow 1 bidi stream.
            Settings.SetPeerBidiStreamCount(1);
            // For stdin/stdout, set a keepalive.
            Settings.SetKeepAlive(20000);
        }
        MsQuicConfiguration Config(Registration, Alpn, Settings, Creds);
        if (!Config.IsValid()) {
            Log() << "Configuration failed to init with: " << hex << Config.GetInitStatus() << endl;
            return Config.GetInitStatus();
        }
        ListenerContext.Config = &Config;
        CxPlatEventInitialize(&(ListenerContext.ConnectionReceivedEvent), false, false);
        CxPlatEventInitialize(&ListenerContext.ConnectionContext.ConnectionShutdownEvent, false, false);
        CxPlatEventInitialize(&(ListenerContext.ConnectionContext.SendCompleteEvent), false, false);
        MsQuicListener Listener(Registration, QcListenerCallback, &ListenerContext);
        ListenerContext.Listener = &Listener;
        if (!ConvertArgToAddress(ListenAddress, Port, &LocalAddr)) {
            Log() << "Failed to convert address: " << ListenAddress << endl;
            return QUIC_STATUS_INVALID_PARAMETER;
        }
        if (QUIC_FAILED(Status = Listener.Start(Alpn, &LocalAddr))) {
            Log() << "Failed to start listener: " << hex << Status << endl;
            return Status;
        }
        CxPlatEventWaitForever(ListenerContext.ConnectionReceivedEvent);
        if (DestinationPath == nullptr) {
            // Start reading from stdin until EOF is read.
            ListenerContext.ConnectionContext.SendBuffer = make_unique<uint8_t[]>(DefaultSendBufferSize);
            ListenerContext.ConnectionContext.SendQuicBuffer.Buffer = ListenerContext.ConnectionContext.SendBuffer.get();
            thread ReadStdIn(QcReadStdInThread, std::ref(ListenerContext.ConnectionContext));
            ReadStdIn.detach();
            bool ConnectionClosed = false;
            do {
                unique_lock<mutex> Lock(ListenerContext.ConnectionContext.RecvDataMutex);
                ListenerContext.ConnectionContext.RecvDataCV.wait(
                    Lock,
                    [&ListenerContext]{return ListenerContext.ConnectionContext.RecvData.size() > 0;});
                uint64_t ConsumedLength = 0;
                for(auto& Data : ListenerContext.ConnectionContext.RecvData) {
                    if (Data.Buffer == nullptr && Data.Length == 0) {
                        // Connection closed
                        ConnectionClosed = true;
                        break;
                    } else {
                        fwrite((char*)Data.Buffer, 1, Data.Length, stdout);
                        ConsumedLength += Data.Length;
                    }
                }
                fflush(stdout);
                ListenerContext.ConnectionContext.RecvData.clear();
                if (!ConnectionClosed) {
                    ListenerContext.ConnectionContext.Stream->ReceiveComplete(ConsumedLength);
                }
            } while (!ConnectionClosed);
        }
        CxPlatEventWaitForever(ListenerContext.ConnectionContext.ConnectionShutdownEvent);
        PrintTransferSummary(
            ListenerContext.ConnectionContext.StartTime,
            ListenerContext.ConnectionContext.EndTime,
            ListenerContext.ConnectionContext.BytesReceived,
            "received");

    } else if (TargetAddress != nullptr) {
        // client
        QcConnection ConnectionContext{};
        CxPlatEventInitialize(&ConnectionContext.SendCompleteEvent, false, false);
        CxPlatEventInitialize(&ConnectionContext.ConnectionShutdownEvent, false, false);
        CxPlatEventInitialize(&ConnectionContext.StreamsReadyEvent, false, false);
        uint32_t Pkcs12Length = 0;
        unique_ptr<uint8_t[]> Pkcs12;
        MsQuicCredentialConfig Creds;
        QUIC_CERTIFICATE_PKCS12 Pkcs12Info{};
        Creds.Flags = QUIC_CREDENTIAL_FLAG_CLIENT;
        if (Password != nullptr) {
            Creds.Flags |=
                QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED
                | QUIC_CREDENTIAL_FLAG_DEFER_CERTIFICATE_VALIDATION;
            ConnectionContext.Password = string(Password);
            if (!QcGenerateAuthCertificate(ConnectionContext.Password, Pkcs12, Pkcs12Length)) {
                Log() << "Failed to generate auth certificate" << endl;
                return QUIC_STATUS_INTERNAL_ERROR;
            }
            Pkcs12Info.Asn1Blob = Pkcs12.get();
            Pkcs12Info.Asn1BlobLength = Pkcs12Length;
            Creds.CertificatePkcs12 = &Pkcs12Info;
            Creds.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_PKCS12;
        } else {
            Creds.Type = QUIC_CREDENTIAL_TYPE_NONE;
            Creds.Flags |= QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
        }
        if (FilePath == nullptr) {
            // For stdin/stdout, set a keepalive.
            Settings.SetKeepAlive(20000);
        }
        MsQuicConfiguration Config(Registration, Alpn, Settings, Creds);
        MsQuicConnection Client(Registration, CleanUpManual, QcClientConnectionCallback, &ConnectionContext);
        ConnectionContext.Connection = &Client;
        MsQuicStream ClientStream(
            Client,
            FilePath != nullptr ? QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL : QUIC_STREAM_OPEN_FLAG_NONE,
            CleanUpManual,
            FilePath != nullptr ? QcFileSendStreamCallback : QcStdInStdOutStreamCallback,
            &ConnectionContext);
        if (QUIC_FAILED(ClientStream.Start(QUIC_STREAM_START_FLAG_SHUTDOWN_ON_FAIL | QUIC_STREAM_START_FLAG_IMMEDIATE))) {
            Log() << "Failed to start stream!" << endl;
            return QUIC_STATUS_INTERNAL_ERROR;
        }
        if (QUIC_FAILED(Client.Start(Config, TargetAddress, Port))) {
            Log() << "Failed to start client connection!" << endl;
            return QUIC_STATUS_INTERNAL_ERROR;
        }

        CxPlatEventWaitForever(ConnectionContext.StreamsReadyEvent);

        ConnectionContext.CurrentSendSize = DefaultSendBufferSize;
        ConnectionContext.SendBuffer = make_unique<uint8_t[]>(ConnectionContext.CurrentSendSize);
        ConnectionContext.SendQuicBuffer.Buffer = ConnectionContext.SendBuffer.get();
        uint8_t* BufferCursor = ConnectionContext.SendQuicBuffer.Buffer;

        if (FilePath != nullptr) {
            filesystem::path Path{FilePath};
            ConnectionContext.FileSize = filesystem::file_size(Path);

            auto FileName = Path.filename().generic_string();

            if (FileName.size() > MaxFileNameLength) {
                Log() << "File name is too long! Actual: " << FileName.size() << " Maximum: " << MaxFileNameLength << endl;
                return QUIC_STATUS_INVALID_PARAMETER;
            }
            *BufferCursor = (uint8_t)FileName.size();
            BufferCursor++;

            strncpy((char*)BufferCursor, FileName.c_str(), MaxFileNameLength);
            BufferCursor += FileName.size();

            BufferCursor = QuicVarIntEncode(ConnectionContext.FileSize, BufferCursor);
            ConnectionContext.SendQuicBuffer.Length = (uint32_t)(1 + FileName.size() + QuicVarIntSize(ConnectionContext.FileSize));
            uint32_t BufferRemaining = ConnectionContext.CurrentSendSize - ConnectionContext.SendQuicBuffer.Length;

            fstream File(Path, ios::binary | ios::in);
            if (File.fail()) {
                Log() << "Failed to open file '" << FilePath << "' for read" << endl;
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
                ConnectionContext.SendQuicBuffer.Length += (uint32_t)BytesRead;
                QUIC_SEND_FLAGS Flags = EndOfFile ? QUIC_SEND_FLAG_FIN : QUIC_SEND_FLAG_NONE;
                if (QUIC_FAILED(Status = ClientStream.Send(&ConnectionContext.SendQuicBuffer, 1, Flags))) {
                    Log() << "StreamSend failed with 0x" << hex << Status << endl;
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
                        Log() << endl;
                    }
                }
                BufferCursor = ConnectionContext.SendBuffer.get();
                ConnectionContext.SendQuicBuffer.Length = 0;
                BufferRemaining = ConnectionContext.CurrentSendSize;
            } while (!ConnectionContext.SendCanceled && !EndOfFile);
            CxPlatEventWaitForever(ConnectionContext.ConnectionShutdownEvent);
            auto StopTime = steady_clock::now();
            PrintTransferSummary(StartTime, StopTime, TotalBytesSent, "sent");
        } else {
            ConnectionContext.Stream = &ClientStream;
            thread ReadStdIn(QcReadStdInThread, std::ref(ConnectionContext));
            ReadStdIn.detach();
            bool ConnectionClosed = false;
            do {
                unique_lock<mutex> Lock(ConnectionContext.RecvDataMutex);
                ConnectionContext.RecvDataCV.wait(Lock, [&ConnectionContext]{return ConnectionContext.RecvData.size() > 0;});
                uint64_t ConsumedLength = 0;
                for(auto& Data : ConnectionContext.RecvData) {
                    if (Data.Buffer == nullptr && Data.Length == 0) {
                        // Connection closed
                        ConnectionClosed = true;
                        break;
                    } else {
                        fwrite((char*)Data.Buffer, 1, Data.Length, stdout);
                        ConsumedLength += Data.Length;
                    }
                }
                fflush(stdout);
                ConnectionContext.RecvData.clear();
                if (!ConnectionClosed) {
                    ClientStream.ReceiveComplete(ConsumedLength);
                }
            } while (!ConnectionClosed);
            CxPlatEventWaitForever(ConnectionContext.ConnectionShutdownEvent);
            PrintTransferSummary(
                ConnectionContext.StartTime,
                ConnectionContext.EndTime,
                ConnectionContext.BytesReceived,
                "received");
        }
    } else {
        Log() << "Error! You didn't specify listen or target!" << endl;
        return QUIC_STATUS_INVALID_STATE;
    }

    if (Wait) {
        Log() << "Press any key to exit..." << endl;
        getchar();
    }

    return 0;
}
