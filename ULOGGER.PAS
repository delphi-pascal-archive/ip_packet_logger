unit ULogger;

interface

uses
  Windows, Controls, Classes, StdCtrls,
  Messages, SysUtils, Forms, Dialogs, ExtCtrls,
  Winsock, TcpIpHlp;

CONST WM_ASYNCSELECT = WM_USER + 1;

type
  TAsyncEvent  = procedure (Sender: TObject; Socket: TSocket) of object;

  TMainForm = class(TForm)
    MainPanel: TPanel;
    InterfaceComboBox: TComboBox;
    ALabel: TLabel;
    LogMemo: TMemo;
    FileCheckBox: TCheckBox;
    MainButton: TButton;
    TopLabel: TLabel;
    procedure FormCreate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure MainButtonClick(Sender: TObject);

  private
    { private declarations }
    FSocket: TSocket;
    FLogOpen: Boolean;
    FLogFile: Textfile;
    FLogName: String;
    FLogInProgress: Boolean;

    FAsyncRead:    TAsyncEvent;
    FAsyncWrite:   TAsyncEvent;
    FAsyncOOB:     TAsyncEvent;
    FAsyncAccept:  TAsyncEvent;
    FAsyncConnect: TAsyncEvent;
    FAsyncClose:   TAsyncEvent;

    procedure AddInterface(value: String; iff_types: Integer);
    procedure HandleData(Sender: TObject; Socket: TSocket);
    procedure Log(s: String);
    function  StartLogging: Boolean;
    function  StopLogging: String;

  protected
    procedure WMASyncSelect(var msg: TMessage); message WM_ASYNCSELECT;

  public
    { public declarations }
  end;

var
  MainForm: TMainForm;

implementation

{$R *.DFM}

var WarnedAboutW2k: Boolean = FALSE;

procedure WarnAboutW2k;
begin
  if NOT WarnedAboutW2k then
  begin
    WarnedAboutW2k := TRUE;
    if NOT Win2KDetected then
      ShowMessage('Warning: This application requires Windows 2000/XP, '
                 +'which weren''t detected on this computer. '
                 +'Therefore you are likely to get socket errors because '
                 +'of the insufficient MS Winsock implementation.');
  end
end;

procedure RaiseException(msg: String; eCode: Integer);
//
// Format the message and throw a nice exception
//
  function AdditionalMessage: String;
  begin
    Result := SysErrorMessage(eCode);
    if Result <> '' then Result := ': ' + Result
  end;
begin
  if eCode = 0 then
    raise Exception.Create(msg)
  else
    raise Exception.Create('ERROR: '+msg+' [SocketError '+IntToStr(eCode)
                          +AdditionalMessage+']')
end;

function LogFilename: String;
VAR this_computer: Array [0..MAXCHAR] of Char;
    len: DWORD;
begin
  // Here we build our log filename.
  // if we can get the machine name
  // then we use "<machinename>.log"
  // otherwise we are stuck with
  // "IPLOGGER.LOG"
  len := sizeof(this_computer)-1;
  GetComputerName(@this_computer, len);
  if len = 0 then
    Result := 'IPLOGGER'
  else begin
    SetLength(Result, len);
    Move(this_computer, Result[1], len);
  end;
  Result := Result+'.log';
end;

function PadStr(s: String; w: Word): String;
// A little helper function to make things pretty
begin
  FmtStr(Result, '%*s', [w, s])
end;

function LogCaption: String;
// A little helper function to make things pretty
begin
  Result := 'PROTO :'+PadStr('SOURCE_IP',15)+#9+' :PORT'+#9+PadStr('DESTINATION_IP',15)+#9+':PORT'+#9+': SVC/TYPE'+#9+'DATA->'
end;

function MakeReadable(s: String): String;
// A little helper function to make things pretty
CONST MAX_UNWRAPPED_LENGTH=950;
VAR i: Integer;
begin
  for i := 1 to Length(s) do
  begin
    if Byte(s[i]) <  32 then s[i] := '.';{ not printable }
    if Byte(s[i]) > 127 then s[i] := '.';{ not printable?}
  end;

  if Length(s) > MAX_UNWRAPPED_LENGTH then
    Result := Copy(s, 1, MAX_UNWRAPPED_LENGTH)+'<!SNIPPED!>'
  else
    Result := s
end;

procedure TMainForm.HandleData(Sender: TObject; Socket: TSocket);
VAR
  p_iphdr: PHdrIP;
  p_tcphdr: PHdrTCP;
  p_udphdr: PHdrUDP;
  s_port, d_port, len: Integer;
  src_ip, dst_ip, src_port, dst_port: String;
  protocol, comments, data: String;
  // Do we know how big our buffer should be?
  // Routers can handle up to 64K octet datagrams,
  // but we know that Ethernet has a maximum frame
  // length of 1514 bytes, so this should cover our case.
  IpBuffer: Array[0..$2000] of Char;

  function GetDataByOffset(d_offset: Integer): String;
  VAR data_start: PChar;
      i: Integer;
  begin
    data_start := PChar(PChar(p_iphdr)+d_offset);

    if ntohs(p_iphdr.tot_len) < sizeof(IpBuffer) then
      i := ntohs(p_iphdr.tot_len) - d_offset
    else
      i := sizeof(IpBuffer) - d_offset;
    SetLength(Result, i);
    Move(data_start^, Result[1], i);
  end;
begin
  Application.ProcessMessages; { always a good idea }

  if SOCKET_ERROR = recv(FSocket, IpBuffer, sizeof(IpBuffer), 0) then
  begin
    // We do not care to report errors in this case
    // if there is no data to read, then so be it.
    // The event handler will get called again.
    //
    Exit;
  end;

  p_iphdr := PHdrIP(@IpBuffer);
  src_ip  := inet_ntoa(TInAddr(p_iphdr.saddr));
  dst_ip  := inet_ntoa(TInAddr(p_iphdr.daddr));

  // Check if this is something we want to ignore...
  // (see the .INI file for ignore ranges)
  //
  //if IgnoreSource(src_ip) then Exit;
  //if IgnoreDestination(dst_ip) then Exit;
  //
  // We need to add these two functions sometime soon,
  // so that we can ignore traffic from or to specific
  // IP addresses

  protocol := GetIPProtoName(p_iphdr.protocol);

  data := '';
  len := GetIHlen(p_iphdr^);

  if p_iphdr.protocol = IPPROTO_ICMP then // is ICMP?
  begin
    comments := GetICMPType(PByte(PChar(p_iphdr)+len)^);
    src_port := '-'; { port does not apply to ICMP }
    dst_port := '-';
  end
  else begin
    s_port := 0;
    d_port := 0;
    if p_iphdr.protocol = IPPROTO_TCP then // is TCP
    begin
      p_tcphdr := PHdrTCP(PChar(p_iphdr)+len);
      s_port   := ntohs(p_tcphdr.source);
      d_port   := ntohs(p_tcphdr.dest);

      data := GetDataByOffset(len + GetTHdoff(p_tcphdr^));
    end;

    if p_iphdr.protocol = IPPROTO_UDP then // is UDP
    begin
      p_udphdr := PHdrUDP(PChar(p_iphdr)+len);
      s_port   := ntohs(p_udphdr.src_port);
      d_port   := ntohs(p_udphdr.dst_port);

      data := GetDataByOffset(len + sizeof(THdrUDP));
    end;

    src_port   := IntToStr(s_port);
    dst_port   := IntToStr(d_port);

    comments := GetServiceName(s_port, d_port);
  end;

  // Log
  Log(PadStr(protocol,5)+': '
     +PadStr(src_ip, 15)+#9+':'+src_port+#9
     +PadStr(dst_ip, 15)+#9+':'+dst_port+#9
     +': '+comments+#9+MakeReadable(data));
end;

procedure TMainForm.WMASyncSelect(var msg: TMessage);
//
// This is a procedure for a common case scenario
// Notice that in this application we handle only FD_READ
// We are not interested in any other socket events
//
begin
  case LoWord(msg.lParam) of
    FD_READ:    if Assigned(FAsyncRead)    then FAsyncRead(Self,msg.wParam);
    FD_WRITE:   if Assigned(FAsyncWrite)   then FAsyncWrite(Self,msg.wParam);
    FD_OOB:     if Assigned(FAsyncOOB)     then FAsyncOOB(Self,msg.wParam);
    FD_ACCEPT:  if Assigned(FAsyncAccept)  then FAsyncAccept(Self,msg.wParam);
    FD_CONNECT: if Assigned(FAsyncConnect) then FAsyncConnect(Self,msg.wParam);
    FD_CLOSE:   if Assigned(FAsyncClose)   then FAsyncClose(Self,msg.wParam);
  end;
end;

function  TMainForm.StartLogging: Boolean;
VAR
  host, errStr: String;
  timeout, ret: Integer;
  sa: TSockAddr;
  dwBufferInLen,
  dwBufferOutLen,
  dwDummy: DWORD;
  addr: u_long;
begin
  Result := FALSE; { guilty until proven innocent }

  // We must have a valid interface IP address.
  //
  host := InterfaceComboBox.Text;
  if host = '' then
  begin
    ShowMessage('You must supply a valid IP address!');
    Exit;
  end;

  // Initialize WinSock. We are going to work with raw
  // sockets, so we require Winsock ver 2.
  //
  errStr := InitWinsock(2,2);
  if errStr <> '' then
  begin
    ShowMessage(errStr);
    Exit;
  end;

  try
    // Create a raw socket with following attributes:
    //  Address Family: AF_INET
    //  Socket Type: RAW, Protocol: IPPROTO_IP
    //
    FSocket := socket(AF_INET, SOCK_RAW, IPPROTO_IP);
    if FSocket = INVALID_SOCKET then
      RaiseException('Invalid Socket', WSAGetLastError);

    // Set receive timeout to 3 seconds
    // SO_SNDTIMEO and SO_RCVTIMEO options set up time-outs
    // for the send(), sendto(), recv(), and recvfrom() functions.
    // You can set these options on any type of socket in any
    // state. The default value for these options is zero,
    // which refers to an infinite time-out. Any other setting
    // is the time-out, in milliseconds. It is valid to set
    // the time-out to any value, but values less than 500 milliseconds
    // (half a second) are interpreted to be 500 ms.
    //
    timeout := 3000;
    ret := setsockopt(FSocket, SOL_SOCKET, SO_RCVTIMEO, PChar(@timeout), sizeof(timeout));
    if ret = SOCKET_ERROR Then
      RaiseException('Setsockopt() failed', WSAGetLastError);

    // Convert the dotted IP into a unsigned long
    // (Note: bytes will be in network order)
    //
    addr := ResolveHostAddress(host);
    if addr = u_long(-1) then
      RaiseException('Interface must be a valid IP address', 0);

    // We are about to call bind() - to give a name to our socket.
    // Note: if the port is zero, the service provider
    // assigns a unique port to the application with
    // a value between 1024 and 5000
    //
    FillChar(sa, sizeof(sa), 0);
    sa.sin_family := AF_INET;
    sa.sin_addr.s_addr := addr;

    ret := bind(FSocket, sa, sizeof(sa));
    if ret = SOCKET_ERROR then
      RaiseException('bind() failed', WSAGetLastError);

    // The WSAIoctl function is used to set or retrieve
    // operating parameters associated with the socket,
    // the transport protocol, or the communications subsystem.
    // SIO_RCVALL control code enables a socket to receive
    // all IP packets on the network. The socket handle
    // passed to the WSAIoctl function must be of AF_INET
    // address family, SOCK_RAW socket type, and IPPROTO_IP protocol.
    // The socket also must be bound to an explicit local interface,
    // which means that you cannot bind to INADDR_ANY.
    //
    dwBufferInLen := 1;
    dwBufferOutLen := 0;
    ret := WSAIoctl(FSocket, SIO_RCVALL,
        @dwBufferInLen, sizeof(dwBufferInLen),
        @dwBufferOutLen, sizeof(dwBufferOutLen),
        @dwDummy, Nil, Nil);

    if ret = SOCKET_ERROR then
      RaiseException('WSAIoctl() failed', WSAGetLastError);

    // Register our asynchronous socket event handler
    //
    ret := WSAASyncSelect(FSocket, handle, WM_ASYNCSELECT, FD_READ);
    if ret = SOCKET_ERROR then
      RaiseException('WSAAsyncSelect() failed', WSAGetLastError)
    else
      Result := TRUE;
  except
    CleanupWinsock(FSocket);
    raise;
  end;
end;

function  TMainForm.StopLogging: String;
begin
  Result := '';

  {$I-}
  if FLogOpen then
  begin
    Result := 'Log File: '+FLogName;
    CloseFile(FLogFile);
    FLogOpen := FALSE;
  end;
  {$I+}

  // Unregister our event handler, and close the socket
  //
  WSAASyncSelect(FSocket, Handle, WM_ASYNCSELECT, 0);
  CleanupWinsock(FSocket);
end;

procedure TMainForm.Log(s: String);
begin
  // If "LogToFile" is checked and if the log file
  // has not been opened yet, then we have to
  // open the file
  //
  if FileCheckBox.Checked AND NOT FLogOpen then
  begin
    {$I-}
    FLogName := ExtractFilePath(Application.ExeName)+LogFilename;
    AssignFile(FLogFile, FLogName);
    if FileExists(FLogName) then
      Append(FLogFile)
    else
      Rewrite(FLogFile);
    {$I-}
    FLogOpen := IOResult = 0;
    if FLogOpen then
    begin
     // Start the log with a time stamp
     WriteLn(FLogFile);
     WriteLn(FLogFile, 'LOG start: '+FormatDateTime('yyyy-mm-dd hh:nn:ss', now));
     WriteLn(FLogFile);
     WriteLn(FLogFile, LogCaption);
     WriteLn(FLogFile);
    end;
  end;

  // Write to log file, if it's open
  if FLogOpen then WriteLn(FLogFile, s);

  // No matter what we write to our memo, of course
  LogMemo.Lines.Add(s)
end;

procedure TMainForm.AddInterface(value: String; iff_types: Integer);
begin
  InterfaceComboBox.Items.Add(value)
end;

procedure TMainForm.FormCreate(Sender: TObject);
CONST valid_types = IFF_UP
                 OR IFF_BROADCAST
                {OR IFF_LOOPBACK - we don't want this one}
                 OR IFF_POINTTOPOINT
                 OR IFF_MULTICAST;
begin
  ClientHeight := MainPanel.Height;
  // This will fill the ComboBox
  EnumInterfaces(AddInterface, valid_types);
  if InterfaceComboBox.Items.Count > 0 then
    InterfaceComboBox.ItemIndex := 0;
  FAsyncRead := HandleData;
end;

procedure TMainForm.FormDestroy(Sender: TObject);
begin
  // Stop logging and close the socket,
  // and the log file, if necessary
  //
  if FLogInProgress then  MainButtonClick(Sender);
end;

procedure TMainForm.MainButtonClick(Sender: TObject);
begin
  // One button will serve as our Start and Stop button.
  //

  if FLogInProgress then
  begin
    // Change the caption of the button,
    // and enable controls on the panel
    //
    FLogInProgress := FALSE;
    TopLabel.Caption := StopLogging;
    MainButton.Caption := 'Start';
    FileCheckBox.Enabled := TRUE;
    InterfaceComboBox.Enabled := TRUE;
    Log('Logging stopped by user ['+FormatDateTime('yyyy-mm-dd hh:nn:ss', now)+']');
  end
  else begin
    WarnAboutW2k;      // We want Win2K

    if StartLogging then
    begin
      // Change the caption, disable controls on
      // the panel, clear the log screen, and
      // resize the form to display the log memo
      //
      FLogInProgress := TRUE;
      MainButton.Caption := 'Stop';
      FileCheckBox.Enabled := FALSE;
      InterfaceComboBox.Enabled := FALSE;
      TopLabel.Caption := LogCaption;
      LogMemo.Clear;

      // is the form currently collapsed?
      // if yes, then resize
      if ClientHeight = MainPanel.Height then
        Height := Screen.Height - Top - 40;

      LogMemo.Visible := TRUE;
      Log('Logging started ['+FormatDateTime('yyyy-mm-dd hh:nn:ss', now)+']');
    end
  end
end;

end.
