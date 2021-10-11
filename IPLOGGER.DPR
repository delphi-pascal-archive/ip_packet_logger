program iplogger;

uses
  Forms,
  ULogger in 'ULOGGER.PAS' {MainForm},
  tcpiphlp in 'tcpiphlp.pas';

{$R *.res}

begin
  Application.Initialize;
  Application.CreateForm(TMainForm, MainForm);
  Application.Run;
end.
