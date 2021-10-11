object MainForm: TMainForm
  Left = 220
  Top = 127
  Width = 679
  Height = 361
  Caption = 'IP packet logger'
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -14
  Font.Name = 'MS Sans Serif'
  Font.Style = []
  OldCreateOrder = False
  Position = poScreenCenter
  OnCreate = FormCreate
  OnDestroy = FormDestroy
  PixelsPerInch = 120
  TextHeight = 16
  object MainPanel: TPanel
    Left = 0
    Top = 0
    Width = 671
    Height = 57
    Align = alTop
    BevelOuter = bvNone
    TabOrder = 0
    object ALabel: TLabel
      Left = 10
      Top = 18
      Width = 95
      Height = 16
      Caption = 'Select Interface:'
      Font.Charset = DEFAULT_CHARSET
      Font.Color = clWindowText
      Font.Height = -13
      Font.Name = 'MS Sans Serif'
      Font.Style = []
      ParentFont = False
    end
    object TopLabel: TLabel
      Left = 0
      Top = 41
      Width = 671
      Height = 16
      Align = alBottom
    end
    object InterfaceComboBox: TComboBox
      Left = 114
      Top = 15
      Width = 198
      Height = 24
      ItemHeight = 16
      TabOrder = 0
    end
    object FileCheckBox: TCheckBox
      Left = 401
      Top = 18
      Width = 96
      Height = 21
      Caption = 'Log To File'
      TabOrder = 1
    end
    object MainButton: TButton
      Left = 560
      Top = 16
      Width = 97
      Height = 25
      Caption = 'Start'
      TabOrder = 2
      OnClick = MainButtonClick
    end
  end
  object LogMemo: TMemo
    Left = 0
    Top = 57
    Width = 671
    Height = 276
    Align = alClient
    Ctl3D = False
    Font.Charset = ANSI_CHARSET
    Font.Color = clWindowText
    Font.Height = -15
    Font.Name = 'Courier New'
    Font.Style = []
    ParentCtl3D = False
    ParentFont = False
    ReadOnly = True
    ScrollBars = ssBoth
    TabOrder = 1
    Visible = False
    WordWrap = False
  end
end
