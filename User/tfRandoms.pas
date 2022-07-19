{ *********************************************************** }
{ *                     TForge Library                      * }
{ *       Copyright (c) Sergey Kasandrov 1997, 2016         * }
{ *********************************************************** }

unit tfRandoms;

{$I TFL.inc}

interface

uses SysUtils, tfTypes, tfConsts, tfExceptions,
    {$IFDEF TFL_DLL} tfImport {$ELSE} tfRandEngines {$ENDIF};

type
  TRandom = record
  private
    FRandom: IRandom;
  public
    procedure GetRand(var Buf; BufSize: LongWord);
    procedure Burn;
    procedure Free;
  end;

implementation

{ TRandom }

procedure TRandom.Burn;
begin
  if FRandom <> nil then begin
{$IFDEF TFL_INTFCALL}
    FRandom.Burn;
{$ELSE}
    TRandEngine.Burn(PRandEngine(FRandom));
{$ENDIF}
  end;
end;

procedure TRandom.Free;
begin
  FRandom:= nil;
end;

procedure TRandom.GetRand(var Buf; BufSize: LongWord);
var
  ErrCode: TF_RESULT;

begin
  if FRandom = nil then begin
{$IFDEF TFL_DLL}
    ErrCode:= GetRandInstance(FRandom);
{$ELSE}
    ErrCode:= GetRandInstance(PRandEngine(FRandom));
{$ENDIF}
    if ErrCode <> TF_S_OK then raise
      ERandError.Create(ErrCode);
  end;
{$IFDEF TFL_INTFCALL}
  ErrCode:= FRandom.GetRand(@Buf, BufSize);
{$ELSE}
  ErrCode:= TRandEngine.GetRand(PRandEngine(FRandom), @Buf, BufSize);
{$ENDIF}
  if ErrCode <> TF_S_OK then raise
    ERandError.Create(ErrCode, SRandFailure);
end;

end.
