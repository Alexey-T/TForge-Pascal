{ *********************************************************** }
{ *                     TForge Library                      * }
{ *       Copyright (c) Sergey Kasandrov 1997, 2016         * }
{ *********************************************************** }

unit tfExceptions;

interface

uses SysUtils, tfTypes;

type
  EForgeError = class(Exception)
  private
    FCode: TF_RESULT;
  public
    constructor Create(ACode: TF_RESULT; const Msg: string = '');
    property Code: TF_RESULT read FCode;
  end;

  ERandError = class(EForgeError);
  EByteArrayError = class(EForgeError);

procedure ForgeError(ACode: TF_RESULT; const Msg: string = '');
function ForgeInfo(ACode: TF_RESULT): string;

implementation

{ EForgeError }

constructor EForgeError.Create(ACode: TF_RESULT; const Msg: string);
begin
  if Msg = '' then
    inherited Create(Format('Forge Error 0x%.8x (%s)', [ACode, ForgeInfo(ACode)]))
  else
    inherited Create(Msg);
  FCode:= ACode;
end;

function ForgeInfo(ACode: TF_RESULT): string;
begin
  case ACode of
    TF_S_OK: Result:= 'TF_S_OK';
    TF_S_FALSE: Result:= 'TF_S_FALSE';
    TF_E_FAIL: Result:= 'TF_E_FAIL';
    TF_E_INVALIDARG: Result:= 'TF_E_INVALIDARG';
    TF_E_NOINTERFACE: Result:= 'TF_E_NOINTERFACE';
    TF_E_NOTIMPL: Result:= 'TF_E_NOTIMPL';
    TF_E_OUTOFMEMORY: Result:= 'TF_E_OUTOFMEMORY';
    TF_E_UNEXPECTED: Result:= 'TF_E_UNEXPECTED';

    TF_E_NOMEMORY: Result:= 'TF_E_NOMEMORY';
    TF_E_LOADERROR: Result:= 'TF_E_LOADERROR';
  else
    Result:= 'Unknown';
  end;
end;

procedure ForgeError(ACode: TF_RESULT; const Msg: string);
begin
  raise EForgeError.Create(ACode, Msg);
end;

end.
