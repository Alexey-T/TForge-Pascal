{ *********************************************************** }
{ *                     TForge Library                      * }
{ *       Copyright (c) Sergey Kasandrov 1997, 2016         * }
{ *********************************************************** }

unit tfStubOS;

{$I TFL.inc}

interface

uses tfTypes;

function GenRandom(var Buf; BufSize: Cardinal): TF_RESULT;

implementation

function GenRandom(var Buf; BufSize: Cardinal): TF_RESULT;
begin
  Result:= TF_E_NOTIMPL;
end;

end.
