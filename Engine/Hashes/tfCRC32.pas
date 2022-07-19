{ *********************************************************** }
{ *                     TForge Library                      * }
{ *       Copyright (c) Sergey Kasandrov 1997, 2016         * }
{ *********************************************************** }

unit tfCRC32;

{$I TFL.inc}

interface

uses tfTypes;

type
  PCRC32Alg = ^TCRC32Alg;
  TCRC32Alg = record
  private
    FVTable: Pointer;
    FRefCount: Integer;
    FValue: UInt32;
  public
//    class function Release(Inst: PCRC32Alg): Integer; stdcall; static;
    class procedure Init(Inst: PCRC32Alg);
         {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class procedure Update(Inst: PCRC32Alg; Data: PByte; DataSize: Cardinal);
         {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class procedure Done(Inst: PCRC32Alg; PDigest: PUInt32);
         {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
//    class procedure Purge(Inst: PCRC32Alg);  -- redirected to Init
//         {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function GetDigestSize(Inst: PCRC32Alg): Integer;
         {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function GetBlockSize(Inst: PCRC32Alg): Integer;
         {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function Duplicate(Inst: PCRC32Alg; var DupInst: PCRC32Alg): TF_RESULT;
         {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
  end;

function GetCRC32Algorithm(var Inst: PCRC32Alg): TF_RESULT;

implementation

uses tfRecords, tfUtils;

const
  CRC32_INIT_VALUE = $FFFFFFFF;

const
  VTable: array[0..9] of Pointer = (
    @TForgeInstance.QueryIntf,
    @TForgeInstance.Addref,
    @HashAlgRelease,
//    @TCRC32Alg.Release,

    @TCRC32Alg.Init,
    @TCRC32Alg.Update,
    @TCRC32Alg.Done,
    @TCRC32Alg.Init,
    @TCRC32Alg.GetDigestSize,
    @TCRC32Alg.GetBlockSize,
    @TCRC32Alg.Duplicate
  );

function GetCRC32Algorithm(var Inst: PCRC32Alg): TF_RESULT;
var
  P: PCRC32Alg;

begin
  try
    New(P);
    P^.FVTable:= @VTable;
    P^.FRefCount:= 1;
    P^.FValue:= CRC32_INIT_VALUE;
    if Inst <> nil then HashAlgRelease(Inst);
    Inst:= P;
    Result:= TF_S_OK;
  except
    Result:= TF_E_OUTOFMEMORY;
  end;
end;

class procedure TCRC32Alg.Init(Inst: PCRC32Alg);
begin
  Inst.FValue:= CRC32_INIT_VALUE;
end;

class procedure TCRC32Alg.Update(Inst: PCRC32Alg; Data: PByte; DataSize: Cardinal);
var
  Tmp: UInt32;

begin
  Tmp:= Inst.FValue;
  while DataSize > 0 do begin
    Tmp:= Crc32Table[Byte(Tmp xor Data^)] xor UInt32(Tmp shr 8);
    Dec(DataSize);
    Inc(Data);
  end;
  Inst.FValue:= Tmp;
end;

class procedure TCRC32Alg.Done(Inst: PCRC32Alg; PDigest: PUint32);
var
  P, PD: PByte;
  L: Integer;

begin
//  PDigest^:= not Inst.FValue;
  L:= 4;
  Inst.FValue:= not Inst.FValue;
  P:= @Inst.FValue;
  PD:= PByte(PDigest) + 4;
  repeat
    Dec(PD);
    PD^:= P^;
    Inc(P);
    Dec(L);
  until L = 0;
  Inst.FValue:= CRC32_INIT_VALUE;
end;

class function TCRC32Alg.Duplicate(Inst: PCRC32Alg; var DupInst: PCRC32Alg): TF_RESULT;
begin
  Result:= GetCRC32Algorithm(DupInst);
  if Result = TF_S_OK then
    DupInst.FValue:= Inst.FValue;
end;

class function TCRC32Alg.GetDigestSize(Inst: PCRC32Alg): Integer;
begin
  Result:= SizeOf(UInt32);
end;

class function TCRC32Alg.GetBlockSize(Inst: PCRC32Alg): Integer;
begin
  Result:= 0;
end;

end.
