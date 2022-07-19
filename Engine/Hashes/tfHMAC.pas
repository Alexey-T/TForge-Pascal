{ *********************************************************** }
{ *                     TForge Library                      * }
{ *       Copyright (c) Sergey Kasandrov 1997, 2016         * }
{ * ------------------------------------------------------- * }
{ *  documentation: RFC2104                                 * }
{ * ------------------------------------------------------- * }
{ *********************************************************** }

unit tfHMAC;

{$I TFL.inc}

interface

uses tfTypes, tfByteVectors;

type
  PHMACAlg = ^THMACAlg;
  THMACAlg = record
  private const
    IPad = $36;
    OPad = $5C;

  private
    FVTable: Pointer;
    FRefCount: Integer;
    FHash: IHashAlgorithm;
    FKey: PByteVector;
  public
    class function Release(Inst: PHMACAlg): Integer; stdcall; static;
    class procedure Init(Inst: PHMACAlg; Key: Pointer; KeySize: Cardinal);
          {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class procedure Update(Inst: PHMACAlg; Data: Pointer; DataSize: Cardinal);
          {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class procedure Done(Inst: PHMACAlg; PDigest: Pointer);
          {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class procedure Burn(Inst: PHMACAlg);
          {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function GetDigestSize(Inst: PHMACAlg): Integer;
          {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
//    class function GetBlockSize(Inst: PHMACAlg): Integer;
//          {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function Duplicate(Inst: PHMACAlg; var DupInst: PHMACAlg): TF_RESULT;
          {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function PBKDF2(Inst: PHMACAlg;
          Password: Pointer; PassLen: Cardinal; Salt: Pointer; SaltLen: Cardinal;
          Rounds, dkLen: Cardinal; var Key: PByteVector): TF_RESULT;
          {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
  end;

function GetHMACAlgorithm(var Inst: PHMACAlg; const HashAlg: IHashAlgorithm): TF_RESULT;
//function GetHMACAlgorithm(var Inst: PHMACAlg; HashAlg: IHashAlgorithm): TF_RESULT;

implementation

uses tfRecords;

const
  HMACVTable: array[0..9] of Pointer = (
   @TForgeInstance.QueryIntf,
   @TForgeInstance.Addref,
   @THMACAlg.Release,

   @THMACAlg.Init,
   @THMACAlg.Update,
   @THMACAlg.Done,
   @THMACAlg.Burn,
   @THMACAlg.GetDigestSize,
//   @THMACAlg.GetBlockSize,
   @THMACAlg.Duplicate,
   @THMACAlg.PBKDF2
   );

function GetHMACAlgorithm(var Inst: PHMACAlg; const HashAlg: IHashAlgorithm): TF_RESULT;
var
  P: PHMACAlg;
  BlockSize: Integer;

begin
  BlockSize:= HashAlg.GetBlockSize;
// protection against hashing algorithms which should not be used in HMAC
  if BlockSize = 0 then begin
    Result:= TF_E_INVALIDARG;
    Exit;
  end;
  try
    New(P);
    P^.FVTable:= @HMACVTable;
    P^.FRefCount:= 1;
                  // interface assignment - refcount is incremented by the compiler
    P^.FHash:= HashAlg;
                  // the bug is commented out - no need to increment refcount manually
//    HashAlg._AddRef;
    P^.FKey:= nil;
    Result:= ByteVectorAlloc(P^.FKey, BlockSize);
    if Result = TF_S_OK then begin
      if Inst <> nil then THMACAlg.Release(Inst);
      Inst:= P;
    end;
  except
    Result:= TF_E_OUTOFMEMORY;
  end;
end;

{ THMACAlg }

class function THMACAlg.Release(Inst: PHMACAlg): Integer;
type
  TVTable = array[0..9] of Pointer;
  PVTable = ^TVTable;
  PPVTable = ^PVTable;

  TBurnProc = procedure(Inst: Pointer);
               {$IFDEF TFL_STDCALL}stdcall;{$ENDIF}
var
  BurnProc: Pointer;

begin
  if Inst.FRefCount > 0 then begin
    Result:= tfDecrement(Inst.FRefCount);
    if Result = 0 then begin
      BurnProc:= PPVTable(Inst)^^[6];  // 6 is 'Burn' index
      TBurnProc(BurnProc)(Inst);
      if Inst.FHash <> nil then begin
        Inst.FHash._Release;
      end;
      if Inst.FKey <> nil
        then IBytes(Inst.FKey)._Release;
      FreeMem(Inst);
    end;
  end
  else
    Result:= Inst.FRefCount;
end;

class procedure THMACAlg.Init(Inst: PHMACAlg; Key: Pointer; KeySize: Cardinal);
var
  BlockSize: Integer;
  I: Integer;
  InnerP: PByte;

begin
  BlockSize:= Inst.FHash.GetBlockSize;
//  DigestSize:= Inst.FHash.GetDigestSize;
  FillChar(Inst.FKey.FData, BlockSize, 0);
  if Integer(KeySize) > BlockSize then begin
    Inst.FHash.Init;
    Inst.FHash.Update(Key, KeySize);
    Inst.FHash.Done(@Inst.FKey.FData);
//    KeySize:= DigestSize;
  end
  else begin
    Move(Key^, Inst.FKey.FData, KeySize);
  end;

  InnerP:= @Inst.FKey.FData;
//    OuterP:= @P^.FOuterKey.FData;
//    Move(InnerP^, OuterP^, BlockSize);

  for I:= 0 to BlockSize - 1 do begin
    InnerP^:= InnerP^ xor THMACAlg.IPad;
//      OuterP^:= OuterP^ xor OPad;
    Inc(InnerP);
//      Inc(OuterP);
  end;

  Inst.FHash.Init;
  Inst.FHash.Update(@Inst.FKey.FData, BlockSize);
end;

class procedure THMACAlg.Update(Inst: PHMACAlg; Data: Pointer; DataSize: Cardinal);
begin
  Inst.FHash.Update(Data, DataSize);
end;

class procedure THMACAlg.Done(Inst: PHMACAlg; PDigest: Pointer);
var
  BlockSize, DigestSize, I: Integer;
  P: PByte;

begin
  BlockSize:= Inst.FHash.GetBlockSize;
  DigestSize:= Inst.FHash.GetDigestSize;
  Inst.FHash.Done(PDigest);
  Inst.FHash.Init;
  P:= @Inst.FKey.FData;
  for I:= 0 to BlockSize - 1 do begin
    P^:= P^ xor (IPad xor OPad);
    Inc(P);
  end;
  Inst.FHash.Update(@Inst.FKey.FData, BlockSize);
  Inst.FHash.Update(PDigest, DigestSize);
  Inst.FHash.Done(PDigest);
end;

class function THMACAlg.Duplicate(Inst: PHMACAlg; var DupInst: PHMACAlg): TF_RESULT;
var
  P: PHMACAlg;
//  BlockSize, DigestSize: Integer;
//  I: Integer;
//  InnerP: PByte;

begin
  try
    New(P);
    P^.FVTable:= @HMACVTable;
    P^.FRefCount:= 1;
    P^.FKey:= nil;

    Result:= TByteVector.CopyBytes(Inst.FKey, P^.FKey);
    if Result <> TF_S_OK then Exit;

    Inst.FHash.Duplicate(P^.FHash);

    if DupInst <> nil then THMACAlg.Release(DupInst);
    DupInst:= P;
    Result:= TF_S_OK;
  except
    Result:= TF_E_OUTOFMEMORY;
  end;
end;

{
class function THMACAlg.GetBlockSize(Inst: PHMACAlg): Integer;
begin
  Result:= 0;
end;
}

class function THMACAlg.GetDigestSize(Inst: PHMACAlg): Integer;
begin
  Result:= Inst.FHash.GetDigestSize;
end;

class procedure THMACAlg.Burn(Inst: PHMACAlg);
begin
  FillChar(Inst.FKey.FData, Inst.FKey.FUsed, 0);
  Inst.FHash.Burn;
end;

const
  BigEndianOne = $01000000;

function BigEndianInc(Value: UInt32): UInt32; inline;
begin
  Result:= Value + BigEndianOne;
  if Result shr 24 = 0 then begin
    Result:= Result + $00010000;
    if Result shr 16 = 0 then begin
      Result:= Result + $00000100;
      if Result shr 8 = 0 then begin
        Result:= Result + $00000001;
      end;
    end;
  end;
end;

class function THMACAlg.PBKDF2(Inst: PHMACAlg; Password: Pointer;
  PassLen: Cardinal; Salt: Pointer; SaltLen, Rounds, dkLen: Cardinal;
  var Key: PByteVector): TF_RESULT;

const
  MAX_DIGEST_SIZE = 128;   // = 1024 bits

var
  hLen: Cardinal;
  Digest: array[0 .. MAX_DIGEST_SIZE - 1] of Byte;
  Tmp: PByteVector;
  Count: UInt32;
  L, N, LRounds: Cardinal;
  PData, P1, P2: PByte;


begin
  hLen:= Inst.FHash.GetDigestSize;
  if (hLen > MAX_DIGEST_SIZE) then begin
    Result:= TF_E_INVALIDARG;
    Exit;
  end;
  Tmp:= nil;
  Result:= ByteVectorAlloc(Tmp, dkLen);
  if Result <> TF_S_OK then Exit;
  FillChar(Tmp.FData, dkLen, 0);
  PData:= @Tmp.FData;
  N:= dkLen div hLen;
  Count:= BigEndianOne;
  while N > 0 do begin    // process full hLen blocks
    LRounds:= Rounds;
    P1:= PData;
    if LRounds > 0 then begin
      Init(Inst, PassWord, PassLen);
      Update(Inst, Salt, SaltLen);
      Update(Inst, @Count, SizeOf(Count));
      Done(Inst, @Digest);
      P2:= @Digest;
      L:= hLen shr 2;
      while L > 0 do begin
        PUInt32(P1)^:= PUInt32(P1)^ xor PUInt32(P2)^;
        Inc(PUInt32(P1));
        Inc(PUInt32(P2));
        Dec(L);
      end;
      L:= hLen and 3;
      while L > 0 do begin
        P1^:= P1^ xor P2^;
        Inc(P1);
        Inc(P2);
        Dec(L);
      end;
      Dec(LRounds);
      while LRounds > 0 do begin
        Init(Inst, PassWord, PassLen);
        Update(Inst, @Digest, hLen);
        Done(Inst, @Digest);
        P1:= PData;
        P2:= @Digest;
        L:= hLen shr 2;
        while L > 0 do begin
          PUInt32(P1)^:= PUInt32(P1)^ xor PUInt32(P2)^;
          Inc(PUInt32(P1));
          Inc(PUInt32(P2));
          Dec(L);
        end;
        L:= hLen and 3;
        while L > 0 do begin
          P1^:= P1^ xor P2^;
          Inc(P1);
          Inc(P2);
          Dec(L);
        end;
        Dec(LRounds);
      end;
    end;
    PData:= P1;
    Count:= BigEndianInc(Count);
    Dec(N);
  end;
  N:= dkLen mod hLen;
  if N > 0 then begin    // process last incomplete block
    LRounds:= Rounds;
    if LRounds > 0 then begin
      Init(Inst, PassWord, PassLen);
      Update(Inst, Salt, SaltLen);
      Update(Inst, @Count, SizeOf(Count));
      Done(Inst, @Digest);
      P1:= PData;
      P2:= @Digest;
      L:= N;
      while L > 0 do begin
        P1^:= P1^ xor P2^;
        Inc(P1);
        Inc(P2);
        Dec(L);
      end;
      Dec(LRounds);
      while LRounds > 0 do begin
        Init(Inst, PassWord, PassLen);
        Update(Inst, @Digest, hLen);
        Done(Inst, @Digest);
        P1:= PData;
        P2:= @Digest;
        L:= N;
        while L > 0 do begin
          P1^:= P1^ xor P2^;
          Inc(P1);
          Inc(P2);
          Dec(L);
        end;
        Dec(LRounds);
      end;
    end;
  end;
  tfFreeInstance(Key);  //if Key <> nil then TtfRecord.Release(Key);
  Key:= Tmp;
end;

end.
