{ *********************************************************** }
{ *                     TForge Library                      * }
{ *       Copyright (c) Sergey Kasandrov 1997, 2016         * }
{ *********************************************************** }

unit tfKeyStreams;

interface

{$I TFL.inc}

uses tfTypes, tfUtils{, tfCipherServ};

type
  PStreamCipherInstance = ^TStreamCipherInstance;
  TStreamCipherInstance = record
  private type
    TBlock = array[0..TF_MAX_CIPHER_BLOCK_SIZE - 1] of Byte;
  private
{$HINTS OFF}
    FVTable:   Pointer;
    FRefCount: Integer;
{$HINTS ON}
    FCipher: ICipher;
    FBlockSize: Cardinal;
// don't assume that FBlockNo is the rightmost 8 bytes of a block cipher's IV
//    FBlockNo: UInt64;
    FPos: Cardinal;       // 0 .. FBlockSize - 1
    FBlock: TBlock;       // var len
  public
    class function GetInstance(var Inst: PStreamCipherInstance; Alg: ICipher): TF_RESULT; static;
    class procedure Burn(Inst: PStreamCipherInstance);
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function Duplicate(Inst: PStreamCipherInstance; var NewInst: PStreamCipherInstance): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function ExpandKey(Inst: PStreamCipherInstance;
      Key: PByte; KeySize: Cardinal; Nonce: UInt64): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function Read(Inst: PStreamCipherInstance; Data: PByte; DataSize: Cardinal): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function Skip(Inst: PStreamCipherInstance; Dist: Int64): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function Crypt(Inst: PStreamCipherInstance; Data: PByte; DataSize: Cardinal): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function SetNonce(Inst: PStreamCipherInstance; Nonce: UInt64): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function GetNonce(Inst: PStreamCipherInstance; var Nonce: UInt64): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
  end;

//function GetKeyStreamByAlgID(AlgID: UInt32; var A: PKeyStreamEngine): TF_RESULT;

implementation

uses tfRecords;

const
  VTable: array[0..10] of Pointer = (
    @TForgeInstance.QueryIntf,
    @TForgeInstance.Addref,
    @TForgeInstance.SafeRelease,
//    @TKeyStreamInstance.Release,
    @TStreamCipherInstance.Burn,
    @TStreamCipherInstance.Duplicate,
    @TStreamCipherInstance.ExpandKey,
    @TStreamCipherInstance.SetNonce,
    @TStreamCipherInstance.GetNonce,
    @TStreamCipherInstance.Skip,
    @TStreamCipherInstance.Read,
    @TStreamCipherInstance.Crypt
  );

(*
function GetKeyStreamByAlgID(AlgID: UInt32; var A: PKeyStreamEngine): TF_RESULT;
var
  Server: ICipherServer;
  Alg: ICipherAlgorithm;
  BlockSize: Cardinal;
  Tmp: PKeyStreamEngine;


begin
  Result:= GetCipherServer(Server);
  if Result <> TF_S_OK then Exit;
  Result:= Server.GetByAlgID(AlgID, Alg);
  if Result <> TF_S_OK then Exit;
  BlockSize:= Alg.GetBlockSize;
  if (BlockSize = 0) or (BlockSize > TF_MAX_CIPHER_BLOCK_SIZE) then begin
    Result:= TF_E_UNEXPECTED;
    Exit;
  end;
  try
    Tmp:= AllocMem(SizeOf(TKeyStreamEngine) + BlockSize);
    Tmp^.FVTable:= @EngVTable;
    Tmp^.FRefCount:= 1;
    Tmp^.FCipher:= Alg;
    Tmp^.FBlockSize:= BlockSize;

    if A <> nil then TKeyStreamEngine.Release(A);
    A:= Tmp;
    Result:= TF_S_OK;
  except
    Result:= TF_E_OUTOFMEMORY;
  end;
end;
*)

{ TKeyStreamInstance }
(*
procedure Burn(Inst: PKeyStreamEngine); inline;
var
  BurnSize: Integer;

begin
  BurnSize:= SizeOf(TKeyStreamEngine) - Integer(@PKeyStreamEngine(nil)^.FBlockNo);
  FillChar(Inst.FBlockNo, BurnSize, 0);
end;
*)

procedure BurnMem(Inst: PStreamCipherInstance); inline;
var
  BurnSize: Integer;

begin
  BurnSize:= SizeOf(TStreamCipherInstance) - SizeOf(TStreamCipherInstance.TBlock)
             + Integer(Inst.FBlockSize) - Integer(@PStreamCipherInstance(nil)^.FCipher);

  FillChar(Inst.FCipher, BurnSize, 0);
end;

class procedure TStreamCipherInstance.Burn(Inst: PStreamCipherInstance);
begin
//  Inst.FCipher.BurnKey;
//  tfFreeInstance(Inst.FCipher);
  Inst.FCipher:= nil;
  BurnMem(Inst);
end;

{
class function TKeyStreamInstance.Release(Inst: PKeyStreamInstance): Integer;
begin
  if Inst.FRefCount > 0 then begin
    Result:= tfDecrement(Inst.FRefCount);
    if Result = 0 then begin
      Inst.FCipher.BurnKey;
      Inst.FCipher:= nil;
      Burn(Inst);
      FreeMem(Inst);
    end;
  end
  else
    Result:= Inst.FRefCount;
end;
}

class function TStreamCipherInstance.ExpandKey(Inst: PStreamCipherInstance;
                 Key: PByte; KeySize: Cardinal; Nonce: UInt64): TF_RESULT;
var
  Flags: UInt32;

begin
// for block ciphers; stream ciphers will return error code which is ignored
  Flags:= CTR_ENCRYPT;
  Inst.FCipher.SetKeyParam(TF_KP_FLAGS, @Flags, SizeOf(Flags));

//  Inst.FBlockNo:= 0;
  Inst.FPos:= 0;
  Result:= Inst.FCipher.ExpandKey(Key, KeySize);
  if Result = TF_S_OK then
    Result:= Inst.FCipher.SetKeyParam(TF_KP_NONCE, @Nonce, SizeOf(Nonce));
end;

class function TStreamCipherInstance.GetInstance(var Inst: PStreamCipherInstance;
                 Alg: ICipher): TF_RESULT;
var
  BlockSize: Cardinal;
  Tmp: PStreamCipherInstance;

begin
  BlockSize:= Alg.GetBlockSize;
  if (BlockSize = 0) or (BlockSize > TF_MAX_CIPHER_BLOCK_SIZE) then begin
    Result:= TF_E_UNEXPECTED;
    Exit;
  end;
  try
    Tmp:= AllocMem(SizeOf(TStreamCipherInstance) + BlockSize);
    Tmp^.FVTable:= @VTable;
    Tmp^.FRefCount:= 1;
    Tmp^.FCipher:= Alg;
    Tmp^.FBlockSize:= BlockSize;
//    Result^.FPos:= 0;
    tfFreeInstance(Inst);   // if Inst <> nil then TKeyStreamInstance.Release(Inst);
    Inst:= Tmp;
    Result:= TF_S_OK;
  except
    Result:= TF_E_OUTOFMEMORY;
  end;
end;

(*
class function TKeyStreamEngine.NewInstance(Alg: ICipherAlgorithm;
  BlockSize: Cardinal): PKeyStreamEngine;
begin
  Result:= AllocMem(SizeOf(TKeyStreamEngine) + BlockSize);
  Result^.FVTable:= @EngVTable;
  Result^.FRefCount:= 1;
  Result^.FCipher:= Alg;
  Result^.FBlockSize:= BlockSize;
//  Result^.FPos:= 0;
end;

*)
(*
class function TKeyStreamEngine.Read(Inst: PKeyStreamEngine; Data: PByte;
  DataSize: Cardinal): TF_RESULT;
var
  LBlockSize: Cardinal;
  LDataSize: Cardinal;
  LPos: Cardinal;
  LBlockNo: UInt64;

begin
// check arguments
  LBlockSize:= Inst.FBlockSize;
  LBlockNo:= Inst.FBlockNo + DataSize div LBlockSize + 1;
  if LBlockNo < Inst.FBlockNo then begin
    Result:= TF_E_INVALIDARG;
    Exit;
  end;

// read current block's tail
  if Inst.FPos > 0 then begin
    LDataSize:= Inst.FBlockSize - Inst.FPos;
    if LDataSize > DataSize
      then LDataSize:= DataSize;
    LPos:= Inst.FPos + LDataSize;

    if LPos = Inst.FBlockSize then begin
      LPos:= 0;
      LBlockNo:= Inst.FBlockNo + 1;
      if LBlockNo = 0 then begin
        Result:= TF_E_INVALIDARG;
        Exit;
      end;
    end;

    Move(PByte(@Inst.FBlock)[Inst.FPos], Data^, LDataSize);
    Inst.FPos:= LPos;
    Inst.FBlockNo:= LBlockNo;

    if LDataSize = DataSize then begin
      Result:= TF_S_OK;
      Exit;
    end;
    Inc(Data, LDataSize);
    Dec(DataSize, LDataSize);
  end;

// read full blocks
  if DataSize >= Inst.FBlockSize then begin
    LDataSize:= DataSize and not (Inst.FBlockSize - 1);
    Result:= Inst.FCipher.GetKeyStream(Data, LDataSize);
    if Result <> TF_S_OK then Exit;
    Inc(Data, LDataSize);
    Dec(DataSize, LDataSize);
//    Inst.FBlockNo:= Inst.FBlockNo + LDataSize div Inst.FBlockSize;
  end;
  if DataSize > 0 then begin
    Result:= Inst.FCipher.GetKeyStream(@Inst.FBlock, Inst.FBlockSize);
    if Result <> TF_S_OK then Exit;
    Move(PByte(@Inst.FBlock)^, Data^, DataSize);
    Inst.FPos:= DataSize;
//    Inst.FBlockNo:= Inst.FBlockNo + 1;
  end;
end;
*)


class function TStreamCipherInstance.Read(Inst: PStreamCipherInstance; Data: PByte;
  DataSize: Cardinal): TF_RESULT;
var
  LDataSize: Cardinal;
  NBlocks: Cardinal;

begin
// read current block's tail
  if Inst.FPos > 0 then begin
    NBlocks:= 1;
    Result:= Inst.FCipher.SetKeyParam(TF_KP_DECNO, @NBlocks, SizeOf(NBlocks));
    if Result <> TF_S_OK then Exit;
    Result:= Inst.FCipher.GetKeyStream(@Inst.FBlock, Inst.FBlockSize);
    if Result <> TF_S_OK then Exit;

    LDataSize:= Inst.FBlockSize - Inst.FPos;
    if LDataSize > DataSize
      then LDataSize:= DataSize;
    Move(PByte(@Inst.FBlock)[Inst.FPos], Data^, LDataSize);
    Inst.FPos:= Inst.FPos + LDataSize;
    if Inst.FPos = Inst.FBlockSize then Inst.FPos:= 0;
    if LDataSize = DataSize then begin
      Result:= TF_S_OK;
      Exit;
    end;
    Inc(Data, LDataSize);
    Dec(DataSize, LDataSize);
  end;

// read full blocks
  if DataSize >= Inst.FBlockSize then begin
    LDataSize:= DataSize and not (Inst.FBlockSize - 1);
    Result:= Inst.FCipher.GetKeyStream(Data, LDataSize);
    if Result <> TF_S_OK then Exit;
    Inc(Data, LDataSize);
    Dec(DataSize, LDataSize);
  end;

// read last incomplete block
  if DataSize > 0 then begin
    Result:= Inst.FCipher.GetKeyStream(@Inst.FBlock, Inst.FBlockSize);
    if Result <> TF_S_OK then Exit;
    Move(PByte(@Inst.FBlock)^, Data^, DataSize);
    Inst.FPos:= DataSize;
  end;

  Result:= TF_S_OK;
end;

class function TStreamCipherInstance.Crypt(Inst: PStreamCipherInstance; Data: PByte;
  DataSize: Cardinal): TF_RESULT;
var
  LDataSize: Cardinal;
  NBlocks: Cardinal;

begin
// read current block's tail
  if Inst.FPos > 0 then begin
    NBlocks:= 1;
    Result:= Inst.FCipher.SetKeyParam(TF_KP_DECNO, @NBlocks, SizeOf(NBlocks));
    if Result <> TF_S_OK then Exit;
    Result:= Inst.FCipher.GetKeyStream(@Inst.FBlock, Inst.FBlockSize);
    if Result <> TF_S_OK then Exit;

    LDataSize:= Inst.FBlockSize - Inst.FPos;
    if LDataSize > DataSize
      then LDataSize:= DataSize;

    MoveXor(PByte(@Inst.FBlock)[Inst.FPos], Data^, LDataSize);
    Inst.FPos:= Inst.FPos + LDataSize;
    if Inst.FPos = Inst.FBlockSize then Inst.FPos:= 0;
    if LDataSize = DataSize then begin
      Result:= TF_S_OK;
      Exit;
    end;
    Inc(Data, LDataSize);
    Dec(DataSize, LDataSize);
  end;

// read full blocks
  if DataSize >= Inst.FBlockSize then begin
    LDataSize:= DataSize and not (Inst.FBlockSize - 1);
    Result:= Inst.FCipher.KeyCrypt(Data, LDataSize, False);
    if Result <> TF_S_OK then Exit;
    Inc(Data, LDataSize);
    Dec(DataSize, LDataSize);
  end;

// read last incomplete block
  if DataSize > 0 then begin
//    Result:= Inst.FCipher.KeyCrypt(@Inst.FBlock, Inst.FBlockSize, False);
    Result:= Inst.FCipher.GetKeyStream(@Inst.FBlock, Inst.FBlockSize);
    if Result <> TF_S_OK then Exit;
    MoveXor(PByte(@Inst.FBlock)^, Data^, DataSize);
    Inst.FPos:= DataSize;
  end;

  Result:= TF_S_OK;
end;

class function TStreamCipherInstance.Duplicate(Inst: PStreamCipherInstance;
               var NewInst: PStreamCipherInstance): TF_RESULT;
var
  CipherInst: ICipher;
  TmpInst: PStreamCipherInstance;

begin
  Result:= Inst.FCipher.Duplicate(CipherInst);
  if Result = TF_S_OK then begin
    TmpInst:= nil;
    Result:= GetInstance(TmpInst, CipherInst);
    if Result = TF_S_OK then begin
      TmpInst.FBlockSize:= Inst.FBlockSize;
      TmpInst.FPos:= Inst.FPos;
      Move(Inst.FBlock, TmpInst.FBlock, Inst.FBlockSize);
      tfFreeInstance(NewInst);
      NewInst:= TmpInst;
    end
    else
      CipherInst:= nil;
  end;
end;

class function TStreamCipherInstance.SetNonce(Inst: PStreamCipherInstance;
  Nonce: UInt64): TF_RESULT;
begin
  Result:= Inst.FCipher.SetKeyParam(TF_KP_NONCE, @Nonce, SizeOf(Nonce));
end;

class function TStreamCipherInstance.GetNonce(Inst: PStreamCipherInstance;
  var Nonce: UInt64): TF_RESULT;
var
  L: Cardinal;

begin
  L:= SizeOf(Nonce);
  Result:= Inst.FCipher.GetKeyParam(TF_KP_NONCE, @Nonce, L);
end;

class function TStreamCipherInstance.Skip(Inst: PStreamCipherInstance; Dist: Int64): TF_RESULT;
var
  NBlocks: UInt64;
  NBytes: Cardinal;
  Tail: Cardinal;
  ZeroIn, ZeroOut: Boolean;

begin
  if Dist >= 0 then begin
    Tail:= Inst.FBlockSize - Inst.FPos;
    NBlocks:= UInt64(Dist) div Inst.FBlockSize;
    NBytes:= UInt64(Dist) mod Inst.FBlockSize;
    ZeroIn:= Inst.FPos = 0;
    Inc(Inst.FPos, NBytes);
    if Inst.FPos >= Inst.FBlockSize then begin
      Inc(NBlocks);
      Dec(Inst.FPos, Inst.FBlockSize);
    end;
    ZeroOut:= Inst.FPos = 0;
    if ZeroIn <> ZeroOut then begin
      if ZeroIn then Inc(NBlocks)
      else Dec(NBlocks);
    end;
    if NBlocks = 0 then Result:= TF_S_OK
    else
      Result:= Inst.FCipher.SetKeyParam(TF_KP_INCNO, @NBlocks, SizeOf(NBlocks));
  end
  else begin
    Dist:= -Dist;
    NBlocks:= UInt64(Dist) div Inst.FBlockSize;
    NBytes:= UInt64(Dist) mod Inst.FBlockSize;
    ZeroIn:= Inst.FPos = 0;
    if NBytes > Inst.FPos then begin
      Inc(NBlocks);
      Inst.FPos:= Inst.FPos + Inst.FBlockSize;
    end;
    Dec(Inst.FPos, NBytes);
    ZeroOut:= Inst.FPos = 0;
    if ZeroIn <> ZeroOut then begin
      if ZeroIn then Dec(NBlocks)
      else Inc(NBlocks);
    end;
    if NBlocks = 0 then Result:= TF_S_OK
    else
      Result:= Inst.FCipher.SetKeyParam(TF_KP_DECNO, @NBlocks, SizeOf(NBlocks));
  end;
end;

end.
