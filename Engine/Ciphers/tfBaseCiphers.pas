{ *********************************************************** }
{ *                     TForge Library                      * }
{ *       Copyright (c) Sergey Kasandrov 1997, 2016         * }
{ *********************************************************** }

{ NB: it is OK to pass a zero-length last block to encryption routine,
      but it is not Ok to pass it to decryption roitine if padding is used
}

unit tfBaseCiphers;

interface

{$I TFL.inc}

uses
  tfLimbs, tfTypes, tfUtils;

type
  PBaseBlockCipher = ^TBaseBlockCipher;
  TBaseBlockCipher = record
  private type
    TBlock = array[0..TF_MAX_CIPHER_BLOCK_SIZE - 1] of Byte;
  private
{$HINTS OFF}
    FVTable:   Pointer;
    FRefCount: Integer;

    FValidKey: Boolean;
{$HINTS ON}
    FDir:      UInt32;
    FMode:     UInt32;
    FPadding:  UInt32;

    FIVector:  TBlock;                // var len = block size


    function SetIV(Data: Pointer; DataLen: Cardinal): TF_RESULT;
    function SetNonce(Data: PByte; DataLen: Cardinal): TF_RESULT;
    function SetDir(Data: UInt32): TF_RESULT;
    function SetMode(Data: UInt32): TF_RESULT;
    function SetPadding(Data: UInt32): TF_RESULT;
    function SetFlags(Data: UInt32): TF_RESULT;
    function IncBlockNo(Data: Pointer; DataLen: Cardinal): TF_RESULT;
    function DecBlockNo(Data: Pointer; DataLen: Cardinal): TF_RESULT;

    function EncryptECB(Data: PByte; var DataSize: Cardinal;
             BufSize: Cardinal; Last: Boolean): TF_RESULT;
    function EncryptCBC(Data: PByte; var DataSize: Cardinal;
             BufSize: Cardinal; Last: Boolean): TF_RESULT;
    function EncryptCTR(Data: PByte; var DataSize: Cardinal;
             BufSize: Cardinal; Last: Boolean): TF_RESULT;
    function DecryptECB(Data: PByte; var DataSize: Cardinal;
             Last: Boolean): TF_RESULT;
    function DecryptCBC(Data: PByte; var DataSize: Cardinal;
             Last: Boolean): TF_RESULT;
    function DecryptCTR(Data: PByte; var DataSize: Cardinal;
             Last: Boolean): TF_RESULT;
  public
    class function SetKeyParam(Inst: Pointer; Param: UInt32; Data: Pointer;
      DataLen: Cardinal): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function GetKeyParam(Inst: PBaseBlockCipher; Param: UInt32; Data: Pointer;
      var DataLen: Cardinal): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function Encrypt(Inst: Pointer; Data: PByte; var DataSize: Cardinal;
      BufSize: Cardinal; Last: Boolean): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function Decrypt(Inst: Pointer; Data: PByte; var DataSize: Cardinal;
      Last: Boolean): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function GetRand(Inst: Pointer; Data: PByte; DataSize: Cardinal): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function RandBlock(Inst: Pointer; Data: PByte): TF_RESULT;
          {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function RandCrypt(Inst: Pointer; Data: PByte; DataSize: Cardinal;
      Last: Boolean): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function GetIsBlockCipher(Inst: Pointer): Boolean;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
  end;

type
  PBaseStreamCipher = ^TBaseStreamCipher;
  TBaseStreamCipher = record
  private
{$HINTS OFF}
    FVTable:   Pointer;
    FRefCount: Integer;

    FValidKey: Boolean;
{$HINTS ON}

  public
    class function SetKeyParam(Inst: Pointer; Param: UInt32; Data: Pointer;
          DataLen: Cardinal): TF_RESULT;
         {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function GetKeyParam(Inst: Pointer; Param: UInt32; Data: Pointer;
      var DataLen: Cardinal): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function Encrypt(Inst: Pointer; Data: PByte; var DataSize: Cardinal;
      BufSize: Cardinal; Last: Boolean): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function Decrypt(Inst: Pointer; Data: PByte; var DataSize: Cardinal;
      Last: Boolean): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function GetRand(Inst: Pointer; Data: PByte; DataSize: Cardinal): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function RandCrypt(Inst: Pointer; Data: PByte; DataSize: Cardinal;
      Last: Boolean): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
// this method is not really needed for stream ciphers,
//   but it can be reasonably implemented
//   and VTable entries for EncryptBlock/DecryptBlock should be filled anyway
    class function EncryptBlock(Inst: Pointer; Data: PByte): TF_RESULT;
          {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;

    class function GetIsBlockCipher(Inst: Pointer): Boolean;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
  end;

implementation

{ TBlockCipher }

type
  TVTable = array[0..15] of Pointer;
  PVTable = ^TVTable;
  PPVTable = ^PVTable;

  TBlockFunc = function(Inst: Pointer; Data: PByte): TF_RESULT;
                 {$IFDEF TFL_STDCALL}stdcall;{$ENDIF}

  TGetBlockSizeFunc = function(Inst: PBaseBlockCipher): Integer;
                 {$IFDEF TFL_STDCALL}stdcall;{$ENDIF}

  TGetRandFunc = function(Inst: PBaseStreamCipher;
      Data: PByte; DataSize: Cardinal): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF}

function GetEncryptFunc(Inst: Pointer): Pointer; inline;
begin
  Result:= PPVTable(Inst)^^[11];     // 11 is 'EncryptBlock' index
end;

function GetDecryptFunc(Inst: Pointer): Pointer; inline;
begin
  Result:= PPVTable(Inst)^^[12];    // 12 is 'DecryptBlock' index
end;

function GetRandFunc(Inst: Pointer): Pointer; inline;
begin
  Result:= PPVTable(Inst)^^[13];    // 13 is 'GetKeyStream' index
end;

function GetRandBlockFunc(Inst: Pointer): Pointer; inline;
begin
  Result:= PPVTable(Inst)^^[14];    // 14 is 'KeyBlock' index
end;

function GetBlockSize(Inst: Pointer): Integer; inline;
begin
  Result:= TGetBlockSizeFunc(PPVTable(Inst)^^[8])(Inst);
end;

procedure XorBytes(Target: Pointer; Value: Pointer; Count: Integer);
var
  LCount: Integer;

begin
  LCount:= Count shr 2;
  while LCount > 0 do begin
    PUInt32(Target)^:= PUInt32(Target)^ xor PUInt32(Value)^;
    Inc(PUInt32(Target));
    Inc(PUInt32(Value));
    Dec(LCount);
  end;
  LCount:= Count and 3;
  while LCount > 0 do begin
    PByte(Target)^:= PByte(Target)^ xor PByte(Value)^;
    Inc(PByte(Target));
    Inc(PByte(Value));
    Dec(LCount);
  end;
end;

class function TBaseBlockCipher.Encrypt(Inst: Pointer; Data: PByte;
  var DataSize: Cardinal; BufSize: Cardinal; Last: Boolean): TF_RESULT;
begin
  if (PBaseBlockCipher(Inst).FDir = TF_KEYDIR_ENCRYPT) and
      PBaseBlockCipher(Inst).FValidKey then begin
    case PBaseBlockCipher(Inst).FMode of
      TF_KEYMODE_ECB: Result:= PBaseBlockCipher(Inst).EncryptECB(Data, DataSize, BufSize, Last);
      TF_KEYMODE_CBC: Result:= PBaseBlockCipher(Inst).EncryptCBC(Data, DataSize, BufSize, Last);
      TF_KEYMODE_CTR: Result:= PBaseBlockCipher(Inst).EncryptCTR(Data, DataSize, BufSize, Last);
    else
      Result:= TF_E_UNEXPECTED;
    end;
  end
  else
    Result:= TF_E_UNEXPECTED;
end;

class function TBaseBlockCipher.Decrypt(Inst: Pointer; Data: PByte;
  var DataSize: Cardinal; Last: Boolean): TF_RESULT;
begin
  if (PBaseBlockCipher(Inst).FDir = TF_KEYDIR_DECRYPT) and
      PBaseBlockCipher(Inst).FValidKey then begin
    case PBaseBlockCipher(Inst).FMode of
      TF_KEYMODE_ECB: Result:= PBaseBlockCipher(Inst).DecryptECB(Data, DataSize, Last);
      TF_KEYMODE_CBC: Result:= PBaseBlockCipher(Inst).DecryptCBC(Data, DataSize, Last);
      TF_KEYMODE_CTR: Result:= PBaseBlockCipher(Inst).DecryptCTR(Data, DataSize, Last);
    else
      Result:= TF_E_UNEXPECTED;
    end;
  end
  else
    Result:= TF_E_UNEXPECTED;
end;

class function TBaseBlockCipher.RandCrypt(Inst: Pointer; Data: PByte;
               DataSize: Cardinal; Last: Boolean): TF_RESULT;
begin
  if PBaseBlockCipher(Inst).FValidKey
    and (PBaseBlockCipher(Inst).FMode = TF_KEYMODE_CTR)
    and ((PBaseBlockCipher(Inst).FPadding = TF_PADDING_NONE)
      or (PBaseBlockCipher(Inst).FPadding = TF_PADDING_DEFAULT))
    then
      Result:= PBaseBlockCipher(Inst).DecryptCTR(Data, DataSize, Last)
    else
      Result:= TF_E_UNEXPECTED;
end;

function TBaseBlockCipher.EncryptECB(Data: PByte; var DataSize: Cardinal;
                      BufSize: Cardinal; Last: Boolean): TF_RESULT;
var
  EncryptBlock: TBlockFunc;
  RequiredSize: Cardinal;
  LDataSize: Cardinal;
  LPadding: UInt32;
  LBlockSize: Cardinal;
  Cnt: Cardinal;

begin
  @EncryptBlock:= GetEncryptFunc(@Self);
  LDataSize:= DataSize;
  LPadding:= FPadding;
  LBlockSize:= GetBlockSize(@Self);
  if LPadding = TF_PADDING_DEFAULT
    then LPadding:= TF_PADDING_PKCS;

// check arguments
  if Last then begin
    case LPadding of
      TF_PADDING_NONE: begin
        if LDataSize and (LBlockSize - 1) <> 0 then begin
          Result:= TF_E_INVALIDARG;
          Exit;
        end;
        RequiredSize:= LDataSize;
      end;
      TF_PADDING_ZERO: RequiredSize:= (LDataSize + LBlockSize - 1) and not (LBlockSize - 1);
      TF_PADDING_ANSI,
      TF_PADDING_PKCS,
      TF_PADDING_ISO10126,
      TF_PADDING_ISOIEC: RequiredSize:= (LDataSize + LBlockSize) and not (LBlockSize - 1);
    else
      Result:= TF_E_UNEXPECTED;
      Exit;
    end;
  end
  else begin
    if LDataSize and (LBlockSize - 1) <> 0 then begin
      Result:= TF_E_INVALIDARG;
      Exit;
    end;
    RequiredSize:= LDataSize;
  end;
  DataSize:= RequiredSize;
  if (Data = nil) or (BufSize < RequiredSize) then begin
    Result:= TF_E_INVALIDARG;
    Exit;
  end;

// encrypt
  while LDataSize >= LBlockSize do begin
    EncryptBlock(@Self, Data);
    Inc(Data, LBlockSize);
    Dec(LDataSize, LBlockSize);
  end;
  if Last then begin
    Cnt:= LBlockSize - LDataSize;    // 0 < Cnt <= LBlockSize
    Inc(Data, LDataSize);
    case LPadding of
                                            // XX 00 00 00 00
      TF_PADDING_ZERO: if LDataSize > 0 then begin
        FillChar(Data^, Cnt, 0);
        Dec(Data, LDataSize);
        EncryptBlock(@Self, Data);
      end;
                                            // XX 00 00 00 04
      TF_PADDING_ANSI: begin
        FillChar(Data^, Cnt - 1, 0);
        Inc(Data, Cnt - 1);
        Data^:= Byte(Cnt);
        Dec(Data, LBlockSize - 1);
        EncryptBlock(@Self, Data);
      end;
                                            // XX 04 04 04 04
      TF_PADDING_PKCS,
      TF_PADDING_ISO10126: begin
        FillChar(Data^, Cnt, Byte(Cnt));
        Dec(Data, LDataSize);
        EncryptBlock(@Self, Data);
      end;
                                            // XX 80 00 00 00
      TF_PADDING_ISOIEC: begin
        Data^:= $80;
        Inc(Data);
        FillChar(Data^, Cnt - 1, 0);
        Dec(Data, LDataSize + 1);
        EncryptBlock(@Self, Data);
      end;
    end;
  end;
  Result:= TF_S_OK;
end;

class function TBaseBlockCipher.GetIsBlockCipher(Inst: Pointer): Boolean;
begin
  Result:= True;
end;

class function TBaseBlockCipher.GetKeyParam(Inst: PBaseBlockCipher; Param: UInt32;
  Data: Pointer; var DataLen: Cardinal): TF_RESULT;
var
  LBlocksize: Cardinal;
  P: PByte;

begin
  if Param = TF_KP_IV then begin
    Result:= TF_E_NOTIMPL; // PBlockCipher(Inst).SetIV(Data, DataLen);
  end
  else if Param = TF_KP_NONCE then begin
    if DataLen < SizeOf(UInt64) then Result:= TF_E_INVALIDARG
    else begin
      LBlockSize:= GetBlockSize(Inst);
      if (LBlockSize = 0) or (LBlockSize > TF_MAX_CIPHER_BLOCK_SIZE) then begin
        Result:= TF_E_UNEXPECTED;
        Exit;
      end;
      if LBlockSize < 16 then begin
        Result:= TF_E_NOTIMPL;
        Exit;
      end;
      P:= @Inst.FIVector;
      while LBlockSize > 16 do begin
        if P^ <> 0 then begin
          Result:= TF_E_UNEXPECTED;
          Exit;
        end;
        Inc(P);
        Dec(LBlockSize);
      end;
      Move(P^, Data^, SizeOf(UInt64));
      DataLen:= SizeOf(UInt64);
      Result:= TF_S_OK;
    end;
  end
  else begin
    if DataLen = SizeOf(UInt32) then begin
//      LData:= PUInt32(Data)^;
      Result:= TF_S_OK;
      case Param of
        TF_KP_DIR: PUInt32(Data)^:= Inst.FDir;
        TF_KP_MODE: PUInt32(Data)^:= Inst.FMode;
        TF_KP_PADDING: PUInt32(Data)^:= Inst.FPadding;
//        TF_KP_FLAGS: Result:= TF_E_NOTIMPL; // PBlockCipher(Inst).SetFlags(LData);
      else
        Result:= TF_E_INVALIDARG;
      end;
    end
    else
      Result:= TF_E_INVALIDARG;
  end;
end;

class function TBaseBlockCipher.GetRand(Inst: Pointer; Data: PByte;
  DataSize: Cardinal): TF_RESULT;

var
  EncryptBlock: TBlockFunc;
  Block: TBlock;
  LBlockSize, LL{, Cnt}: Cardinal;

begin
  @EncryptBlock:= GetEncryptFunc(Inst);
  LBlockSize:= GetBlockSize(Inst);
  if LBlockSize > SizeOf(Block) then begin
    Result:= TF_E_UNEXPECTED;
    Exit;
  end;
  while DataSize > 0 do begin
    LL:= LBlockSize;
    if LL > DataSize then begin
      LL:= DataSize;
      if Data <> nil then begin
        Move(PBaseBlockCipher(Inst).FIVector, Block, LBlockSize);
        EncryptBlock(Inst, @Block);
        Move(Block, Data^, LL);
        FillChar(Block, LBlockSize, 0);
      end;
    end
    else begin
      if Data <> nil then begin
        Move(PBaseBlockCipher(Inst).FIVector, Data^, LBlockSize);
        EncryptBlock(Inst, Data);
      end;
    end;

// Inc IV
    TBigEndian.Incr(@PBaseBlockCipher(Inst).FIVector,
                    PByte(@PBaseBlockCipher(Inst).FIVector) + LBlockSize);
{
    Cnt:= LBlockSize - 1;
    Inc(PBlockCipher(Inst).FIVector[Cnt]);
    if PBlockCipher(Inst).FIVector[Cnt] = 0 then begin
      repeat
        Dec(Cnt);
        Inc(PBlockCipher(Inst).FIVector[Cnt]);
      until (PBlockCipher(Inst).FIVector[Cnt] <> 0) or (Cnt = 0);
    end;
}
    if Data <> nil then Inc(Data, LL);
    Dec(DataSize, LL);
  end;
  Result:= TF_S_OK;
end;

class function TBaseBlockCipher.RandBlock(Inst: Pointer; Data: PByte): TF_RESULT;
var
  EncryptBlock: TBlockFunc;
  LBlockSize: Cardinal;

begin
  @EncryptBlock:= GetEncryptFunc(Inst);
  LBlockSize:= GetBlockSize(Inst);
  if (LBlockSize = 0) or (LBlockSize > TF_MAX_CIPHER_BLOCK_SIZE) then begin
    Result:= TF_E_UNEXPECTED;
    Exit;
  end;
  Move(PBaseBlockCipher(Inst).FIVector, Data^, LBlockSize);
  EncryptBlock(Inst, Data);

// Inc IV
  TBigEndian.Incr(@PBaseBlockCipher(Inst).FIVector,
                  PByte(@PBaseBlockCipher(Inst).FIVector) + LBlockSize);
  Result:= TF_S_OK;
end;

function TBaseBlockCipher.SetIV(Data: Pointer; DataLen: Cardinal): TF_RESULT;
begin
  if (Data = nil) then begin
    FillChar(FIVector, GetBlockSize(@Self), 0);
    Result:= TF_S_OK;
  end
  else if (DataLen = Cardinal(GetBlockSize(@Self))) then begin
    Move(Data^, FIVector, DataLen);
    Result:= TF_S_OK;
  end
  else
    Result:= TF_E_INVALIDARG;
end;

function TBaseBlockCipher.SetNonce(Data: PByte; DataLen: Cardinal): TF_RESULT;
var
  LBlockSize: Cardinal;
  Output: PByte;
  Nonce: UInt64;

begin
  if (Data <> nil) then begin
    LBlockSize:= GetBlockSize(@Self);
    if (LBlockSize = 0) or (LBlockSize > TF_MAX_CIPHER_BLOCK_SIZE) then begin
      Result:= TF_E_UNEXPECTED;
      Exit;
    end;

// IV is considered consisting of 2 parts: Nonce and BlockNo;
//   if BlockSize >= 16 (128 bits),
//     when both Nonce and BlockNo are of 8 bytes (64 bits).
//   if BlockSize < 16 (128 bits),
//     when whole IV is BlockNo, and the only valid nonce value is zero.
//   if BlockSize > 16 (128 bits),
//     when leftmost L - 16 bytes of IV are zeroed.
//   BlockNo bytes of IV are zeroed.

    if {(DataLen = 0) or} (DataLen > SizeOf(Nonce)) then begin
      Result:= TF_E_INVALIDARG;
      Exit;
    end;

    Nonce:= 0;
    Move(Data^, Nonce, DataLen);

    if (LBlockSize < 16) and (Nonce <> 0) then begin
      Result:= TF_E_INVALIDARG;
      Exit;
    end;

    FillChar(FIVector, LBlockSize, 0);

    if (LBlockSize >= 16) then begin
      Output:= @FIVector;
      Inc(Output, LBlockSize - 16);
      Move(Nonce, Output^, SizeOf(Nonce));
    end;
// if L < 16 and nonce is zero, just return success
    Result:= TF_S_OK;
  end
  else
    Result:= TF_E_INVALIDARG;
end;

function TBaseBlockCipher.SetDir(Data: UInt32): TF_RESULT;
begin
  if (Data = TF_KEYDIR_ENCRYPT) or (Data = TF_KEYDIR_DECRYPT) then begin
    FDir:= Data;
    Result:= TF_S_OK;
  end
  else
    Result:= TF_E_INVALIDARG;
end;

function TBaseBlockCipher.SetMode(Data: UInt32): TF_RESULT;
begin
  if (Data >= TF_KEYMODE_MIN) and (Data <= TF_KEYMODE_MAX) then begin
    FMode:= Data;
    Result:= TF_S_OK;
  end
  else
    Result:= TF_E_INVALIDARG;
end;

function TBaseBlockCipher.SetPadding(Data: UInt32): TF_RESULT;
begin
  if (Data >= TF_PADDING_MIN) and (Data <= TF_PADDING_MAX) then begin
    FPadding:= Data;
    Result:= TF_S_OK;
  end
  else
    Result:= TF_E_INVALIDARG;
end;

(*
function TBlockCipher.IncBlockNo(Data: Pointer; DataLen: Cardinal{; LE: Boolean}): TF_RESULT;
var
  L: LongWord;
  LData: UInt64;
  BlockNoPtr: PByte;

begin
  L:= GetBlockSize(@Self);
  if (L = 0) or (L > SizeOf(TBlock)) then begin
    Result:= TF_E_UNEXPECTED;
    Exit;
  end;
  if (DataLen > SizeOf(LData)) or (DataLen > L) then begin
    Result:= TF_E_INVALIDARG;
    Exit;
  end;

  BlockNoPtr:= @FIVector;
// if block size > 8 bytes, the rightmost 8 bytes of IV are used as block number
  if L > SizeOf(LData) then begin
    Inc(BlockNoPtr, L - SizeOf(LData));
    L:= SizeOf(LData);
  end;

  LData:= 0;
// since IV is big-endian, little-endian data is reversed
  TBigEndian.ReverseCopy(Data, PByte(Data) + DataLen, @LData);

  TBigEndian.Add(BlockNoPtr, L, @LData, DataLen);

  Result:= TF_S_OK;
end;

function TBlockCipher.DecBlockNo(Data: Pointer; DataLen: Cardinal): TF_RESULT;
var
  L: LongWord;
  LData: UInt64;
  BlockNoPtr: PByte;

begin
  L:= GetBlockSize(@Self);
  if (L = 0) or (L > SizeOf(TBlock)) then begin
    Result:= TF_E_UNEXPECTED;
    Exit;
  end;

  if (DataLen > SizeOf(LData)) or (DataLen > L) then begin
    Result:= TF_E_INVALIDARG;
    Exit;
  end;

  BlockNoPtr:= @FIVector;
// if block size > 8 bytes, the rightmost 8 bytes of IV are used as block number
  if L > SizeOf(LData) then begin
    Inc(BlockNoPtr, L - SizeOf(LData));
    L:= SizeOf(LData);
  end;

  LData:= 0;
// since IV is big-endian, little-endian data is reversed
  TBigEndian.ReverseCopy(Data, PByte(Data) + DataLen, @LData);

  TBigEndian.Sub(BlockNoPtr, L, @LData, DataLen);

  Result:= TF_S_OK;
end;

*)

function TBaseBlockCipher.IncBlockNo(Data: Pointer; DataLen: Cardinal{; LE: Boolean}): TF_RESULT;
var
  LBlockSize: Cardinal;
  LData: UInt64;

begin
  LBlockSize:= GetBlockSize(@Self);
  if (LBlockSize = 0) or (LBlockSize > SizeOf(TBlock)) then begin
    Result:= TF_E_UNEXPECTED;
    Exit;
  end;
  if (DataLen > SizeOf(LData)) or (DataLen > LBlockSize) then begin
    Result:= TF_E_INVALIDARG;
    Exit;
  end;

  LData:= 0;
// since IV is big-endian, little-endian data is reversed
  TBigEndian.ReverseCopy(Data, PByte(Data) + DataLen, @LData);

  TBigEndian.Add(@FIVector, LBlockSize, @LData, DataLen);

  Result:= TF_S_OK;
end;


function TBaseBlockCipher.DecBlockNo(Data: Pointer; DataLen: Cardinal): TF_RESULT;
var
  LBlockSize: Cardinal;
  LData: UInt64;

begin
  LBlockSize:= GetBlockSize(@Self);
  if (LBlockSize = 0) or (LBlockSize > SizeOf(TBlock)) then begin
    Result:= TF_E_UNEXPECTED;
    Exit;
  end;
  if (DataLen > SizeOf(LData)) or (DataLen > LBlockSize) then begin
    Result:= TF_E_INVALIDARG;
    Exit;
  end;

  LData:= 0;
// since IV is big-endian, little-endian data is reversed
  TBigEndian.ReverseCopy(Data, PByte(Data) + DataLen, @LData);

  TBigEndian.Sub(@FIVector, LBlockSize, @LData, DataLen);

  Result:= TF_S_OK;
end;

function TBaseBlockCipher.SetFlags(Data: UInt32): TF_RESULT;
begin
  Result:= TF_S_FALSE;
{
  if Data and TF_KEYDIR_BASE <> 0 then
    Result:= SetDir(Data and TF_KEYDIR_MASK);

  if (Result >= 0) and (Data and TF_KEYMODE_BASE <> 0) then
    Result:= SetMode(Data and TF_KEYMODE_MASK);

  if (Result >= 0) and (Data and TF_PADDING_BASE <> 0) then
    Result:= SetPadding(Data and TF_PADDING_MASK);
}
  if Data and TF_KEYDIR_MASK <> 0 then
    Result:= SetDir(Data and TF_KEYDIR_MASK);

  if (Result >= 0) and (Data and TF_KEYMODE_MASK <> 0) then
    Result:= SetMode(Data and TF_KEYMODE_MASK);

  if (Result >= 0) and (Data and TF_PADDING_MASK <> 0) then
    Result:= SetPadding(Data and TF_PADDING_MASK);

end;

class function TBaseBlockCipher.SetKeyParam(Inst: Pointer; Param: UInt32;
               Data: Pointer; DataLen: Cardinal): TF_RESULT;
var
  LData: Cardinal;

begin
  if Param = TF_KP_IV then begin
    Result:= PBaseBlockCipher(Inst).SetIV(Data, DataLen);
  end
  else if Param = TF_KP_NONCE then begin
    Result:= PBaseBlockCipher(Inst).SetNonce(Data, DataLen);
  end
  else if Param {and not TF_KP_LE} = TF_KP_INCNO then begin

//    if Param and TF_KP_LE <> 0 then             // convert to big endian
//      TBigEndian.Reverse(Data, Data + Datalen);

    Result:= PBaseBlockCipher(Inst).IncBlockNo(Data, DataLen{, Param and TF_KP_LE <> 0});
  end
  else if Param = TF_KP_DECNO then begin
    Result:= PBaseBlockCipher(Inst).DecBlockNo(Data, DataLen);
  end
  else begin
    if DataLen = SizeOf(UInt32) then begin
      LData:= PUInt32(Data)^;
      case Param of
        TF_KP_DIR: Result:= PBaseBlockCipher(Inst).SetDir(LData);
        TF_KP_MODE: Result:= PBaseBlockCipher(Inst).SetMode(LData);
        TF_KP_PADDING: Result:= PBaseBlockCipher(Inst).SetPadding(LData);
        TF_KP_FLAGS: Result:= PBaseBlockCipher(Inst).SetFlags(LData);
      else
        Result:= TF_E_INVALIDARG;
      end;
    end
    else
      Result:= TF_E_INVALIDARG;

// setting flags invalidates key
    PBaseBlockCipher(Inst).FValidKey:= False;
  end;
end;

function TBaseBlockCipher.EncryptCBC(Data: PByte; var DataSize: Cardinal;
                      BufSize: Cardinal; Last: Boolean): TF_RESULT;
var
  EncryptBlock: TBlockFunc;
  RequiredSize: Cardinal;
  LDataSize: Cardinal;
  LPadding: UInt32;
  LBlockSize: Cardinal;
  Cnt: Cardinal;

begin
  @EncryptBlock:= GetEncryptFunc(@Self);
  LDataSize:= DataSize;
  LPadding:= FPadding;
  LBlockSize:= GetBlockSize(@Self);
  if LPadding = TF_PADDING_DEFAULT
    then LPadding:= TF_PADDING_PKCS;

// check arguments
  if Last then begin
    case LPadding of
      TF_PADDING_NONE: begin
        if LDataSize and (LBlockSize - 1) <> 0 then begin
          Result:= TF_E_INVALIDARG;
          Exit;
        end;
        RequiredSize:= LDataSize;
      end;
      TF_PADDING_ZERO: RequiredSize:= (LDataSize + LBlockSize - 1) and not (LBlockSize - 1);
      TF_PADDING_ANSI,
      TF_PADDING_PKCS,
      TF_PADDING_ISO10126,
      TF_PADDING_ISOIEC: RequiredSize:= (LDataSize + LBlockSize) and not (LBlockSize - 1);
    else
      Result:= TF_E_UNEXPECTED;
      Exit;
    end;
  end
  else begin
    if LDataSize and (LBlockSize - 1) <> 0 then begin
      Result:= TF_E_INVALIDARG;
      Exit;
    end;
    RequiredSize:= LDataSize;
  end;
  DataSize:= RequiredSize;
  if BufSize < RequiredSize then begin
    Result:= TF_E_INVALIDARG;
    Exit;
  end;

// encrypt
  while LDataSize >= LBlockSize do begin
    XorBytes(Data, @FIVector, LBlockSize);
    EncryptBlock(@Self, Data);
    Move(Data^, FIVector, LBlockSize);
    Inc(Data, LBlockSize);
    Dec(LDataSize, LBlockSize);
  end;
  if Last then begin
    Cnt:= LBlockSize - LDataSize;    // 0 < Cnt <= BLOCK_SIZE
    Inc(Data, LDataSize);
    case LPadding of
                                            // XX 00 00 00 00
      TF_PADDING_ZERO: if LDataSize > 0 then begin
        FillChar(Data^, Cnt, 0);
        Dec(Data, LDataSize);
        XorBytes(Data, @FIVector, LBlockSize);
        EncryptBlock(@Self, Data);
      end;
                                            // XX 00 00 00 04
      TF_PADDING_ANSI: begin
        FillChar(Data^, Cnt - 1, 0);
        Inc(Data, Cnt - 1);
        Data^:= Byte(Cnt);
        Dec(Data, LBlockSize - 1);
        XorBytes(Data, @FIVector, LBlockSize);
        EncryptBlock(@Self, Data);
      end;
                                            // XX 04 04 04 04
      TF_PADDING_PKCS,
      TF_PADDING_ISO10126: begin
        FillChar(Data^, Cnt, Byte(Cnt));
        Dec(Data, LDataSize);
        XorBytes(Data, @FIVector, LBlockSize);
        EncryptBlock(@Self, Data);
      end;
                                            // XX 80 00 00 00
      TF_PADDING_ISOIEC: begin
        Data^:= $80;
        Inc(Data);
        FillChar(Data^, Cnt - 1, 0);
        Dec(Data, LDataSize + 1);
        XorBytes(Data, @FIVector, LBlockSize);
        EncryptBlock(@Self, Data);
      end;
    end;
  end;
  Result:= TF_S_OK;
end;

function TBaseBlockCipher.EncryptCTR(Data: PByte; var DataSize: Cardinal;
  BufSize: Cardinal; Last: Boolean): TF_RESULT;

var
  EncryptBlock: TBlockFunc;
  Temp: TBlock;
  RequiredSize: Cardinal;
  LDataSize: Cardinal;
  LPadding: UInt32;
  LBlockSize: Cardinal;
  Cnt: Cardinal;

begin
  @EncryptBlock:= GetEncryptFunc(@Self);
  LDataSize:= DataSize;
  LPadding:= FPadding;
  LBlockSize:= GetBlockSize(@Self);
  if LBlockSize > SizeOf(TBlock) then begin
    Result:= TF_E_UNEXPECTED;
    Exit;
  end;
  if LPadding = TF_PADDING_DEFAULT
    then LPadding:= TF_PADDING_NONE;

// check arguments
  if Last then begin
    case LPadding of
      TF_PADDING_NONE: RequiredSize:= LDataSize;
      TF_PADDING_ZERO: RequiredSize:= (LDataSize + LBlockSize - 1) and not (LBlockSize - 1);
      TF_PADDING_ANSI,
      TF_PADDING_PKCS,
      TF_PADDING_ISO10126,
      TF_PADDING_ISOIEC: RequiredSize:= (LDataSize + LBlockSize) and not (LBlockSize - 1);
    else
      Result:= TF_E_UNEXPECTED;
      Exit;
    end;
  end
  else begin
    if LDataSize and (LBlockSize - 1) <> 0 then begin
      Result:= TF_E_INVALIDARG;
      Exit;
    end;
    RequiredSize:= LDataSize;
  end;
  DataSize:= RequiredSize;
  if BufSize < RequiredSize then begin
    Result:= TF_E_INVALIDARG;
    Exit;
  end;

// encrypt
  while LDataSize >= LBlockSize do begin        // process full blocks
    Move(FIVector, Temp, LBlockSize);           // copy IV to temp block
                                                // encrypt temp block
    EncryptBlock(@Self, @Temp);
    XorBytes(Data, @Temp, LBlockSize);          // xor ciphertext with encrypted block
                                                // increment IV
    Cnt:= LBlockSize - 1;
    Inc(FIVector[Cnt]);
    if FIVector[Cnt] = 0 then begin
      repeat
        Dec(Cnt);
        Inc(FIVector[Cnt]);
      until (FIVector[Cnt] <> 0) or (Cnt = 0);
    end;
    Inc(Data, LBlockSize);                      // go to next block
    Dec(LDataSize, LBlockSize);
  end;
  if Last then begin
    if LPadding = TF_PADDING_NONE then begin
      if LDataSize > 0 then begin
        Move(FIVector, Temp, LBlockSize);       // copy IV to temp block
                                                // encrypt temp block
        EncryptBlock(@Self, @Temp);
        XorBytes(Data, @Temp, LDataSize);
        Cnt:= LBlockSize - 1;
        Inc(FIVector[Cnt]);
        if FIVector[Cnt] = 0 then begin
          repeat
            Dec(Cnt);
            Inc(FIVector[Cnt]);
          until (FIVector[Cnt] <> 0) or (Cnt = 0);
        end;
      end;
    end
    else begin
      Cnt:= LBlockSize - LDataSize;           // 0 < Cnt <= BLOCK_SIZE
      Inc(Data, LDataSize);
      case LPadding of
                                              // XX 00 00 00 00
        TF_PADDING_ZERO: if LDataSize > 0 then begin
          FillChar(Data^, Cnt, 0);
          Dec(Data, LDataSize);
          XorBytes(Data, @FIVector, LBlockSize);
          EncryptBlock(@Self, Data);
        end;
                                              // XX 00 00 00 04
        TF_PADDING_ANSI: begin
          FillChar(Data^, Cnt - 1, 0);
          Inc(Data, Cnt - 1);
          Data^:= Byte(Cnt);
          Dec(Data, LBlockSize - 1);
          XorBytes(Data, @FIVector, LBlockSize);
          EncryptBlock(@Self, Data);
        end;
                                              // XX 04 04 04 04
        TF_PADDING_PKCS,
        TF_PADDING_ISO10126 : begin
          FillChar(Data^, Cnt, Byte(Cnt));
          Dec(Data, LDataSize);
          XorBytes(Data, @FIVector, LBlockSize);
          EncryptBlock(@Self, Data);
        end;
                                              // XX 80 00 00 00
        TF_PADDING_ISOIEC: begin
          Data^:= $80;
          Inc(Data);
          FillChar(Data^, Cnt - 1, 0);
          Dec(Data, LDataSize + 1);
          XorBytes(Data, @FIVector, LBlockSize);
          EncryptBlock(@Self, Data);
        end;
      end;
    end;
  end;
  Result:= TF_S_OK;
end;

function TBaseBlockCipher.DecryptECB(Data: PByte; var DataSize: Cardinal;
                                 Last: Boolean): TF_RESULT;
var
  DecryptBlock: TBlockFunc;
  LDataSize: Cardinal;
  LPadding: UInt32;
  LBlockSize: Cardinal;
  Cnt, SaveCnt: Cardinal;

begin
  @DecryptBlock:= GetDecryptFunc(@Self);
  LDataSize:= DataSize;
  LPadding:= FPadding;
  LBlockSize:= GetBlockSize(@Self);
  if LPadding = TF_PADDING_DEFAULT
    then LPadding:= TF_PADDING_PKCS;

  if LDataSize and (LBlockSize - 1) <> 0 then begin
    Result:= TF_E_INVALIDARG;
    Exit;
  end;
  if Last and (LDataSize = 0) then begin
    case LPadding of
      TF_PADDING_ANSI,
      TF_PADDING_PKCS,
      TF_PADDING_ISO10126,
      TF_PADDING_ISOIEC: begin
        Result:= TF_E_INVALIDARG;
        Exit;
      end;
    end;
  end;
  while LDataSize >= LBlockSize do begin
    DecryptBlock(@Self, Data);
    Inc(Data, LBlockSize);
    Dec(LDataSize, LBlockSize);
  end;
  if Last then begin
    case LPadding of
                                            // XX 00 00 00 04
      TF_PADDING_ANSI: begin
        Dec(Data);
        Cnt:= Data^;
        if (Cnt > 0) and (Cnt <= LBlockSize) then begin
          SaveCnt:= Cnt - 1;
          while SaveCnt > 0 do begin
            Dec(Data);
            if Data^ <> 0 then begin
              Result:= TF_E_INVALIDARG;
              Exit;
            end;
            Dec(SaveCnt);
          end;
          DataSize:= DataSize - Cnt;
        end
        else begin
          Result:= TF_E_INVALIDARG;
          Exit;
        end;
      end;
                                            // XX 04 04 04 04
      TF_PADDING_PKCS: begin
        Dec(Data);
        Cnt:= Data^;
        if (Cnt > 0) and (Cnt <= LBlockSize) then begin
          SaveCnt:= Cnt - 1;
          while SaveCnt > 0 do begin
            Dec(Data);
            if Data^ <> Cnt then begin
              Result:= TF_E_INVALIDARG;
              Exit;
            end;
            Dec(SaveCnt);
          end;
          DataSize:= DataSize - Cnt;
        end
        else begin
          Result:= TF_E_INVALIDARG;
          Exit;
        end;
      end;
                                            // XX ?? ?? ?? 04
      TF_PADDING_ISO10126: begin
        Cnt:= (Data - 1)^;
        if (Cnt > 0) and (Cnt <= LBlockSize) then begin
          DataSize:= DataSize - Cnt;
        end
        else begin
          Result:= TF_E_INVALIDARG;
          Exit;
        end;
      end;
                                            // XX 80 00 00 00
      TF_PADDING_ISOIEC: begin
        Cnt:= LBlockSize;
        repeat
          Dec(Data);
          Dec(Cnt);
        until (Data^ <> 0) or (Cnt = 0);
        if (Data^ = $80) then
          DataSize:= DataSize - LBlockSize + Cnt
        else begin
          Result:= TF_E_INVALIDARG;
          Exit;
        end;
      end;
    end;
  end;
  Result:= TF_S_OK;
end;

function TBaseBlockCipher.DecryptCBC(Data: PByte; var DataSize: Cardinal;
                    Last: Boolean): TF_RESULT;
var
  DecryptBlock: TBlockFunc;
  Temp: TBlock;
  LDataSize: Cardinal;
  LPadding: UInt32;
  LBlockSize: Cardinal;
  Cnt, SaveCnt: Cardinal;

begin
  @DecryptBlock:= GetDecryptFunc(@Self);

  LPadding:= FPadding;
  if LPadding = TF_PADDING_DEFAULT
    then LPadding:= TF_PADDING_PKCS;

  LBlockSize:= GetBlockSize(@Self);
  if LBlockSize > SizeOf(TBlock) then begin
    Result:= TF_E_UNEXPECTED;
    Exit;
  end;

  LDataSize:= DataSize;
  if LDataSize and (LBlockSize - 1) <> 0 then begin
    Result:= TF_E_INVALIDARG;
    Exit;
  end;
  if Last and (DataSize = 0) then begin
    case LPadding of
      TF_PADDING_ANSI,
      TF_PADDING_PKCS,
      TF_PADDING_ISO10126,
      TF_PADDING_ISOIEC: begin
        Result:= TF_E_INVALIDARG;
        Exit;
      end;
    end;
  end;
  while LDataSize >= LBlockSize do begin
    Move(Data^, Temp, LBlockSize);
    DecryptBlock(@Self, Data);
    XorBytes(Data, @FIVector, LBlockSize);
    Move(Temp, FIVector, LBlockSize);
    Inc(Data, LBlockSize);
    Dec(LDataSize, LBlockSize);
  end;
  if Last then begin
    case LPadding of
                                            // XX 00 00 00 04
      TF_PADDING_ANSI: begin
        Dec(Data);
        Cnt:= Data^;
        if (Cnt > 0) and (Cnt <= LBlockSize) then begin
          SaveCnt:= Cnt - 1;
          while SaveCnt > 0 do begin
            Dec(Data);
            if Data^ <> 0 then begin
              Result:= TF_E_INVALIDARG;
              Exit;
            end;
            Dec(SaveCnt);
          end;
          DataSize:= DataSize - Cnt;
        end
        else begin
          Result:= TF_E_INVALIDARG;
          Exit;
        end;
      end;
                                              // XX 04 04 04 04
      TF_PADDING_PKCS: begin
        Dec(Data);
        Cnt:= Data^;
        if (Cnt > 0) and (Cnt <= LBlockSize) then begin
          SaveCnt:= Cnt - 1;
          while SaveCnt > 0 do begin
            Dec(Data);
            if Data^ <> Cnt then begin
              Result:= TF_E_INVALIDARG;
              Exit;
            end;
            Dec(SaveCnt);
          end;
          DataSize:= DataSize - Cnt;
        end
        else begin
          Result:= TF_E_INVALIDARG;
          Exit;
        end;
      end;
                                              // XX ?? ?? ?? 04
      TF_PADDING_ISO10126: begin
        Cnt:= (Data - 1)^;
        if (Cnt > 0) and (Cnt <= LBlockSize) then begin
          DataSize:= DataSize - Cnt;
        end
        else begin
          Result:= TF_E_INVALIDARG;
          Exit;
        end;
      end;
                                              // XX 80 00 00 00
      TF_PADDING_ISOIEC: begin
        Cnt:= LBlockSize;
        repeat
          Dec(Data);
          Dec(Cnt);
        until (Data^ <> 0) or (Cnt = 0);
        if (Data^ = $80) then
          DataSize:= DataSize - LBlockSize + Cnt
        else begin
          Result:= TF_E_INVALIDARG;
          Exit;
        end;
      end;
    end;
  end;
  Result:= TF_S_OK;
end;

function TBaseBlockCipher.DecryptCTR(Data: PByte; var DataSize: Cardinal;
                               Last: Boolean): TF_RESULT;
var
  EncryptBlock: TBlockFunc;
  Temp: TBlock;
  LDataSize: Cardinal;
  LPadding: UInt32;
  LBlockSize: Cardinal;
  Cnt, SaveCnt: Cardinal;

begin
  @EncryptBlock:= GetEncryptFunc(@Self);  // !! CTR mode uses EncryptBlock for decryption
  LDataSize:= DataSize;
  LPadding:= FPadding;
  if LPadding = TF_PADDING_DEFAULT
    then LPadding:= TF_PADDING_NONE;

  LBlockSize:= GetBlockSize(@Self);
  if LBlockSize > SizeOf(TBlock) then begin
    Result:= TF_E_UNEXPECTED;
    Exit;
  end;

  if (LDataSize and (LBlockSize - 1) <> 0) then begin
// the last block with TF_PADDING_NONE can be incomplete
    if not Last or (LPadding <> TF_PADDING_NONE) then begin
      Result:= TF_E_INVALIDARG;
      Exit;
    end;
  end;

// encrypt
  while LDataSize >= LBlockSize do begin        // process full blocks
    Move(FIVector, Temp, LBlockSize);           // copy IV to temp block
                                                // encrypt temp block
    EncryptBlock(@Self, @Temp);
    XorBytes(Data, @Temp, LBlockSize);          // xor ciphertext with encrypted block
                                                // increment IV
    Cnt:= LBlockSize - 1;
    Inc(FIVector[Cnt]);
    if FIVector[Cnt] = 0 then begin
      repeat
        Dec(Cnt);
        Inc(FIVector[Cnt]);
      until (FIVector[Cnt] <> 0) or (Cnt = 0);
    end;
    Inc(Data, LBlockSize);                      // go to next block
    Dec(LDataSize, LBlockSize);
  end;

  if Last then begin
    if LDataSize > 0 then begin
      Move(FIVector, Temp, LBlockSize);       // copy IV to temp block
                                              // encrypt temp block
      EncryptBlock(@Self, @Temp);
      Cnt:= LBlockSize - 1;
      Inc(FIVector[Cnt]);
      if FIVector[Cnt] = 0 then begin
        repeat
          Dec(Cnt);
          Inc(FIVector[Cnt]);
        until (FIVector[Cnt] <> 0) or (Cnt = 0);
      end;
      if LPadding = TF_PADDING_NONE then begin
        XorBytes(Data, @Temp, LDataSize);
        Result:= TF_S_OK;
      end
      else
        Result:= TF_E_INVALIDARG;
      Exit;
    end
    else begin    { LDataSize = 0 }
      case LPadding of
                                              // XX 00 00 00 04
        TF_PADDING_ANSI: begin
          Dec(Data);
          Cnt:= Data^;
          if (Cnt > 0) and (Cnt <= LBlockSize) then begin
            SaveCnt:= Cnt - 1;
            while SaveCnt > 0 do begin
              Dec(Data);
              if Data^ <> 0 then begin
                Result:= TF_E_INVALIDARG;
                Exit;
              end;
              Dec(SaveCnt);
            end;
            DataSize:= DataSize - Cnt;
          end
          else begin
            Result:= TF_E_INVALIDARG;
            Exit;
          end;
        end;
                                              // XX 04 04 04 04
        TF_PADDING_PKCS: begin
          Dec(Data);
          Cnt:= Data^;
          if (Cnt > 0) and (Cnt <= LBlockSize) then begin
            SaveCnt:= Cnt - 1;
            while SaveCnt > 0 do begin
              Dec(Data);
              if Data^ <> Cnt then begin
                Result:= TF_E_INVALIDARG;
                Exit;
              end;
              Dec(SaveCnt);
            end;
            DataSize:= DataSize - Cnt;
          end
          else begin
            Result:= TF_E_INVALIDARG;
            Exit;
          end;
        end;
                                              // XX ?? ?? ?? 04
        TF_PADDING_ISO10126: begin
          Cnt:= (Data - 1)^;
          if (Cnt > 0) and (Cnt <= LBlockSize) then begin
            DataSize:= DataSize - Cnt;
          end
          else begin
            Result:= TF_E_INVALIDARG;
            Exit;
          end;
        end;

                                              // XX 80 00 00 00
        TF_PADDING_ISOIEC: begin
          Cnt:= LBlockSize;
          repeat
            Dec(Data);
            Dec(Cnt);
          until (Data^ <> 0) or (Cnt = 0);
          if (Data^ = $80) then
            DataSize:= DataSize - LBlockSize + Cnt
          else begin
            Result:= TF_E_INVALIDARG;
            Exit;
          end;
        end;
      end;
    end;
  end;
  Result:= TF_S_OK;
end;

{ TStreamCipher }

class function TBaseStreamCipher.Encrypt(Inst: Pointer; Data: PByte;
  var DataSize: Cardinal; BufSize: Cardinal; Last: Boolean): TF_RESULT;
var
  GetRand: TGetRandFunc;
//  EncryptBlock: TBlockProc;
  LDataSize: Cardinal;
  LBlockSize: Cardinal;
  Block: array[0..TF_MAX_CIPHER_BLOCK_SIZE - 1] of Byte;

begin
  LDataSize:= DataSize;
  if not PBaseStreamCipher(Inst).FValidKey then begin
    Result:= TF_E_UNEXPECTED;
    Exit;
  end;
  if LDataSize > BufSize then begin
    Result:= TF_E_INVALIDARG;
    Exit;
  end;
  LBlockSize:= GetBlockSize(Inst);
  if (LBlockSize = 0) or (LBlockSize > TF_MAX_CIPHER_BLOCK_SIZE) then begin
    Result:= TF_E_UNEXPECTED;
    Exit;
  end;
  @GetRand:= GetRandFunc(Inst);
//  @EncryptBlock:= GetEncryptProc(Inst);
  while LDataSize >= LBlockSize do begin
    GetRand(Inst, @Block, LBlockSize);
    XorBytes(Data, @Block, LBlockSize);
//    EncryptBlock(Inst, Data);
    Inc(Data, LBlockSize);
    Dec(LDataSize, LBlockSize);
  end;
  if (LDataSize > 0) then begin
    if not Last then begin
      Result:= TF_E_INVALIDARG;
      Exit;
    end;
    GetRand(Inst, @Block, LBlockSize);
    XorBytes(Data, @Block, LDataSize);
{
    Move(Data^, Block, LDataSize);
    EncryptBlock(Inst, @Block);
    Move(Block, Data^, LDataSize);
    FillChar(Block, LDataSize, 0);
}
  end;
  FillChar(Block, LBlockSize, 0);
  Result:= TF_S_OK;
end;

class function TBaseStreamCipher.Decrypt(Inst: Pointer; Data: PByte;
  var DataSize: Cardinal; Last: Boolean): TF_RESULT;
var
  DecryptBlock: TBlockFunc;
  LDataSize: Cardinal;
  LBlockSize: Cardinal;
  Block: array[0..TF_MAX_CIPHER_BLOCK_SIZE - 1] of Byte;

begin
  LDataSize:= DataSize;
  if not PBaseStreamCipher(Inst).FValidKey then begin
    Result:= TF_E_UNEXPECTED;
    Exit;
  end;
  LBlockSize:= GetBlockSize(Inst);
  if (LBlockSize = 0) or (LBlockSize > TF_MAX_CIPHER_BLOCK_SIZE) then begin
    Result:= TF_E_UNEXPECTED;
    Exit;
  end;
  @DecryptBlock:= GetDecryptFunc(Inst);
  while LDataSize >= LBlockSize do begin
    DecryptBlock(Inst, Data);
    Inc(Data, LBlockSize);
    Dec(LDataSize, LBlockSize);
  end;
  if (LDataSize > 0) then begin
    if not Last then begin
      Result:= TF_E_INVALIDARG;
      Exit;
    end;
    Move(Data^, Block, LDataSize);
    DecryptBlock(Inst, @Block);
    Move(Block, Data^, LDataSize);
    FillChar(Block, LDataSize, 0);
  end;
  Result:= TF_S_OK;
end;

class function TBaseStreamCipher.SetKeyParam(Inst: Pointer; Param: UInt32;
  Data: Pointer; DataLen: Cardinal): TF_RESULT;

var
  Block: array[0..TF_MAX_CIPHER_BLOCK_SIZE - 1] of Byte;
  Cnt: UInt64;
  RandBlock: TBlockFunc;
  LBlockSize: Cardinal;
  LData: UInt64;

begin
  if Param = TF_KP_INCNO{_LE} then begin
    if (DataLen = 0) or (DataLen > SizeOf(Cnt)) then begin
      Result:= TF_E_INVALIDARG;
      Exit;
    end;
    LBlockSize:= GetBlockSize(Inst);
    if (LBlockSize = 0) or (LBlockSize > TF_MAX_CIPHER_BLOCK_SIZE) then begin
      Result:= TF_E_UNEXPECTED;
      Exit;
    end;
    Cnt:= 0;
    Move(Data^, Cnt, DataLen);
    @RandBlock:= GetRandBlockFunc(Inst);
    while Cnt > 0 do begin
      RandBlock(Inst, @Block);
      Dec(Cnt);
    end;
    FillChar(Block, LBlockSize, 0);
    Result:= TF_S_OK;
  end
  else if Param = TF_KP_NONCE then begin
// only zero nonces allowed for stream ciphers without nonce support
    Result:= TF_E_INVALIDARG;
    if (DataLen > 0) and (DataLen <= SizeOf(UInt64)) then begin
      LData:= 0;
      Move(Data^, LData, DataLen);
      if LData = 0 then Result:= TF_S_OK;
    end;
  end
  else
    Result:= TF_E_INVALIDARG;
//    Result:= TF_E_NOTIMPL;
end;

class function TBaseStreamCipher.EncryptBlock(Inst: Pointer; Data: PByte): TF_RESULT;
var
  L: Cardinal;
  GetRand: TGetRandFunc;
  Block: array[0..TF_MAX_CIPHER_BLOCK_SIZE - 1] of Byte;

begin
  L:= GetBlockSize(Inst);
  if (L = 0) or (L > TF_MAX_CIPHER_BLOCK_SIZE) then begin
    Result:= TF_E_UNEXPECTED;
    Exit;
  end;
  @GetRand:= GetRandFunc(Inst);
  GetRand(Inst, @Block, L);
  XorBytes(Data, @Block, L);
  FillChar(Block, L, 0);
  Result:= TF_S_OK;
end;

class function TBaseStreamCipher.GetIsBlockCipher(Inst: Pointer): Boolean;
begin
  Result:= False;
end;

class function TBaseStreamCipher.GetKeyParam(Inst: Pointer; Param: UInt32;
  Data: Pointer; var DataLen: Cardinal): TF_RESULT;
begin
  Result:= TF_E_NOTIMPL;
end;

class function TBaseStreamCipher.GetRand(Inst: Pointer; Data: PByte;
  DataSize: Cardinal): TF_RESULT;
var
  LBlockSize: Cardinal;
  RandBlock: TBlockFunc;
  Block: array[0..TF_MAX_CIPHER_BLOCK_SIZE - 1] of Byte;

begin
  LBlockSize:= GetBlockSize(Inst);
  if (LBlockSize = 0) or (LBlockSize > TF_MAX_CIPHER_BLOCK_SIZE) then begin
    Result:= TF_E_UNEXPECTED;
    Exit;
  end;
  @RandBlock:= GetRandBlockFunc(Inst);
  while DataSize >= LBlockSize do begin
    RandBlock(Inst, Data);
    Inc(Data, LBlockSize);
    Dec(DataSize, LBlockSize);
  end;
  if DataSize > 0 then begin
    RandBlock(Inst, @Block);
    Move(Block, Data^, DataSize);
    FillChar(Block, LBlockSize, 0);
  end;
  Result:= TF_S_OK;
end;

class function TBaseStreamCipher.RandCrypt(Inst: Pointer; Data: PByte;
  DataSize: Cardinal; Last: Boolean): TF_RESULT;
var
  LBlockSize: Cardinal;
  RandBlock: TBlockFunc;
  Block: array[0..TF_MAX_CIPHER_BLOCK_SIZE - 1] of Byte;

begin
  if not PBaseStreamCipher(Inst).FValidKey then begin
    Result:= TF_E_UNEXPECTED;
    Exit;
  end;
  LBlockSize:= GetBlockSize(Inst);
  if (LBlockSize = 0) or (LBlockSize > TF_MAX_CIPHER_BLOCK_SIZE) or
    (not Last and (DataSize mod LBlockSize <> 0)) then begin
    Result:= TF_E_UNEXPECTED;
    Exit;
  end;
  @RandBlock:= GetRandBlockFunc(Inst);
  while DataSize >= LBlockSize do begin
    RandBlock(Inst, @Block);
    XorBytes(Data, @Block, LBlockSize);
    Inc(Data, LBlockSize);
    Dec(DataSize, LBlockSize);
  end;
  if DataSize > 0 then begin
(*
    if not Last then begin
      Result:= TF_E_UNEXPECTED;
      Exit;
    end;
*)
    RandBlock(Inst, @Block);
    XorBytes(Data, @Block, DataSize);
  end;
  FillChar(Block, LBlockSize, 0);
  Result:= TF_S_OK;
end;

end.
