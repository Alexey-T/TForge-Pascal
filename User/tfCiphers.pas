{ *********************************************************** }
{ *                     TForge Library                      * }
{ *       Copyright (c) Sergey Kasandrov 1997, 2016         * }
{ *********************************************************** }

unit tfCiphers;

interface

{$I TFL.inc}

uses
  SysUtils, Classes, tfTypes, tfBytes, tfConsts, tfExceptions,
  {$IFDEF TFL_DLL} tfImport {$ELSE} tfCipherServ, tfKeyStreams {$ENDIF};

type
  TCipher = record
  private
    FInstance: ICipher;
//    procedure SetFlagsProc(const Value: UInt32);
    procedure SetIVProc(const Value: ByteArray);
    procedure SetNonceProc(const Value: UInt64);
    function GetBlockSize: Cardinal;
  public
//    class function Create(const Alg: ICipherAlgorithm): TCipher; static;
    procedure Free;
    function IsAssigned: Boolean;
    function IsBlockCipher: Boolean;

//    function SetFlags(AFlags: UInt32): TCipher; overload;

    function SetIV(AIV: Pointer; AIVLen: Cardinal): TCipher; overload;
    function SetIV(const AIV: ByteArray): TCipher; overload;

//    function SetNonce(const Value: ByteArray): TCipher; overload;
    function SetNonce(const Value: UInt64): TCipher;
    function GetNonce: UInt64;
//    function SetBlockNo(const Value: ByteArray): TCipher; overload;
//    function SetBlockNo(const Value: UInt64): TCipher; overload;

    function ExpandKey(AKey: PByte; AKeyLen: Cardinal): TCipher; overload;

    function ExpandKey(AKey: PByte; AKeyLen: Cardinal; AFlags: UInt32): TCipher; overload;
    function ExpandKey(AKey: PByte; AKeyLen: Cardinal; AFlags: UInt32;
                       AIV: Pointer; AIVLen: Cardinal): TCipher; overload;

    function ExpandKey(const AKey: ByteArray): TCipher; overload;
    function ExpandKey(const AKey: ByteArray; AFlags: UInt32): TCipher; overload;
    function ExpandKey(const AKey: ByteArray; AFlags: UInt32;
                       const AIV: ByteArray): TCipher; overload;
    function ExpandKey(const AKey: ByteArray; AFlags: UInt32;
                       const ANonce: UInt64): TCipher; overload;

    procedure Burn;

    procedure Encrypt(var Data; var DataSize: Cardinal;
                      BufSize: Cardinal; Last: Boolean);
    procedure Decrypt(var Data; var DataSize: Cardinal;
                      Last: Boolean);
    procedure Apply(var Data; DataSize: Cardinal;
                        Last: Boolean);

    procedure GetKeyStream(var Data; DataSize: Cardinal);
    function KeyStream(DataSize: Cardinal): ByteArray;

    function EncryptBlock(const Data, Key: ByteArray): ByteArray;
    function DecryptBlock(const Data, Key: ByteArray): ByteArray;

    function EncryptData(const Data: ByteArray): ByteArray; deprecated;
    function DecryptData(const Data: ByteArray): ByteArray; deprecated;

    function EncryptByteArray(const Data: ByteArray): ByteArray;
    function DecryptByteArray(const Data: ByteArray): ByteArray;

    procedure EncryptStream(InStream, OutStream: TStream; BufSize: Cardinal = 0);
    procedure DecryptStream(InStream, OutStream: TStream; BufSize: Cardinal = 0);

    procedure EncryptFile(const InName, OutName: string; BufSize: Cardinal = 0);
    procedure DecryptFile(const InName, OutName: string; BufSize: Cardinal = 0);

//    function Skip(Value: UInt32): TCipher; overload;
    function Skip(Value: UInt64): TCipher; overload;
//    function Skip(Value: ByteArray): TCipher; overload;

    class function GetInstance(const Name: string): TCipher; static;

    class function AES: TCipher; static;
    class function DES: TCipher; static;
    class function TripleDES: TCipher; static;
    class function RC5: TCipher; overload; static;
    class function RC5(BlockSize, Rounds: Cardinal): TCipher; overload; static;
    class function RC4: TCipher; static;
    class function Salsa20: TCipher; overload; static;
    class function Salsa20(Rounds: Cardinal): TCipher; overload; static;
    class function ChaCha20: TCipher; overload; static;
    class function ChaCha20(Rounds: Cardinal): TCipher; overload; static;

    function Copy: TCipher;

    class operator Explicit(const Name: string): TCipher;
    class operator Explicit(AlgID: Integer): TCipher;

    class function AlgName(Index: Cardinal): string; static;
    class function AlgCount: Integer; static;

//    property Algorithm: ICipher read FInstance;
//    property Flags: UInt32 write SetFlagsProc;

// todo:
//    property Dir: UInt32 read GetDir write SetDir;
//    property Mode: UInt32 read GetMode write SetMode;
//    property Padding: UInt32 read GetPadding write SetPadding;
//    property IV: ByteArray read GetIV write SetIVProc;
    property Nonce: UInt64 read GetNonce write SetNonceProc;
    property BlockSize: Cardinal read GetBlockSize;
  end;

  TStreamCipher = record
  private
    FInstance: IStreamCipher;
    function GetNonce: UInt64;
    procedure SetNonceProc(const Nonce: UInt64);
  public
    procedure Free;
    function IsAssigned: Boolean;
    procedure Burn;
    function Copy: TStreamCipher;

    function ExpandKey(const AKey: ByteArray; ANonce: UInt64 = 0): TStreamCipher; overload;
    function ExpandKey(AKey: PByte; AKeyLen: Cardinal; ANonce: UInt64): TStreamCipher; overload;
    function SetNonce(const AValue: UInt64): TStreamCipher;
    function Skip(const AValue: Int64): TStreamCipher;

    procedure GetKeyStream(var Data; DataSize: Cardinal);
    function KeyStream(ASize: Cardinal): ByteArray;

    procedure Apply(var Data; DataLen: Cardinal);
    procedure ApplyTo(const InData; var OutData; DataLen: Cardinal);

    function ApplyToByteArray(const Data: ByteArray): ByteArray;
    procedure ApplyToStream(InStream, OutStream: TStream; BufSize: Cardinal = 0);
    procedure ApplyToFile(const InName, OutName: string; BufSize: Cardinal = 0);

    class function GetInstance(const Name: string): TStreamCipher; static;

    class function AES: TStreamCipher; static;
    class function DES: TStreamCipher; static;
    class function TripleDES: TStreamCipher; static;
    class function RC5: TStreamCipher; overload; static;
    class function RC5(BlockSize, Rounds: Cardinal): TStreamCipher; overload; static;
    class function RC4: TStreamCipher; static;
    class function Salsa20: TStreamCipher; overload; static;
    class function Salsa20(Rounds: Cardinal): TStreamCipher; overload; static;
    class function ChaCha20: TStreamCipher; overload; static;
    class function ChaCha20(Rounds: Cardinal): TStreamCipher; overload; static;

    class operator Explicit(const Name: string): TStreamCipher;

    property Nonce: UInt64 read GetNonce write SetNonceProc;
  end;

type
  ECipherError = class(EForgeError);

implementation

var
  FServer: ICipherServer;

procedure CipherError(ACode: TF_RESULT; const Msg: string = '');
begin
  raise ECipherError.Create(ACode, Msg);
end;

procedure HResCheck(Value: TF_RESULT); inline;
begin
  if Value <> TF_S_OK then
    CipherError(Value);
end;

{ TCipher }
(*
class function TCipher.Create(const Alg: ICipherAlgorithm): TCipher;
begin
  Result.FInstance:= Alg;
end;
*)

procedure TCipher.Free;
begin
  FInstance:= nil;
end;

function TCipher.GetBlockSize: Cardinal;
begin
  Result:= FInstance.GetBlockSize;
end;

procedure TCipher.GetKeyStream(var Data; DataSize: Cardinal);
begin
  HResCheck(FInstance.GetKeyStream(@Data, DataSize));
end;

function TCipher.GetNonce: UInt64;
var
  DataLen: Cardinal;

begin
  DataLen:= SizeOf(UInt64);
  HResCheck(FInstance.GetKeyParam(TF_KP_NONCE, @Result, DataLen));
end;

function TCipher.KeyStream(DataSize: Cardinal): ByteArray;
begin
  Result:= ByteArray.Allocate(DataSize);
  GetKeyStream(Result.RawData^, DataSize);
end;

function TCipher.IsAssigned: Boolean;
begin
  Result:= FInstance <> nil;
end;

function TCipher.IsBlockCipher: Boolean;
begin
  Result:= FInstance.GetIsBlockCipher;
end;

class function TCipher.GetInstance(const Name: string): TCipher;
begin
  HResCheck(FServer.GetByName(Pointer(Name), SizeOf(Char), Result.FInstance));
end;

class function TCipher.AES: TCipher;
begin
  HResCheck(FServer.GetByAlgID(TF_ALG_AES, Result.FInstance));
end;

class function TCipher.DES: TCipher;
begin
  HResCheck(FServer.GetByAlgID(TF_ALG_DES, Result.FInstance));
end;

class function TCipher.TripleDES: TCipher;
begin
  HResCheck(FServer.GetByAlgID(TF_ALG_3DES, Result.FInstance));
end;

class function TCipher.RC4: TCipher;
begin
  HResCheck(FServer.GetByAlgID(TF_ALG_RC4, Result.FInstance));
end;

class function TCipher.RC5: TCipher;
begin
  HResCheck(FServer.GetByAlgID(TF_ALG_RC5, Result.FInstance));
end;

class function TCipher.RC5(BlockSize, Rounds: Cardinal): TCipher;
begin
  HResCheck(FServer.GetRC5(BlockSize, Rounds, Result.FInstance));
end;

function TCipher.ExpandKey(AKey: PByte; AKeyLen: Cardinal): TCipher;
begin
  HResCheck(FInstance.ExpandKey(AKey, AKeyLen));
  Result:= Self;
end;

function TCipher.ExpandKey(const AKey: ByteArray): TCipher;
begin
  HResCheck(FInstance.ExpandKey(AKey.RawData, AKey.Len));
  Result:= Self;
end;

function TCipher.ExpandKey(AKey: PByte; AKeyLen: Cardinal; AFlags: UInt32): TCipher;
begin
  HResCheck(FInstance.SetKeyParam(TF_KP_FLAGS, @AFlags, SizeOf(AFlags)));
  HResCheck(FInstance.ExpandKey(AKey, AKeyLen));
  Result:= Self;
end;

function TCipher.ExpandKey(AKey: PByte; AKeyLen: Cardinal; AFlags: UInt32;
                           AIV: Pointer; AIVLen: Cardinal): TCipher;
begin
  HResCheck(FInstance.SetKeyParam(TF_KP_FLAGS, @AFlags, SizeOf(AFlags)));
  HResCheck(FInstance.SetKeyParam(TF_KP_IV, AIV, AIVLen));
  HResCheck(FInstance.ExpandKey(AKey, AKeyLen));
  Result:= Self;
end;

function TCipher.ExpandKey(const AKey: ByteArray; AFlags: UInt32): TCipher;
begin
  HResCheck(FInstance.SetKeyParam(TF_KP_FLAGS, @AFlags, SizeOf(AFlags)));
  HResCheck(FInstance.ExpandKey(AKey.RawData, AKey.Len));
  Result:= Self;
end;

function TCipher.ExpandKey(const AKey: ByteArray; AFlags: UInt32;
                           const AIV: ByteArray): TCipher;
begin
  HResCheck(FInstance.SetKeyParam(TF_KP_FLAGS, @AFlags, SizeOf(AFlags)));
  HResCheck(FInstance.SetKeyParam(TF_KP_IV, AIV.RawData, AIV.Len));
  HResCheck(FInstance.ExpandKey(AKey.RawData, AKey.Len));
  Result:= Self;
end;

function TCipher.ExpandKey(const AKey: ByteArray; AFlags: UInt32;
                           const ANonce: UInt64): TCipher;
begin
  HResCheck(FInstance.SetKeyParam(TF_KP_FLAGS, @AFlags, SizeOf(AFlags)));
  HResCheck(FInstance.SetKeyParam(TF_KP_NONCE, @ANonce, SizeOf(ANonce)));
  HResCheck(FInstance.ExpandKey(AKey.RawData, AKey.Len));
  Result:= Self;
end;

procedure TCipher.Burn;
begin
  FInstance.Burn;
end;

procedure TCipher.Encrypt(var Data; var DataSize: Cardinal;
  BufSize: Cardinal; Last: Boolean);
begin
  HResCheck(FInstance.Encrypt(@Data, DataSize, BufSize, Last));
end;

procedure TCipher.Decrypt(var Data; var DataSize: Cardinal; Last: Boolean);
begin
  HResCheck(FInstance.Decrypt(@Data, DataSize, Last));
end;

procedure TCipher.Apply(var Data; DataSize: Cardinal; Last: Boolean);
begin
  HResCheck(FInstance.KeyCrypt(@Data, DataSize, Last));
end;

function TCipher.EncryptBlock(const Data, Key: ByteArray): ByteArray;
var
  Flags: LongWord;
  BlockSize: Integer;

begin
  BlockSize:= FInstance.GetBlockSize;
  if (BlockSize = 0) or (BlockSize <> Data.GetLen) then
    CipherError(TF_E_UNEXPECTED);

  Flags:= ECB_ENCRYPT;
  HResCheck(FInstance.SetKeyParam(TF_KP_FLAGS, @Flags, SizeOf(Flags)));
  HResCheck(FInstance.ExpandKey(Key.RawData, Key.Len));

  Result:= Data.Copy();
  FInstance.EncryptBlock(Result.RawData);
end;

function TCipher.DecryptBlock(const Data, Key: ByteArray): ByteArray;
var
  Flags: LongWord;
  BlockSize: Integer;

begin
  BlockSize:= FInstance.GetBlockSize;
  if (BlockSize = 0) or (BlockSize <> Data.GetLen) then
    CipherError(TF_E_UNEXPECTED);

  Flags:= ECB_DECRYPT;
  HResCheck(FInstance.SetKeyParam(TF_KP_FLAGS, @Flags, SizeOf(Flags)));
  HResCheck(FInstance.ExpandKey(Key.RawData, Key.Len));

  Result:= Data.Copy;
  FInstance.DecryptBlock(Result.RawData);
end;

function TCipher.EncryptByteArray(const Data: ByteArray): ByteArray;
var
  L0, L1: LongWord;

begin
  L0:= Data.GetLen;
  L1:= L0;
  if (FInstance.Encrypt(nil, L1, 0, True) <> TF_E_INVALIDARG) or (L1 <= 0)
    then CipherError(TF_E_UNEXPECTED);

  Result:= Data;
  Result.ReAllocate(L1);
  HResCheck(FInstance.Encrypt(Result.RawData, L0, L1, True));
end;

function TCipher.DecryptByteArray(const Data: ByteArray): ByteArray;
var
  L: LongWord;

begin
  L:= Data.GetLen;
  Result:= Data.Copy;
  HResCheck(FInstance.Decrypt(Result.RawData, L, True));
  Result.SetLen(L);
end;

function TCipher.EncryptData(const Data: ByteArray): ByteArray;
var
  L0, L1: LongWord;

begin
  L0:= Data.GetLen;
  L1:= L0;
  if (FInstance.Encrypt(nil, L1, 0, True) <> TF_E_INVALIDARG) or (L1 <= 0)
    then CipherError(TF_E_UNEXPECTED);

  Result:= Data;
  Result.ReAllocate(L1);
  HResCheck(FInstance.Encrypt(Result.RawData, L0, L1, True));
end;

procedure TCipher.EncryptFile(const InName, OutName: string; BufSize: Cardinal);
var
  InStream, OutStream: TStream;

begin
  InStream:= TFileStream.Create(InName, fmOpenRead or fmShareDenyWrite);
  OutStream:= TFileStream.Create(OutName, fmCreate);
  try
    EncryptStream(InStream, OutStream, BufSize);
  finally
    InStream.Free;
    OutStream.Free;
  end;
end;

procedure TCipher.EncryptStream(InStream, OutStream: TStream; BufSize: Cardinal);
const
  MIN_BUFSIZE = 4 * 1024;
  MAX_BUFSIZE = 4 * 1024 * 1024;
  DEFAULT_BUFSIZE = 16 * 1024;
  PAD_BUFSIZE = TF_MAX_CIPHER_BLOCK_SIZE;


var
  OutBufSize, DataSize: LongWord;
  Data, PData: PByte;
  N: Integer;
  Cnt: LongWord;
  Last: Boolean;

begin
  if (BufSize < MIN_BUFSIZE) or (BufSize > MAX_BUFSIZE)
    then BufSize:= DEFAULT_BUFSIZE
    else BufSize:= (BufSize + PAD_BUFSIZE - 1)
                         and not (PAD_BUFSIZE - 1);
  OutBufSize:= BufSize + PAD_BUFSIZE;
  GetMem(Data, OutBufSize);
  try
    repeat
      Cnt:= BufSize;
      PData:= Data;
      repeat
        N:= InStream.Read(PData^, Cnt);
        if N <= 0 then Break;
        Inc(PData, N);
        Dec(Cnt, N);
      until (Cnt = 0);
      Last:= Cnt > 0;
      DataSize:= BufSize - Cnt;
      Encrypt(Data^, DataSize, OutBufSize, Last);
      if DataSize > 0 then
        OutStream.WriteBuffer(Data^, DataSize);
    until Last;
  finally
    FreeMem(Data);
  end;
end;

procedure TCipher.DecryptStream(InStream, OutStream: TStream; BufSize: Cardinal);
const
  MIN_BUFSIZE = 4 * 1024;
  MAX_BUFSIZE = 4 * 1024 * 1024;
  DEFAULT_BUFSIZE = 16 * 1024;
  PAD_BUFSIZE = TF_MAX_CIPHER_BLOCK_SIZE;

var
  OutBufSize, DataSize: Cardinal;
  Data, PData: PByte;
  N: Integer;
  Cnt: Cardinal;
  Last: Boolean;

begin
  if (BufSize < MIN_BUFSIZE) or (BufSize > MAX_BUFSIZE)
    then BufSize:= DEFAULT_BUFSIZE
    else BufSize:= (BufSize + PAD_BUFSIZE - 1)
                         and not (PAD_BUFSIZE - 1);
  OutBufSize:= BufSize + PAD_BUFSIZE;
  GetMem(Data, OutBufSize);
  try
    PData:= Data;
    Cnt:= OutBufSize;
    repeat
      repeat
        N:= InStream.Read(PData^, Cnt);
        if N <= 0 then Break;
        Inc(PData, N);
        Dec(Cnt, N);
      until (Cnt = 0);
      Last:= Cnt > 0;
      if Last then begin
        DataSize:= OutBufSize - Cnt;
      end
      else begin
        DataSize:= BufSize - Cnt;
      end;
      Decrypt(Data^, DataSize, Last);
      if DataSize > 0 then
        OutStream.WriteBuffer(Data^, DataSize);
      if Last then Break
      else begin
        Move((Data + OutBufSize - PAD_BUFSIZE)^, Data^, PAD_BUFSIZE);
        PData:= Data + PAD_BUFSIZE;
        Cnt:= BufSize;
      end;
    until False;
  finally
    FreeMem(Data);
  end;
end;

function TCipher.DecryptData(const Data: ByteArray): ByteArray;
var
  L: LongWord;

begin
  L:= Data.GetLen;
  Result:= Data.Copy;
  HResCheck(FInstance.Decrypt(Result.RawData, L, True));
  Result.SetLen(L);
end;

procedure TCipher.DecryptFile(const InName, OutName: string; BufSize: Cardinal);
var
  InStream, OutStream: TStream;

begin
  InStream:= TFileStream.Create(InName, fmOpenRead or fmShareDenyWrite);
  OutStream:= TFileStream.Create(OutName, fmCreate);
  try
    DecryptStream(InStream, OutStream, BufSize);
  finally
    InStream.Free;
    OutStream.Free;
  end;
end;

function TCipher.Copy: TCipher;
begin
  HResCheck(FInstance.Duplicate(Result.FInstance));
end;

class function TCipher.AlgCount: Integer;
begin
  Result:= FServer.GetCount;
end;

{
function TCipher.Decrypt(const Data: ByteArray): ByteArray;
var
  L: LongWord;

begin
  L:= Data.Len;
  Result:= ByteArray.Copy(Data);
  Decrypt(Result.RawData^, L, True);
  Result.Len:= L;
end;
}

class function TCipher.AlgName(Index: Cardinal): string;
var
  Bytes: IBytes;
  I, L: Integer;
  P: PByte;

begin
  HResCheck(FServer.GetName(Index, Bytes));
  L:= Bytes.GetLen;
  P:= Bytes.GetRawData;
  SetLength(Result, L);
  for I:= 1 to L do begin
    Result[I]:= Char(P^);
    Inc(P);
  end;
end;

class function TCipher.Salsa20: TCipher;
begin
  HResCheck(FServer.GetByAlgID(TF_ALG_SALSA20, Result.FInstance));
end;

class function TCipher.Salsa20(Rounds: Cardinal): TCipher;
begin
  HResCheck(FServer.GetSalsa20(Rounds, Result.FInstance));
end;

class function TCipher.ChaCha20: TCipher;
begin
  HResCheck(FServer.GetByAlgID(TF_ALG_CHACHA20, Result.FInstance));
end;

class function TCipher.ChaCha20(Rounds: Cardinal): TCipher;
begin
  HResCheck(FServer.GetChaCha20(Rounds, Result.FInstance));
end;

(*
function TCipher.SetFlags(AFlags: UInt32): TCipher;
begin
  HResCheck(FInstance.SetKeyParam(TF_KP_FLAGS, @AFlags, SizeOf(AFlags)));
  Result:= Self;
end;

procedure TCipher.SetFlagsProc(const Value: UInt32);
begin
  HResCheck(FInstance.SetKeyParam(TF_KP_FLAGS, @Value, SizeOf(Value)));
end;
*)

function TCipher.SetIV(AIV: Pointer; AIVLen: Cardinal): TCipher;
begin
  HResCheck(FInstance.SetKeyParam(TF_KP_IV, AIV, AIVLen));
  Result:= Self;
end;

function TCipher.SetIV(const AIV: ByteArray): TCipher;
begin
  HResCheck(FInstance.SetKeyParam(TF_KP_IV, AIV.RawData, AIV.Len));
  Result:= Self;
end;

procedure TCipher.SetIVProc(const Value: ByteArray);
begin
  HResCheck(FInstance.SetKeyParam(TF_KP_IV, Value.RawData, Value.Len));
end;

(*
function TCipher.SetNonce(const Value: ByteArray): TCipher;
begin
  HResCheck(FInstance.SetKeyParam(TF_KP_NONCE, Value.RawData, Value.Len));
  Result:= Self;
end;
*)

function TCipher.SetNonce(const Value: UInt64): TCipher;
begin
  HResCheck(FInstance.SetKeyParam(TF_KP_NONCE, @Value, SizeOf(Value)));
  Result:= Self;
end;

procedure TCipher.SetNonceProc(const Value: UInt64);
begin
  HResCheck(FInstance.SetKeyParam(TF_KP_NONCE, @Value, SizeOf(Value)));
//  HResCheck(FInstance.SetKeyParam(TF_KP_NONCE, Value.RawData, Value.Len));
end;

{
function TCipher.SetBlockNo(const Value: ByteArray): TCipher;
begin
  HResCheck(FAlgorithm.SetKeyParam(TF_KP_BLOCKNO, Value.RawData, Value.Len));
  Result:= Self;
end;

function TCipher.SetBlockNo(const Value: UInt64): TCipher;
begin
  HResCheck(FAlgorithm.SetKeyParam(TF_KP_BLOCKNO_LE, @Value, SizeOf(Value)));
  Result:= Self;
end;
}
(*
function TCipher.Skip(Value: UInt32): TCipher;
begin
  HResCheck(FInstance.SetKeyParam(TF_KP_INCNO{_LE}, @Value, SizeOf(Value)));
  Result:= Self;
end;
*)
function TCipher.Skip(Value: UInt64): TCipher;
begin
  HResCheck(FInstance.SetKeyParam(TF_KP_INCNO{_LE}, @Value, SizeOf(Value)));
  Result:= Self;
end;
{
function TCipher.Skip(Value: ByteArray): TCipher;
begin
  HResCheck(FAlgorithm.SetKeyParam(TF_KP_INCNO, @Value, SizeOf(Value)));
  Result:= Self;
end;
}
class operator TCipher.Explicit(AlgID: Integer): TCipher;
begin
  HResCheck(FServer.GetByAlgID(AlgID, Result.FInstance));
end;

class operator TCipher.Explicit(const Name: string): TCipher;
begin
  HResCheck(FServer.GetByName(Pointer(Name), SizeOf(Char), Result.FInstance));
end;

{ TKeyStream }

procedure TStreamCipher.Free;
begin
  FInstance:= nil;
end;

function TStreamCipher.IsAssigned: Boolean;
begin
  Result:= FInstance <> nil;
end;

function TStreamCipher.KeyStream(ASize: Cardinal): ByteArray;
begin
  Result:= ByteArray.Allocate(ASize);
  HResCheck(FInstance.GetKeyStream(Result.GetRawData, ASize));
end;

procedure TStreamCipher.Burn;
begin
  FInstance.Burn;
end;

function TStreamCipher.ExpandKey(AKey: PByte; AKeyLen: Cardinal; ANonce: UInt64): TStreamCipher;
begin
  HResCheck(FInstance.ExpandKey(AKey, AKeyLen, ANonce));
  Result:= Self;
end;

function TStreamCipher.ExpandKey(const AKey: ByteArray; ANonce: UInt64): TStreamCipher;
begin
  HResCheck(FInstance.ExpandKey(AKey.GetRawData, AKey.GetLen, ANonce));
  Result:= Self;
end;

(*
function TStreamCipher.ExpandKey(const AKey: ByteArray): TStreamCipher;
begin
  HResCheck(FInstance.ExpandKey(AKey.GetRawData, AKey.GetLen, 0));
  Result:= Self;
end;
*)

class operator TStreamCipher.Explicit(const Name: string): TStreamCipher;
begin
  HResCheck(FServer.GetKSByName(Pointer(Name), SizeOf(Char), Result.FInstance));
end;

(*  don't want to expose
class operator TStreamCipher.Explicit(AlgID: Integer): TStreamCipher;
begin
  HResCheck(FServer.GetKSByAlgID(AlgID, Result.FInstance));
end;
*)

function TStreamCipher.Skip(const AValue: Int64): TStreamCipher;
begin
  HResCheck(FInstance.Skip(AValue));
  Result:= Self;
end;

// introduced for consistency with TCipher.SetNonce
function TStreamCipher.SetNonce(const AValue: UInt64): TStreamCipher;
begin
  HResCheck(FInstance.SetNonce(Nonce));
  Result:= Self;
end;

function TStreamCipher.Copy: TStreamCipher;
begin
  HResCheck(FInstance.Duplicate(Result.FInstance));
end;

class function TStreamCipher.AES: TStreamCipher;
begin
  HResCheck(FServer.GetKSByAlgID(TF_ALG_AES, Result.FInstance));
end;

class function TStreamCipher.DES: TStreamCipher;
begin
  HResCheck(FServer.GetKSByAlgID(TF_ALG_DES, Result.FInstance));
end;

class function TStreamCipher.TripleDES: TStreamCipher;
begin
  HResCheck(FServer.GetKSByAlgID(TF_ALG_3DES, Result.FInstance));
end;

class function TStreamCipher.Salsa20: TStreamCipher;
begin
  HResCheck(FServer.GetKSByAlgID(TF_ALG_SALSA20, Result.FInstance));
end;

class function TStreamCipher.Salsa20(Rounds: Cardinal): TStreamCipher;
begin
  HResCheck(FServer.GetKSSalsa20(Rounds, Result.FInstance));
end;

class function TStreamCipher.GetInstance(const Name: string): TStreamCipher;
begin
  HResCheck(FServer.GetKSByName(Pointer(Name), SizeOf(Char), Result.FInstance));
end;

function TStreamCipher.GetNonce: UInt64;
begin
  HResCheck(FInstance.GetNonce(Result));
end;

procedure TStreamCipher.SetNonceProc(const Nonce: UInt64);
begin
  HResCheck(FInstance.SetNonce(Nonce));
end;

class function TStreamCipher.ChaCha20: TStreamCipher;
begin
  HResCheck(FServer.GetKSByAlgID(TF_ALG_CHACHA20, Result.FInstance));
end;

class function TStreamCipher.ChaCha20(Rounds: Cardinal): TStreamCipher;
begin
  HResCheck(FServer.GetKSChaCha20(Rounds, Result.FInstance));
end;

class function TStreamCipher.RC4: TStreamCipher;
begin
  HResCheck(FServer.GetKSByAlgID(TF_ALG_RC4, Result.FInstance));
end;

class function TStreamCipher.RC5(BlockSize, Rounds: Cardinal): TStreamCipher;
begin
  HResCheck(FServer.GetKSRC5(BlockSize, Rounds, Result.FInstance));
end;

class function TStreamCipher.RC5: TStreamCipher;
begin
  HResCheck(FServer.GetKSByAlgID(TF_ALG_RC5, Result.FInstance));
end;

procedure TStreamCipher.GetKeyStream(var Data; DataSize: Cardinal);
begin
  HResCheck(FInstance.GetKeyStream(@Data, DataSize));
end;

procedure TStreamCipher.Apply(var Data; DataLen: Cardinal);
begin
  HResCheck(FInstance.Apply(@Data, DataLen));
end;

procedure TStreamCipher.ApplyTo(const InData; var OutData; DataLen: Cardinal);
var
  HRes: TF_RESULT;

begin
  Move(InData, OutData, DataLen);
  HRes:= FInstance.Apply(@OutData, DataLen);
  if HRes <> TF_S_OK then begin
    FillChar(OutData, DataLen, 0);
    CipherError(HRes);
  end;
end;

function TStreamCipher.ApplyToByteArray(const Data: ByteArray): ByteArray;
var
  L: Cardinal;
  HRes: TF_RESULT;

begin
  L:= Data.GetLen;
  Result:= Data;
  Result.ReAllocate(L);
  HRes:= FInstance.Apply(Result.RawData, L);
  if HRes <> TF_S_OK then begin
    FillChar(Result.RawData^, L, 0);
    CipherError(HRes);
  end;
end;

procedure TStreamCipher.ApplyToFile(const InName, OutName: string;
  BufSize: Cardinal);
var
  InStream, OutStream: TStream;

begin
  InStream:= TFileStream.Create(InName, fmOpenRead or fmShareDenyWrite);
  try
    OutStream:= TFileStream.Create(OutName, fmCreate);
    try
      ApplyToStream(InStream, OutStream, BufSize);
    finally
      OutStream.Free;
    end;
  finally
    InStream.Free;
  end;
end;

procedure TStreamCipher.ApplyToStream(InStream, OutStream: TStream;
  BufSize: Cardinal);
const
  MIN_BUFSIZE = 4 * 1024;
  MAX_BUFSIZE = 4 * 1024 * 1024;
  DEFAULT_BUFSIZE = 16 * 1024;
  PAD_BUFSIZE = TF_MAX_CIPHER_BLOCK_SIZE;

var
  DataSize: Cardinal;
  Data, PData: PByte;
  N: Integer;
  Cnt: Cardinal;

begin
  if (BufSize < MIN_BUFSIZE) or (BufSize > MAX_BUFSIZE)
    then BufSize:= DEFAULT_BUFSIZE
    else BufSize:= (BufSize + PAD_BUFSIZE - 1)
                         and not (PAD_BUFSIZE - 1);
  GetMem(Data, BufSize);
  try
    repeat
      Cnt:= BufSize;
      PData:= Data;
      repeat
        N:= InStream.Read(PData^, Cnt);
        if N <= 0 then Break;
        Inc(PData, N);
        Dec(Cnt, N);
      until (Cnt = 0);
      DataSize:= BufSize - Cnt;
      if DataSize > 0 then begin
        Apply(Data^, DataSize);
        OutStream.WriteBuffer(Data^, DataSize);
        FillChar(Data^, DataSize, 0);
      end;
    until Cnt > 0;
  finally
    FreeMem(Data);
  end;
end;

{$IFNDEF TFL_DLL}
initialization
  GetCipherServer(FServer);

{$ENDIF}
end.
