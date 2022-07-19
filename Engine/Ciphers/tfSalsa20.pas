{ *********************************************************** }
{ *                     TForge Library                      * }
{ *       Copyright (c) Sergey Kasandrov 1997, 2016         * }
{ *********************************************************** }

unit tfSalsa20;

{$I TFL.inc}

interface

uses
  tfTypes;

type
  PSalsaBlock = ^TSalsaBlock;
  TSalsaBlock = array[0..15] of UInt32;

  PSalsa20 = ^TSalsa20;
  TSalsa20 = record
  private type
    PKey = ^TKey;
    TKey = array[0..7] of UInt32;    // 256-bit key

    PBlock = ^TBlock;
    TBlock = array[0..15] of UInt32;

    TNonce = record
      case Byte of
        0: (Value: UInt64);
        1: (Words: array[0..1] of UInt32);
    end;

  private
{$HINTS OFF}                    // -- inherited fields begin --
                                // from tfRecord
    FVTable:   Pointer;
    FRefCount: Integer;
                                // from tfStreamCipher
    FValidKey: Boolean;
                                // -- inherited fields end --
    FExpandedKey: TBlock;
    FRounds: Cardinal;          // 2..254
{$HINTS ON}
  public
    class function Release(Inst: PSalsa20): Integer; stdcall; static;
    class function ExpandKey(Inst: PSalsa20; Key: PByte; KeySize: Cardinal): TF_RESULT;
          {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function GetBlockSize(Inst: PSalsa20): Integer;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function DuplicateKey(Inst: PSalsa20; var Key: PSalsa20): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class procedure DestroyKey(Inst: PSalsa20);{$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function SetKeyParam(Inst: PSalsa20; Param: UInt32; Data: Pointer;
          DataLen: Cardinal): TF_RESULT;
         {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function KeyBlock(Inst: PSalsa20; Data: TSalsa20.PBlock): TF_RESULT;
          {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function GetKeyParam(Inst: PSalsa20; Param: UInt32; Data: Pointer;
      var DataLen: Cardinal): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
  end;

type
  TChaCha20 = record
  public
    class function ExpandKey(Inst: PSalsa20; Key: PByte; KeySize: Cardinal): TF_RESULT;
          {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function DuplicateKey(Inst: PSalsa20; var Key: PSalsa20): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function SetKeyParam(Inst: PSalsa20; Param: UInt32; Data: Pointer;
          DataLen: Cardinal): TF_RESULT;
         {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function KeyBlock(Inst: PSalsa20; Data: TSalsa20.PBlock): TF_RESULT;
          {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function GetKeyParam(Inst: PSalsa20; Param: UInt32; Data: Pointer;
      var DataLen: Cardinal): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
  end;

function GetSalsa20Algorithm(var A: PSalsa20): TF_RESULT;
function GetSalsa20AlgorithmEx(var A: PSalsa20; Rounds: Integer): TF_RESULT;

function GetChaCha20Algorithm(var A: PSalsa20): TF_RESULT;
function GetChaCha20AlgorithmEx(var A: PSalsa20; Rounds: Integer): TF_RESULT;

type
  TChaChaPRG = record
  private type
    TBlock = array[0..15] of UInt32;
  private
    FExpandedKey: TBlock;
  public
    function Init(Seed: PByte; SeedSize: Cardinal): TF_RESULT;
    function GetKeyStream(Buf: PByte; BufSize: Cardinal): TF_RESULT;
  end;

implementation

uses tfRecords, tfUtils, tfBaseCiphers;

const
  SALSA_BLOCK_SIZE = 64;

  Salsa20VTable: array[0..16] of Pointer = (
   @TForgeInstance.QueryIntf,
   @TForgeInstance.Addref,
   @TSalsa20.Release,

   @TSalsa20.DestroyKey,
   @TSalsa20.DuplicateKey,
   @TSalsa20.ExpandKey,
   @TSalsa20.SetKeyParam,
   @TSalsa20.GetKeyParam,
   @TSalsa20.GetBlockSize,
   @TBaseStreamCipher.Encrypt,
   @TBaseStreamCipher.Decrypt,
   @TBaseStreamCipher.EncryptBlock,
   @TBaseStreamCipher.EncryptBlock,
   @TBaseStreamCipher.GetRand,
   @TSalsa20.KeyBlock,
   @TBaseStreamCipher.RandCrypt,
   @TBaseStreamCipher.GetIsBlockCipher
   );

  ChaCha20VTable: array[0..16] of Pointer = (
   @TForgeInstance.QueryIntf,
   @TForgeInstance.Addref,
   @TSalsa20.Release,

   @TSalsa20.DestroyKey,
   @TChaCha20.DuplicateKey,
   @TChaCha20.ExpandKey,
   @TChaCha20.SetKeyParam,
   @TChaCha20.GetKeyParam,
   @TSalsa20.GetBlockSize,
   @TBaseStreamCipher.Encrypt,
   @TBaseStreamCipher.Decrypt,
   @TBaseStreamCipher.EncryptBlock,
   @TBaseStreamCipher.EncryptBlock,
   @TBaseStreamCipher.GetRand,
   @TChaCha20.KeyBlock,
   @TBaseStreamCipher.RandCrypt,
   @TBaseStreamCipher.GetIsBlockCipher
   );

function GetSalsa20Algorithm(var A: PSalsa20): TF_RESULT;
begin
  Result:= GetSalsa20AlgorithmEx(A, 20);
end;

function GetSalsa20AlgorithmEx(var A: PSalsa20; Rounds: Integer): TF_RESULT;
var
  Tmp: PSalsa20;

begin
  if (Rounds < 1) or (Rounds > 255) or Odd(Rounds) then begin
    Result:= TF_E_INVALIDARG;
    Exit;
  end;
  try
    Tmp:= AllocMem(SizeOf(TSalsa20));
    Tmp^.FVTable:= @Salsa20VTable;
    Tmp^.FRefCount:= 1;
    Tmp^.FRounds:= Rounds shr 1;

    if A <> nil then TSalsa20.Release(A);
    A:= Tmp;
    Result:= TF_S_OK;
  except
    Result:= TF_E_OUTOFMEMORY;
  end;
end;

function GetChaCha20Algorithm(var A: PSalsa20): TF_RESULT;
begin
  Result:= GetChaCha20AlgorithmEx(A, 20);
end;

function GetChaCha20AlgorithmEx(var A: PSalsa20; Rounds: Integer): TF_RESULT;
var
  Tmp: PSalsa20;

begin
  if (Rounds < 1) or (Rounds > 255) or Odd(Rounds) then begin
    Result:= TF_E_INVALIDARG;
    Exit;
  end;
  try
    Tmp:= AllocMem(SizeOf(TSalsa20));
    Tmp^.FVTable:= @ChaCha20VTable;
    Tmp^.FRefCount:= 1;
    Tmp^.FRounds:= Rounds shr 1;

    if A <> nil then TSalsa20.Release(A);
    A:= Tmp;
    Result:= TF_S_OK;
  except
    Result:= TF_E_OUTOFMEMORY;
  end;
end;

const
                        // Sigma = 'expand 32-byte k'
  Sigma0 = $61707865;
  Sigma1 = $3320646e;
  Sigma2 = $79622d32;
  Sigma3 = $6b206574;
                        // Tau = 'expand 16-byte k'
  Tau0   = $61707865;
  Tau1   = $3120646e;
  Tau2   = $79622d36;
  Tau3   = $6b206574;

{ TSalsa20 }

procedure BurnKey(Inst: PSalsa20); inline;
var
  BurnSize: Integer;

begin
  BurnSize:= SizeOf(TSalsa20)
             - Integer(@PSalsa20(nil)^.FValidKey);
  FillChar(Inst.FValidKey, BurnSize, 0);
end;

class function TSalsa20.Release(Inst: PSalsa20): Integer;
begin
  if Inst.FRefCount > 0 then begin
    Result:= tfDecrement(Inst.FRefCount);
    if Result = 0 then begin
      BurnKey(Inst);
      FreeMem(Inst);
    end;
  end
  else
    Result:= Inst.FRefCount;
end;

class procedure TSalsa20.DestroyKey(Inst: PSalsa20);
begin
  BurnKey(Inst);
end;

procedure SalsaDoubleRound(x: TSalsa20.PBlock);
var
  y: UInt32;

begin
  y := x[ 0] + x[12]; x[ 4] := x[ 4] xor ((y shl 07) or (y shr (32-07)));
  y := x[ 4] + x[ 0]; x[ 8] := x[ 8] xor ((y shl 09) or (y shr (32-09)));
  y := x[ 8] + x[ 4]; x[12] := x[12] xor ((y shl 13) or (y shr (32-13)));
  y := x[12] + x[ 8]; x[ 0] := x[ 0] xor ((y shl 18) or (y shr (32-18)));
  y := x[ 5] + x[ 1]; x[ 9] := x[ 9] xor ((y shl 07) or (y shr (32-07)));
  y := x[ 9] + x[ 5]; x[13] := x[13] xor ((y shl 09) or (y shr (32-09)));
  y := x[13] + x[ 9]; x[ 1] := x[ 1] xor ((y shl 13) or (y shr (32-13)));
  y := x[ 1] + x[13]; x[ 5] := x[ 5] xor ((y shl 18) or (y shr (32-18)));
  y := x[10] + x[ 6]; x[14] := x[14] xor ((y shl 07) or (y shr (32-07)));
  y := x[14] + x[10]; x[ 2] := x[ 2] xor ((y shl 09) or (y shr (32-09)));
  y := x[ 2] + x[14]; x[ 6] := x[ 6] xor ((y shl 13) or (y shr (32-13)));
  y := x[ 6] + x[ 2]; x[10] := x[10] xor ((y shl 18) or (y shr (32-18)));
  y := x[15] + x[11]; x[ 3] := x[ 3] xor ((y shl 07) or (y shr (32-07)));
  y := x[ 3] + x[15]; x[ 7] := x[ 7] xor ((y shl 09) or (y shr (32-09)));
  y := x[ 7] + x[ 3]; x[11] := x[11] xor ((y shl 13) or (y shr (32-13)));
  y := x[11] + x[ 7]; x[15] := x[15] xor ((y shl 18) or (y shr (32-18)));
  y := x[ 0] + x[ 3]; x[ 1] := x[ 1] xor ((y shl 07) or (y shr (32-07)));
  y := x[ 1] + x[ 0]; x[ 2] := x[ 2] xor ((y shl 09) or (y shr (32-09)));
  y := x[ 2] + x[ 1]; x[ 3] := x[ 3] xor ((y shl 13) or (y shr (32-13)));
  y := x[ 3] + x[ 2]; x[ 0] := x[ 0] xor ((y shl 18) or (y shr (32-18)));
  y := x[ 5] + x[ 4]; x[ 6] := x[ 6] xor ((y shl 07) or (y shr (32-07)));
  y := x[ 6] + x[ 5]; x[ 7] := x[ 7] xor ((y shl 09) or (y shr (32-09)));
  y := x[ 7] + x[ 6]; x[ 4] := x[ 4] xor ((y shl 13) or (y shr (32-13)));
  y := x[ 4] + x[ 7]; x[ 5] := x[ 5] xor ((y shl 18) or (y shr (32-18)));
  y := x[10] + x[ 9]; x[11] := x[11] xor ((y shl 07) or (y shr (32-07)));
  y := x[11] + x[10]; x[ 8] := x[ 8] xor ((y shl 09) or (y shr (32-09)));
  y := x[ 8] + x[11]; x[ 9] := x[ 9] xor ((y shl 13) or (y shr (32-13)));
  y := x[ 9] + x[ 8]; x[10] := x[10] xor ((y shl 18) or (y shr (32-18)));
  y := x[15] + x[14]; x[12] := x[12] xor ((y shl 07) or (y shr (32-07)));
  y := x[12] + x[15]; x[13] := x[13] xor ((y shl 09) or (y shr (32-09)));
  y := x[13] + x[12]; x[14] := x[14] xor ((y shl 13) or (y shr (32-13)));
  y := x[14] + x[13]; x[15] := x[15] xor ((y shl 18) or (y shr (32-18)));
end;

procedure ChaChaDoubleRound(x: TSalsa20.PBlock);
var
  a, b, c, d: UInt32;

begin
  a := x[0];   b := x[4];      c := x[8];      d:= x[12];
  inc(a, b);   d := a xor d;   d := (d shl 16) or (d shr (32-16));
  inc(c, d);   b := c xor b;   b := (b shl 12) or (b shr (32-12));
  inc(a, b);   d := a xor d;   d := (d shl  8) or (d shr (32- 8));
  inc(c, d);   b := c xor b;   b := (b shl  7) or (b shr (32- 7));
  x[0] := a;   x[4] := b;      x[8] := c;      x[12] := d;

  a := x[1];   b := x[5];      c := x[9];      d := x[13];
  inc(a, b);   d := a xor d;   d := (d shl 16) or (d shr (32-16));
  inc(c, d);   b := c xor b;   b := (b shl 12) or (b shr (32-12));
  inc(a, b);   d := a xor d;   d := (d shl  8) or (d shr (32- 8));
  inc(c, d);   b := c xor b;   b := (b shl  7) or (b shr (32- 7));
  x[1] := a;   x[5] := b;      x[9] := c;      x[13] := d;

  a := x[2];   b := x[6];      c := x[10];     d := x[14];
  inc(a, b);   d := a xor d;   d := (d shl 16) or (d shr (32-16));
  inc(c, d);   b := c xor b;   b := (b shl 12) or (b shr (32-12));
  inc(a, b);   d := a xor d;   d := (d shl  8) or (d shr (32- 8));
  inc(c, d);   b := c xor b;   b := (b shl  7) or (b shr (32- 7));
  x[2] := a;   x[6] := b;      x[10] := c;     x[14] := d;

  a := x[3];   b := x[7];      c := x[11];     d := x[15];
  inc(a, b);   d := a xor d;   d := (d shl 16) or (d shr (32-16));
  inc(c, d);   b := c xor b;   b := (b shl 12) or (b shr (32-12));
  inc(a, b);   d := a xor d;   d := (d shl  8) or (d shr (32- 8));
  inc(c, d);   b := c xor b;   b := (b shl  7) or (b shr (32- 7));
  x[3] := a;   x[7] := b;      x[11] := c;     x[15] := d;

  a := x[0];   b := x[5];      c := x[10];     d := x[15];
  inc(a, b);   d := a xor d;   d := (d shl 16) or (d shr (32-16));
  inc(c, d);   b := c xor b;   b := (b shl 12) or (b shr (32-12));
  inc(a, b);   d := a xor d;   d := (d shl  8) or (d shr (32- 8));
  inc(c, d);   b := c xor b;   b := (b shl  7) or (b shr (32- 7));
  x[0] := a;   x[5] := b;      x[10] := c;     x[15] := d;

  a := x[1];   b := x[6];      c := x[11];     d := x[12];
  inc(a, b);   d := a xor d;   d := (d shl 16) or (d shr (32-16));
  inc(c, d);   b := c xor b;   b := (b shl 12) or (b shr (32-12));
  inc(a, b);   d := a xor d;   d := (d shl  8) or (d shr (32- 8));
  inc(c, d);   b := c xor b;   b := (b shl  7) or (b shr (32- 7));
  x[1] := a;   x[6] := b;      x[11] := c;     x[12] := d;

  a := x[2];   b := x[7];      c := x[8];      d := x[13];
  inc(a, b);   d := a xor d;   d := (d shl 16) or (d shr (32-16));
  inc(c, d);   b := c xor b;   b := (b shl 12) or (b shr (32-12));
  inc(a, b);   d := a xor d;   d := (d shl  8) or (d shr (32- 8));
  inc(c, d);   b := c xor b;   b := (b shl  7) or (b shr (32- 7));
  x[2] := a;   x[7] := b;      x[8] := c;      x[13] := d;

  a := x[3];   b := x[4];      c := x[9];      d := x[14];
  inc(a, b);   d := a xor d;   d := (d shl 16) or (d shr (32-16));
  inc(c, d);   b := c xor b;   b := (b shl 12) or (b shr (32-12));
  inc(a, b);   d := a xor d;   d := (d shl  8) or (d shr (32- 8));
  inc(c, d);   b := c xor b;   b := (b shl  7) or (b shr (32- 7));
  x[3] := a;   x[4] := b;      x[9] := c;      x[14] := d;
end;

class function TSalsa20.GetBlockSize(Inst: PSalsa20): Integer;
begin
  Result:= SALSA_BLOCK_SIZE;
end;

class function TSalsa20.GetKeyParam(Inst: PSalsa20; Param: UInt32; Data: Pointer;
  var DataLen: Cardinal): TF_RESULT;
begin
  if (Param = TF_KP_NONCE) then begin
    if (DataLen >= SizeOf(UInt64)) then begin
      Move(Inst.FExpandedKey[6], Data^, SizeOf(UInt64));
      DataLen:= SizeOf(UInt64);
      Result:= TF_S_OK;
      Exit;
    end
  end;
  Result:= TF_E_INVALIDARG;
end;

class function TSalsa20.KeyBlock(Inst: PSalsa20; Data: TSalsa20.PBlock): TF_RESULT;
var
  N: Cardinal;

begin
  Move(Inst.FExpandedKey, Data^, SizeOf(TBlock));
  N:= Inst.FRounds;
  repeat
    SalsaDoubleRound(Data);
    Dec(N);
  until N = 0;
  repeat
    Data[N]:= Data[N] + Inst.FExpandedKey[N];
    Inc(N);
  until N = 16;
  Inc(Inst.FExpandedKey[8]);
  if (Inst.FExpandedKey[8] = 0)
    then Inc(Inst.FExpandedKey[9]);
  Result:= TF_S_OK;
end;

class function TSalsa20.DuplicateKey(Inst: PSalsa20; var Key: PSalsa20): TF_RESULT;
begin
  Result:= GetSalsa20AlgorithmEx(Key, Inst.FRounds shl 1);
  if Result = TF_S_OK then begin
    Key.FValidKey:= Inst.FValidKey;
    Key.FExpandedKey:= Inst.FExpandedKey;
//    Key.FRounds:= Inst.FRounds;
  end;
end;

class function TSalsa20.ExpandKey(Inst: PSalsa20; Key: PByte;
  KeySize: Cardinal): TF_RESULT;
begin
  if (KeySize <> 16) and (KeySize <> 32) then begin
    Result:= TF_E_INVALIDARG;
    Exit;
  end;
  Move(Key^, Inst.FExpandedKey[1], 16);
  if KeySize = 16 then begin        // 128-bit key
    Inst.FExpandedKey[0]:= Tau0;
    Inst.FExpandedKey[5]:= Tau1;
    Inst.FExpandedKey[10]:= Tau2;
    Inst.FExpandedKey[15]:= Tau3;
    Move(Key^, Inst.FExpandedKey[11], 16);
  end
  else begin                        // 256-bit key
    Inst.FExpandedKey[0]:= Sigma0;
    Inst.FExpandedKey[5]:= Sigma1;
    Inst.FExpandedKey[10]:= Sigma2;
    Inst.FExpandedKey[15]:= Sigma3;
    Move(PByte(Key)[16], Inst.FExpandedKey[11], 16);
  end;
                                    // 64-bit block number
  Inst.FExpandedKey[8]:= 0;
  Inst.FExpandedKey[9]:= 0;
  Inst.FValidKey:= True;

  Result:= TF_S_OK;
end;

class function TSalsa20.SetKeyParam(Inst: PSalsa20; Param: UInt32;
  Data: Pointer; DataLen: Cardinal): TF_RESULT;

type
  TUInt64Rec = record
    Lo, Hi: UInt32;
  end;

var
  Tmp, Tmp1: UInt64;

begin
  if (Param = TF_KP_IV) then begin
    if (DataLen = SizeOf(UInt64)) then begin
      Move(Data^, Inst.FExpandedKey[6], SizeOf(UInt64));
                                      // 64-byte block number
      Inst.FExpandedKey[8]:= 0;
      Inst.FExpandedKey[9]:= 0;

      Result:= TF_S_OK;
      Exit;
    end;
    Result:= TF_E_INVALIDARG;
    Exit;
  end;

  if (Param = TF_KP_NONCE) then begin
    if (DataLen > 0) and (DataLen <= SizeOf(UInt64)) then begin
      Inst.FExpandedKey[6]:= 0;
      Inst.FExpandedKey[7]:= 0;
      Move(Data^, Inst.FExpandedKey[6], DataLen);
                                      // 64-byte block number
      Inst.FExpandedKey[8]:= 0;
      Inst.FExpandedKey[9]:= 0;
      Result:= TF_S_OK;
    end
    else
      Result:= TF_E_INVALIDARG;
    Exit;
  end;

  if (Param = TF_KP_INCNO) then begin
    if (DataLen > 0) and (DataLen <= SizeOf(UInt64)) then begin

// Salsa20 uses little-endian block numbers
      Tmp:= 0;
      TUInt64Rec(Tmp1).Lo:= Inst.FExpandedKey[8];
      TUInt64Rec(Tmp1).Hi:= Inst.FExpandedKey[9];

      Move(Data^, Tmp, DataLen);

      Tmp:= Tmp + Tmp1;

      Inst.FExpandedKey[8]:= TUInt64Rec(Tmp).Lo;
      Inst.FExpandedKey[9]:= TUInt64Rec(Tmp).Hi;

      Result:= TF_S_OK;
    end
    else
      Result:= TF_E_INVALIDARG;
    Exit;
  end;

  if (Param = TF_KP_DECNO) then begin
    if (DataLen > 0) and (DataLen <= SizeOf(UInt64)) then begin

// Salsa20 uses little-endian block numbers
      Tmp1:= 0;
      TUInt64Rec(Tmp).Lo:= Inst.FExpandedKey[8];
      TUInt64Rec(Tmp).Hi:= Inst.FExpandedKey[9];

      Move(Data^, Tmp1, DataLen);

      Tmp:= Tmp - Tmp1;

      Inst.FExpandedKey[8]:= TUInt64Rec(Tmp).Lo;
      Inst.FExpandedKey[9]:= TUInt64Rec(Tmp).Hi;

      Result:= TF_S_OK;
    end
    else
      Result:= TF_E_INVALIDARG;
    Exit;
  end;

  Result:= TF_E_INVALIDARG;
//    Result:= TF_E_NOTIMPL;
end;

{ TChaCha20 }

class function TChaCha20.DuplicateKey(Inst: PSalsa20;
  var Key: PSalsa20): TF_RESULT;
begin
  Result:= GetChaCha20AlgorithmEx(Key, Inst.FRounds shl 1);
  if Result = TF_S_OK then begin
    Key.FValidKey:= Inst.FValidKey;
    Key.FExpandedKey:= Inst.FExpandedKey;
//    Key.FRounds:= Inst.FRounds;
  end;
end;

class function TChaCha20.ExpandKey(Inst: PSalsa20; Key: PByte;
  KeySize: Cardinal): TF_RESULT;
begin
  if (KeySize <> 16) and (KeySize <> 32) then begin
    Result:= TF_E_INVALIDARG;
    Exit;
  end;

  if KeySize = 16 then begin        // 128-bit key
    Inst.FExpandedKey[0]:= Tau0;
    Inst.FExpandedKey[1]:= Tau1;
    Inst.FExpandedKey[2]:= Tau2;
    Inst.FExpandedKey[3]:= Tau3;
    Move(Key^, Inst.FExpandedKey[4], 16);
    Move(Key^, Inst.FExpandedKey[8], 16);
  end
  else begin                        // 256-bit key
    Inst.FExpandedKey[0]:= Sigma0;
    Inst.FExpandedKey[1]:= Sigma1;
    Inst.FExpandedKey[2]:= Sigma2;
    Inst.FExpandedKey[3]:= Sigma3;
    Move(Key^, Inst.FExpandedKey[4], 32);
  end;
                                    // 64-bit block number
  Inst.FExpandedKey[12]:= 0;
  Inst.FExpandedKey[13]:= 0;
  Inst.FValidKey:= True;

  Result:= TF_S_OK;
end;

class function TChaCha20.GetKeyParam(Inst: PSalsa20; Param: UInt32;
  Data: Pointer; var DataLen: Cardinal): TF_RESULT;
begin
  if (Param = TF_KP_NONCE) then begin
    if (DataLen >= SizeOf(UInt64)) then begin
      Move(Inst.FExpandedKey[14], Data^, SizeOf(UInt64));
      DataLen:= SizeOf(UInt64);
      Result:= TF_S_OK;
      Exit;
    end
  end;
  Result:= TF_E_INVALIDARG;
end;

class function TChaCha20.KeyBlock(Inst: PSalsa20;
  Data: TSalsa20.PBlock): TF_RESULT;
var
  N: Cardinal;

begin
  Move(Inst.FExpandedKey, Data^, SizeOf(TSalsa20.TBlock));
  N:= Inst.FRounds;
  repeat
    ChaChaDoubleRound(Data);
    Dec(N);
  until N = 0;
  repeat
    Data[N]:= Data[N] + Inst.FExpandedKey[N];
    Inc(N);
  until N = 16;
  Inc(Inst.FExpandedKey[12]);
  if (Inst.FExpandedKey[12] = 0)
    then Inc(Inst.FExpandedKey[13]);
  Result:= TF_S_OK;
end;

class function TChaCha20.SetKeyParam(Inst: PSalsa20; Param: UInt32;
  Data: Pointer; DataLen: Cardinal): TF_RESULT;
type
  TUInt64Rec = record
    Lo, Hi: UInt32;
  end;

var
  Tmp, Tmp1: UInt64;

begin
  if (Param = TF_KP_IV) then begin
    if (DataLen = SizeOf(UInt64)) then begin
      Move(Data^, Inst.FExpandedKey[14], SizeOf(UInt64));
                                      // 64-byte block number
      Inst.FExpandedKey[12]:= 0;
      Inst.FExpandedKey[13]:= 0;

      Result:= TF_S_OK;
    end
    else begin
      Result:= TF_E_INVALIDARG;
    end;
    Exit;
  end;

  if (Param = TF_KP_NONCE) then begin
    if (DataLen > 0) and (DataLen <= SizeOf(UInt64)) then begin
      Inst.FExpandedKey[14]:= 0;
      Inst.FExpandedKey[15]:= 0;
      Move(Data^, Inst.FExpandedKey[14], DataLen);
                                      // 64-byte block number
      Inst.FExpandedKey[12]:= 0;
      Inst.FExpandedKey[13]:= 0;
      Result:= TF_S_OK;
    end
    else
      Result:= TF_E_INVALIDARG;
    Exit;
  end;

  if (Param = TF_KP_INCNO) then begin
    if (DataLen > 0) and (DataLen <= SizeOf(UInt64)) then begin
// Salsa20 uses little-endian block numbers
      Tmp:= 0;
      TUInt64Rec(Tmp1).Lo:= Inst.FExpandedKey[12];
      TUInt64Rec(Tmp1).Hi:= Inst.FExpandedKey[13];

      Move(Data^, Tmp, DataLen);

      Tmp:= Tmp + Tmp1;

      Inst.FExpandedKey[12]:= TUInt64Rec(Tmp).Lo;
      Inst.FExpandedKey[13]:= TUInt64Rec(Tmp).Hi;
      Result:= TF_S_OK;
    end
    else
      Result:= TF_E_INVALIDARG;
    Exit;
  end;

  if (Param = TF_KP_DECNO) then begin
    if (DataLen > 0) and (DataLen <= SizeOf(UInt64)) then begin
// Salsa20 uses little-endian block numbers
      Tmp1:= 0;
      TUInt64Rec(Tmp).Lo:= Inst.FExpandedKey[12];
      TUInt64Rec(Tmp).Hi:= Inst.FExpandedKey[13];

      Move(Data^, Tmp1, DataLen);

      Tmp:= Tmp - Tmp1;

      Inst.FExpandedKey[12]:= TUInt64Rec(Tmp).Lo;
      Inst.FExpandedKey[13]:= TUInt64Rec(Tmp).Hi;
      Result:= TF_S_OK;
    end
    else
      Result:= TF_E_INVALIDARG;
    Exit;
  end;

  Result:= TF_E_INVALIDARG;
end;

{ TChaChaPRG }

function TChaChaPRG.Init(Seed: PByte; SeedSize: Cardinal): TF_RESULT;
begin
  if (SeedSize <> 24) and (SeedSize <> 40) then begin
    Result:= TF_E_INVALIDARG;
    Exit;
  end;

  if SeedSize = 24 then begin        // 128-bit key
    FExpandedKey[0]:= Tau0;
    FExpandedKey[1]:= Tau1;
    FExpandedKey[2]:= Tau2;
    FExpandedKey[3]:= Tau3;
    Move(Seed^, FExpandedKey[4], 16);
    Move(Seed^, FExpandedKey[8], 16);
    Move((Seed + 16)^, FExpandedKey[14], 8);
  end
  else begin                        // 256-bit key
    FExpandedKey[0]:= Sigma0;
    FExpandedKey[1]:= Sigma1;
    FExpandedKey[2]:= Sigma2;
    FExpandedKey[3]:= Sigma3;
    Move(Seed^, FExpandedKey[4], 32);
    Move((Seed + 32)^, FExpandedKey[14], 8);
  end;
                                    // 64-bit block number
  FExpandedKey[12]:= 0;
  FExpandedKey[13]:= 0;

  Result:= TF_S_OK;
end;

function TChaChaPRG.GetKeyStream(Buf: PByte; BufSize: Cardinal): TF_RESULT;
var
  N: Cardinal;

begin
// should be multiple of 64
  if BufSize and $3F <> 0 then begin
    Result:= TF_E_INVALIDARG;
    Exit;
  end;
  while BufSize > 0 do begin
    Move(FExpandedKey, Buf^, SizeOf(FExpandedKey));
    N:= 10;
    repeat
      ChaChaDoubleRound(TSalsa20.PBlock(Buf));
      Dec(N);
    until N = 0;
    repeat
      PUInt32(Buf)^:= PUInt32(Buf)^ + FExpandedKey[N];
      Inc(PUInt32(Buf));
      Inc(N);
    until N = 16;
    Inc(FExpandedKey[12]);
    if (FExpandedKey[12] = 0)
      then Inc(FExpandedKey[13]);
    Dec(BufSize, 64);
  end;
  Result:= TF_S_OK;
end;

end.
