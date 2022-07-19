{ *********************************************************** }
{ *                     TForge Library                      * }
{ *       Copyright (c) Sergey Kasandrov 1997, 2016         * }
{ *********************************************************** }

unit tfRC5;

{$I TFL.inc}
{$POINTERMATH ON}

interface

uses
  tfTypes;

type
  PRC5Algorithm = ^TRC5Algorithm;
  TRC5Algorithm = record
  private const
    MAX_ROUNDS = 255;
    MAX_KEYLEN = 255;

  private type
    PRC5Block = ^TRC5Block;
    TRC5Block = record
      case Byte of
        0: (Word16: array[0..1] of Word);
        1: (Word32: array[0..1] of UInt32);
        2: (Word64: array[0..1] of UInt64);
    end;

    TDummy = array[0..0] of UInt64;     // to ensure 64-bit alignment

  private
{$HINTS OFF}                    // -- inherited fields begin --
                                // from tfRecord
    FVTable:   Pointer;
    FRefCount: Integer;
                                // from tfBlockCipher
    FValidKey: Boolean;
    FDir:      UInt32;
    FMode:     UInt32;
    FPadding:  UInt32;
    FIVector:  TRC5Block;       // -- inherited fields end --
{$HINTS ON}
    FBlockSize: Cardinal;       // 4, 8, 16
    FRounds: Cardinal;          // 0..255

    FSubKeys: TDummy;

  public
    class function Release(Inst: PRC5Algorithm): Integer; stdcall; static;
    class function ExpandKey32(Inst: PRC5Algorithm; Key: PByte; KeySize: Cardinal): TF_RESULT;
          {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function ExpandKey64(Inst: PRC5Algorithm; Key: PByte; KeySize: Cardinal): TF_RESULT;
          {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function ExpandKey128(Inst: PRC5Algorithm; Key: PByte; KeySize: Cardinal): TF_RESULT;
          {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function GetBlockSize(Inst: PRC5Algorithm): Integer;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function DuplicateKey(Inst: PRC5Algorithm; var Key: PRC5Algorithm): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class procedure DestroyKey(Inst: PRC5Algorithm);{$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function EncryptBlock32(Inst: PRC5Algorithm; Data: PByte): TF_RESULT;
          {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function EncryptBlock64(Inst: PRC5Algorithm; Data: PByte): TF_RESULT;
          {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function EncryptBlock128(Inst: PRC5Algorithm; Data: PByte): TF_RESULT;
          {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function DecryptBlock32(Inst: PRC5Algorithm; Data: PByte): TF_RESULT;
          {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function DecryptBlock64(Inst: PRC5Algorithm; Data: PByte): TF_RESULT;
          {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function DecryptBlock128(Inst: PRC5Algorithm; Data: PByte): TF_RESULT;
          {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
  end;

function GetRC5Algorithm(var A: PRC5Algorithm): TF_RESULT;
function GetRC5AlgorithmEx(var A: PRC5Algorithm; BlockSize, Rounds: Integer): TF_RESULT;

implementation

uses tfRecords, tfBaseCiphers;

//const
//  MAX_BLOCK_SIZE = 16;  // 16 bytes = 128 bits

const
  RC5VTable32: array[0..16] of Pointer = (
   @TForgeInstance.QueryIntf,
   @TForgeInstance.Addref,
   @TRC5Algorithm.Release,

   @TRC5Algorithm.DestroyKey,
   @TRC5Algorithm.DuplicateKey,
   @TRC5Algorithm.ExpandKey32,
   @TBaseBlockCipher.SetKeyParam,
   @TBaseBlockCipher.GetKeyParam,
   @TRC5Algorithm.GetBlockSize,
   @TBaseBlockCipher.Encrypt,
   @TBaseBlockCipher.Decrypt,
   @TRC5Algorithm.EncryptBlock32,
   @TRC5Algorithm.DecryptBlock32,
   @TBaseBlockCipher.GetRand,
   @TBaseBlockCipher.RandBlock,
   @TBaseBlockCipher.RandCrypt,
   @TBaseBlockCipher.GetIsBlockCipher
   );

  RC5VTable64: array[0..16] of Pointer = (
   @TForgeInstance.QueryIntf,
   @TForgeInstance.Addref,
   @TRC5Algorithm.Release,

   @TRC5Algorithm.DestroyKey,
   @TRC5Algorithm.DuplicateKey,
   @TRC5Algorithm.ExpandKey64,
   @TBaseBlockCipher.SetKeyParam,
   @TBaseBlockCipher.GetKeyParam,
   @TRC5Algorithm.GetBlockSize,
   @TBaseBlockCipher.Encrypt,
   @TBaseBlockCipher.Decrypt,
   @TRC5Algorithm.EncryptBlock64,
   @TRC5Algorithm.DecryptBlock64,
   @TBaseBlockCipher.GetRand,
   @TBaseBlockCipher.RandBlock,
   @TBaseBlockCipher.RandCrypt,
   @TBaseBlockCipher.GetIsBlockCipher
   );

  RC5VTable128: array[0..16] of Pointer = (
   @TForgeInstance.QueryIntf,
   @TForgeInstance.Addref,
   @TRC5Algorithm.Release,

   @TRC5Algorithm.DestroyKey,
   @TRC5Algorithm.DuplicateKey,
   @TRC5Algorithm.ExpandKey128,
   @TBaseBlockCipher.SetKeyParam,
   @TBaseBlockCipher.GetKeyParam,
   @TRC5Algorithm.GetBlockSize,
   @TBaseBlockCipher.Encrypt,
   @TBaseBlockCipher.Decrypt,
   @TRC5Algorithm.EncryptBlock128,
   @TRC5Algorithm.DecryptBlock128,
   @TBaseBlockCipher.GetRand,
   @TBaseBlockCipher.RandBlock,
   @TBaseBlockCipher.RandCrypt,
   @TBaseBlockCipher.GetIsBlockCipher
   );

procedure BurnKey(Inst: PRC5Algorithm); inline;
var
  BurnSize: Integer;
  TmpBlockSize: Integer;
  TmpRounds: Integer;

begin
//  if Inst.FSubKeys <> nil then begin
//    FillChar(Inst.FSubKeys^, (Inst.FRounds + 1) * Inst.FBlockSize, 0);
//    FreeMem(Inst.FSubKeys);
//  end;
  TmpBlockSize:= Inst.FBlockSize;
  TmpRounds:= Inst.FRounds;
  BurnSize:= SizeOf(TRC5Algorithm)
             - SizeOf(TRC5Algorithm.TDummy)
             + (TmpRounds + 1) * TmpBlockSize
             - Integer(@PRC5Algorithm(nil)^.FValidKey);
//  BurnSize:= Integer(@PRC5Algorithm(nil)^.FSubKeys)
//           - Integer(@PRC5Algorithm(nil)^.FValidKey);
  FillChar(Inst.FValidKey, BurnSize, 0);
  Inst.FBlockSize:= TmpBlockSize;
  Inst.FRounds:= TmpRounds;
//  if Inst.FSubKeys <> nil then begin
//    FillChar(Inst.FSubKeys.GetRawData^, Inst.FSubKeys.GetLen, 0);
//  end;
end;

class function TRC5Algorithm.Release(Inst: PRC5Algorithm): Integer;
begin
  if Inst.FRefCount > 0 then begin
    Result:= tfDecrement(Inst.FRefCount);
    if Result = 0 then begin
      BurnKey(Inst);
//      if Inst.FSubKeys <> nil then Inst.FSubKeys._Release;
      FreeMem(Inst);
    end;
  end
  else
    Result:= Inst.FRefCount;
end;

function GetRC5Algorithm(var A: PRC5Algorithm): TF_RESULT;
begin
  Result:= GetRC5AlgorithmEx(A,   // "standard" RC5:
                             8,   //   64-bit block (8 bytes)
                             12   //   12 rounds
                              );
end;

function GetRC5AlgorithmEx(var A: PRC5Algorithm; BlockSize, Rounds: Integer): TF_RESULT;
var
  Tmp: PRC5Algorithm;

begin
  if ((BlockSize <> 4) and (BlockSize <> 8) and (BlockSize <> 16))
       or (Rounds < 1) or (Rounds > 255)
    then begin
      Result:= TF_E_INVALIDARG;
      Exit;
    end;
//  BlockSize:= BlockSize shr 3;
  try
    Tmp:= AllocMem(SizeOf(TRC5Algorithm)
                   - SizeOf(TRC5Algorithm.TDummy)
                   + (Rounds + 1) * BlockSize);
    case BlockSize of
      4: Tmp^.FVTable:= @RC5VTable32;
      8: Tmp^.FVTable:= @RC5VTable64;
     16: Tmp^.FVTable:= @RC5VTable128;
    end;
    Tmp^.FRefCount:= 1;
    Tmp^.FBlockSize:= BlockSize;
    Tmp^.FRounds:= Rounds;

    if A <> nil then TRC5Algorithm.Release(A);
    A:= Tmp;
    Result:= TF_S_OK;
  except
    Result:= TF_E_OUTOFMEMORY;
  end;
end;

class procedure TRC5Algorithm.DestroyKey(Inst: PRC5Algorithm);
begin
  BurnKey(Inst);
end;

class function TRC5Algorithm.DuplicateKey(Inst: PRC5Algorithm;
  var Key: PRC5Algorithm): TF_RESULT;
begin
  Result:= GetRC5AlgorithmEx(Key, Inst.FBlockSize, Inst.FRounds);
  if Result = TF_S_OK then begin
    Key.FValidKey:= Inst.FValidKey;
    Key.FDir:= Inst.FDir;
    Key.FMode:= Inst.FMode;
    Key.FPadding:= Inst.FPadding;
    Key.FIVector:= Inst.FIVector;
    Key.FRounds:= Inst.FRounds;
    Key.FBlockSize:= Inst.FBlockSize;
//    Result:= Key.FSubKeys.CopyBytes(Inst.FSubKeys);
    Move(Inst.FSubKeys, Key.FSubKeys, (Inst.FRounds + 1) * Inst.FBlockSize);
  end;
end;

function Rol16(Value: Word; Shift: Cardinal): Word; inline;
begin
  Result:= (Value shl Shift) or (Value shr (16 - Shift));
end;

function Rol32(Value: UInt32; Shift: Cardinal): UInt32; inline;
begin
  Result:= (Value shl Shift) or (Value shr (32 - Shift));
end;

function Rol64(Value: UInt64; Shift: Cardinal): UInt64; inline;
begin
  Result:= (Value shl Shift) or (Value shr (64 - Shift));
end;

function Ror16(Value: Word; Shift: Cardinal): Word; inline;
begin
  Result:= (Value shr Shift) or (Value shl (16 - Shift));
end;

function Ror32(Value: UInt32; Shift: Cardinal): UInt32; inline;
begin
  Result:= (Value shr Shift) or (Value shl (32 - Shift));
end;

function Ror64(Value: UInt64; Shift: Cardinal): UInt64; inline;
begin
  Result:= (Value shr Shift) or (Value shl (64 - Shift));
end;

class function TRC5Algorithm.EncryptBlock32(Inst: PRC5Algorithm; Data: PByte): TF_RESULT;
type
  PRC5Word = ^RC5Word;
  RC5Word = Word;

var
  A, B: RC5Word;
  S: PRC5Word;
  I: Integer;

begin
  S:= @Inst.FSubKeys;
  A:= PRC5Word(Data)[0] + S^;
  Inc(S);
  B:= PRC5Word(Data)[1] + S^;
  I:= Inst.FRounds;
  repeat
    Inc(S);
    A:= Rol16(A xor B, B) + S^;
    Inc(S);
    B:= Rol16(B xor A, A) + S^;
    Dec(I);
  until I = 0;
  PRC5Word(Data)[0]:= A;
  PRC5Word(Data)[1]:= B;

  Result:= TF_S_OK;
end;

class function TRC5Algorithm.EncryptBlock64(Inst: PRC5Algorithm; Data: PByte): TF_RESULT;
type
  PRC5Word = ^RC5Word;
  RC5Word = UInt32;

var
  A, B: RC5Word;
  S: PRC5Word;
  I: Integer;

begin
  S:= @Inst.FSubKeys;
  A:= PRC5Word(Data)[0] + S^;
  Inc(S);
  B:= PRC5Word(Data)[1] + S^;
  I:= Inst.FRounds;
  repeat
    Inc(S);
    A:= Rol32(A xor B, B) + S^;
    Inc(S);
    B:= Rol32(B xor A, A) + S^;
    Dec(I);
  until I = 0;
  PRC5Word(Data)[0]:= A;
  PRC5Word(Data)[1]:= B;

  Result:= TF_S_OK;
end;

class function TRC5Algorithm.EncryptBlock128(Inst: PRC5Algorithm; Data: PByte): TF_RESULT;
type
  PRC5Word = ^RC5Word;
  RC5Word = UInt64;

var
  A, B: RC5Word;
  S: PRC5Word;
  I: Integer;

begin
  S:= @Inst.FSubKeys;
  A:= PRC5Word(Data)[0] + S^;
  Inc(S);
  B:= PRC5Word(Data)[1] + S^;
  I:= Inst.FRounds;
  repeat
    Inc(S);
    A:= Rol64(A xor B, B) + S^;
    Inc(S);
    B:= Rol64(B xor A, A) + S^;
    Dec(I);
  until I = 0;
  PRC5Word(Data)[0]:= A;
  PRC5Word(Data)[1]:= B;

  Result:= TF_S_OK;
end;

class function TRC5Algorithm.DecryptBlock32(Inst: PRC5Algorithm; Data: PByte): TF_RESULT;
type
  PRC5Word = ^RC5Word;
  RC5Word = Word;

var
  A, B: RC5Word;
  S: PRC5Word;
  I: Integer;

begin
  A:= PRC5Word(Data)[0];
  B:= PRC5Word(Data)[1];

  I:= Inst.FRounds;
  S:= PRC5Word(@Inst.FSubKeys) + 2 * Inst.FRounds + 1;
  repeat
    B:= Ror16(B - S^, A) xor A;
    Dec(S);
    A:= Ror16(A - S^, B) xor B;
    Dec(S);
    Dec(I);
  until I = 0;

  PRC5Word(Data)[1]:= B - S^;
  Dec(S);
  PRC5Word(Data)[0]:= A - S^;

  Result:= TF_S_OK;
end;

class function TRC5Algorithm.DecryptBlock64(Inst: PRC5Algorithm; Data: PByte): TF_RESULT;
type
  PRC5Word = ^RC5Word;
  RC5Word = UInt32;

var
  A, B: RC5Word;
  S: PRC5Word;
  I: Integer;

begin
  A:= PRC5Word(Data)[0];
  B:= PRC5Word(Data)[1];

  I:= Inst.FRounds;
  S:= PRC5Word(@Inst.FSubKeys) + 2 * Inst.FRounds + 1;
  repeat
    B:= Ror32(B - S^, A) xor A;
    Dec(S);
    A:= Ror32(A - S^, B) xor B;
    Dec(S);
    Dec(I);
  until I = 0;

  PRC5Word(Data)[1]:= B - S^;
  Dec(S);
  PRC5Word(Data)[0]:= A - S^;

  Result:= TF_S_OK;
end;

class function TRC5Algorithm.DecryptBlock128(Inst: PRC5Algorithm; Data: PByte): TF_RESULT;
type
  PRC5Word = ^RC5Word;
  RC5Word = UInt64;

var
  A, B: RC5Word;
  S: PRC5Word;
  I: Integer;

begin
  A:= PRC5Word(Data)[0];
  B:= PRC5Word(Data)[1];

  I:= Inst.FRounds;
  S:= PRC5Word(@Inst.FSubKeys) + 2 * Inst.FRounds + 1;
  repeat
    B:= Ror64(B - S^, A) xor A;
    Dec(S);
    A:= Ror64(A - S^, B) xor B;
    Dec(S);
    Dec(I);
  until I = 0;

  PRC5Word(Data)[1]:= B - S^;
  Dec(S);
  PRC5Word(Data)[0]:= A - S^;

  Result:= TF_S_OK;
end;

class function TRC5Algorithm.ExpandKey32(Inst: PRC5Algorithm; Key: PByte;
  KeySize: Cardinal): TF_RESULT;

type
  RC5Word = Word;         // RC5 "word" size = 2 bytes
  PWArray = ^TWArray;
  TWArray = array[0..$FFFF] of RC5Word;

const
  Pw = $B7E1;
  Qw = $9E37;
  kShift = 1;

var
  L: array[0..(256 div SizeOf(RC5Word) - 1)] of RC5Word;
  S: PWArray;
  LLen: Integer;
  T: Integer;
  I, J, N: Integer;
  X, Y: RC5Word;
  NSteps: Integer;

begin
  if (KeySize > 255) then begin
    Result:= TF_E_INVALIDARG;
    Exit;
  end;

// Convert secret key from bytes to RC5 words, K[0..KLen-1] --> L[0..LLen-1]
  LLen:= (KeySize + SizeOf(RC5Word) - 1) shr kShift;
  FillChar(L, LLen * SizeOf(RC5Word), 0);
  Move(Key^, L, KeySize);

  S:= @Inst.FSubKeys;
// Initialize the array of subkeys, FSubKeys[0..T-1]
  T:= 2 * (Inst.FRounds + 1);
  S^[0]:= Pw;
  for I:= 1 to T - 1 do
    S^[I]:= S^[I-1] + Qw;

// Mix in the secret key
  if LLen > T
    then NSteps:= 3 * LLen
    else NSteps:= 3 * T;

  X:= 0; Y:= 0; I:= 0; J:= 0;
  for N:= 0 to NSteps - 1 do begin
    S^[I]:= Rol16((S^[I] + X + Y), 3);
    X:= S^[I];
    L[J]:= Rol16((L[J] + X + Y), (X + Y) and $1F);
    Y:= L[J];
    I:= (I + 1) mod T;
    J:= (J + 1) mod LLen;
  end;

  FillChar(L, LLen * SizeOf(RC5Word), 0);
  Inst.FValidKey:= True;
  Result:= TF_S_OK;
end;

class function TRC5Algorithm.ExpandKey64(Inst: PRC5Algorithm; Key: PByte;
  KeySize: Cardinal): TF_RESULT;

type
  RC5Word = UInt32;     // RC5 "word" size = 4 bytes
  PWArray = ^TWArray;
  TWArray = array[0..$FFFF] of RC5Word;

const
  Pw = $B7E15163;
  Qw = $9E3779B9;
  kShift = 2;

var
  L: array[0..(256 div SizeOf(RC5Word) - 1)] of RC5Word;
  S: PWArray;
  LLen: Integer;
  T: Integer;
  I, J, N: Integer;
  X, Y: RC5Word;
  NSteps: Integer;

begin
  if (KeySize > 255) then begin
    Result:= TF_E_INVALIDARG;
    Exit;
  end;

// Convert secret key from bytes to RC5 words, K[0..KLen-1] --> L[0..LLen-1]
  LLen:= (KeySize + SizeOf(RC5Word) - 1) shr kShift;
  FillChar(L, LLen * SizeOf(RC5Word), 0);
  Move(Key^, L, KeySize);

  S:= @Inst.FSubKeys;
// Initialize the array of subkeys, FSubKeys[0..T-1]
  T:= 2 * (Inst.FRounds + 1);
  S^[0]:= Pw;
  for I:= 1 to T - 1 do
    S^[I]:= S^[I-1] + Qw;

// Mix in the secret key
  if LLen > T
    then NSteps:= 3 * LLen
    else NSteps:= 3 * T;

  X:= 0; Y:= 0; I:= 0; J:= 0;
  for N:= 0 to NSteps - 1 do begin
    S^[I]:= Rol32((S^[I] + X + Y), 3);
    X:= S^[I];
    L[J]:= Rol32((L[J] + X + Y), (X + Y) and $1F);
    Y:= L[J];
    I:= (I + 1) mod T;
    J:= (J + 1) mod LLen;
  end;

  FillChar(L, LLen * SizeOf(RC5Word), 0);
  Inst.FValidKey:= True;
  Result:= TF_S_OK;
end;

class function TRC5Algorithm.ExpandKey128(Inst: PRC5Algorithm; Key: PByte;
  KeySize: Cardinal): TF_RESULT;
type
  RC5Word = UInt64;       // RC5 "word" size = 8 bytes
  PWArray = ^TWArray;
  TWArray = array[0..$FFFF] of RC5Word;

const
  Pw = $B7E151628AED2A6B;
  Qw = $9E3779B97F4A7C15;
  kShift = 3;

var
  L: array[0..(256 div SizeOf(RC5Word) - 1)] of RC5Word;
  S: PWArray;
  LLen: Integer;
  T: Integer;
  I, J, N: Integer;
  X, Y: RC5Word;
  NSteps: Integer;

begin
  if (KeySize > 255) then begin
    Result:= TF_E_INVALIDARG;
    Exit;
  end;

// Convert secret key from bytes to RC5 words, K[0..KLen-1] --> L[0..LLen-1]
  LLen:= (KeySize + SizeOf(RC5Word) - 1) shr kShift;
  FillChar(L, LLen * SizeOf(RC5Word), 0);
  Move(Key^, L, KeySize);

  S:= @Inst.FSubKeys;
// Initialize the array of subkeys, FSubKeys[0..T-1]
  T:= 2 * (Inst.FRounds + 1);
  S^[0]:= Pw;
  for I:= 1 to T - 1 do
    S^[I]:= S^[I-1] + Qw;

// Mix in the secret key
  if LLen > T
    then NSteps:= 3 * LLen
    else NSteps:= 3 * T;

  X:= 0; Y:= 0; I:= 0; J:= 0;
  for N:= 0 to NSteps - 1 do begin
    S^[I]:= Rol64((S^[I] + X + Y), 3);
    X:= S^[I];
    L[J]:= Rol64((L[J] + X + Y), (X + Y) and $1F);
    Y:= L[J];
    I:= (I + 1) mod T;
    J:= (J + 1) mod LLen;
  end;

  FillChar(L, LLen * SizeOf(RC5Word), 0);
  Inst.FValidKey:= True;
  Result:= TF_S_OK;
end;

class function TRC5Algorithm.GetBlockSize(Inst: PRC5Algorithm): Integer;
begin
  Result:= Inst.FBlockSize;
end;

end.
