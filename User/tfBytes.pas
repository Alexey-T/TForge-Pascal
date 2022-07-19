{ *********************************************************** }
{ *                     TForge Library                      * }
{ *       Copyright (c) Sergey Kasandrov 1997, 2016         * }
{ *********************************************************** }

unit tfBytes;

{$I TFL.inc}

interface

uses SysUtils, tfTypes, tfConsts, tfExceptions,
    {$IFDEF TFL_DLL} tfImport {$ELSE} tfByteVectors {$ENDIF};

type
  ByteArray = record
  private
    FBytes: IBytes;
    function GetByte(Index: Integer): Byte;
    procedure SetByte(Index: Integer; const Value: Byte);
  public
    function IsAssigned: Boolean;
    procedure Free;

    function GetEnumerator: IBytesEnumerator;
    function GetHashCode: Integer;
    property HashCode: Integer read GetHashCode;

    function GetLen: Integer;
    procedure SetLen(Value: Integer);
    procedure SetInstanceLen(Value: Integer);
    function GetRawData: PByte;

    class function Allocate(ASize: Cardinal): ByteArray; overload; static;
    class function Allocate(ASize: Cardinal; Filler: Byte): ByteArray; overload; static;
    class function AllocateRand(ASize: Cardinal): ByteArray; static;
    procedure ReAllocate(ASize: Cardinal);
    class function FromBytes(const A: array of Byte): ByteArray; static;
    class function FromText(const S: string): ByteArray; static;
    class function FromAnsi(const S: RawByteString): ByteArray; static;
    class function FromMem(P: Pointer; Count: Cardinal): ByteArray; static;
    class function Parse(const S: string; Delimiter: Char = #0): ByteArray; static;
    class function TryParse(const S: string; var R: ByteArray): Boolean; overload; static;
    class function TryParse(const S: string; Delimiter: Char; var R: ByteArray): Boolean; overload; static;
    class function ParseHex(const S: string): ByteArray; overload; static;
    class function ParseHex(const S: string; Delimiter: Char): ByteArray; overload; static;
    class function TryParseHex(const S: string; var R: ByteArray): Boolean; overload; static;
    class function TryParseHex(const S: string; Delimiter: Char; var R: ByteArray): Boolean; overload; static;
    class function ParseBitString(const S: string; ABitLen: Integer): ByteArray; static;

    class function FromInt(const Data; DataLen: Cardinal;
                     Reversed: Boolean): ByteArray; static;

    function ToText: string;
    function ToString: string;
    function ToHex: string;

    procedure ToInt(var Data; DataLen: Cardinal; Reversed: Boolean);

    procedure Incr;
    procedure Decr;

    procedure IncrLE;
    procedure DecrLE;

    procedure Burn;
    procedure Fill(AValue: Byte);

    function Copy: ByteArray; overload;
    function Copy(I: Cardinal): ByteArray; overload;
    function Copy(I, L: Cardinal): ByteArray; overload;

    function Insert(I: Cardinal; B: Byte): ByteArray; overload;
    function Insert(I: Cardinal; const B: ByteArray): ByteArray; overload;
    function Insert(I: Cardinal; const B: TBytes): ByteArray; overload;

    function Remove(I: Cardinal): ByteArray; overload;
    function Remove(I, L: Cardinal): ByteArray; overload;

    function Reverse: ByteArray; overload;

    function TestBit(BitNo: Cardinal): Boolean;
    function SeniorBit: Integer;

    class function Concat(const A, B: ByteArray): ByteArray; static;

    class function AddBytes(const A, B: ByteArray): ByteArray; static;
    class function SubBytes(const A, B: ByteArray): ByteArray; static;
    class function AndBytes(const A, B: ByteArray): ByteArray; static;
    class function OrBytes(const A, B: ByteArray): ByteArray; static;
    class function XorBytes(const A, B: ByteArray): ByteArray; static;

    class function ShlBytes(const A: ByteArray; Shift: Cardinal): ByteArray; static;
    class function ShrBytes(const A: ByteArray; Shift: Cardinal): ByteArray; static;

    class operator Explicit(const Value: ByteArray): Byte;
    class operator Explicit(const Value: ByteArray): Word;
    class operator Explicit(const Value: ByteArray): LongWord;
    class operator Explicit(const Value: ByteArray): UInt64;

    class operator Explicit(const Value: Byte): ByteArray;
    class operator Explicit(const Value: Word): ByteArray;
    class operator Explicit(const Value: LongWord): ByteArray;
    class operator Explicit(const Value: UInt64): ByteArray;

    class operator Implicit(const Value: ByteArray): TBytes;
    class operator Implicit(const Value: TBytes): ByteArray;

    class operator Equal(const A, B: ByteArray): Boolean;
    class operator Equal(const A: ByteArray; const B: TBytes): Boolean;
    class operator Equal(const A: TBytes; const B: ByteArray): Boolean;
    class operator Equal(const A: ByteArray; const B: Byte): Boolean;
    class operator Equal(const A: Byte; const B: ByteArray): Boolean;

    class operator NotEqual(const A, B: ByteArray): Boolean;
    class operator NotEqual(const A: ByteArray; const B: TBytes): Boolean;
    class operator NotEqual(const A: TBytes; const B: ByteArray): Boolean;
    class operator NotEqual(const A: ByteArray; const B: Byte): Boolean;
    class operator NotEqual(const A: Byte; const B: ByteArray): Boolean;

    class operator Add(const A, B: ByteArray): ByteArray;
    class operator Add(const A: ByteArray; const B: TBytes): ByteArray;
    class operator Add(const A: ByteArray; const B: Byte): ByteArray;
    class operator Add(const A: TBytes; const B: ByteArray): ByteArray;
    class operator Add(const A: Byte; const B: ByteArray): ByteArray;

    class operator BitwiseAnd(const A, B: ByteArray): ByteArray;
    class operator BitwiseOr(const A, B: ByteArray): ByteArray;
    class operator BitwiseXor(const A, B: ByteArray): ByteArray;

    class operator LeftShift(const A: ByteArray; Shift: Cardinal): ByteArray;
    class operator RightShift(const A: ByteArray; Shift: Cardinal): ByteArray;

    property InstanceLen: Integer read GetLen write SetInstanceLen;
    property Len: Integer read GetLen write SetLen;
    property RawData: PByte read GetRawData;

    property Bytes[Index: Integer]: Byte read GetByte write SetByte; default;
  end;

implementation

type
  PByteArrayRec = ^TByteArrayRec;
  PPByteArrayRec = ^PByteArrayRec;
  TByteArrayRec = record
    FVTable: Pointer;
    FRefCount: Integer;
    FCapacity: Integer;         // number of bytes allocated
    FUsed: Integer;             // number of bytes used
    FData: array[0..0] of Byte;
  end;

procedure ByteArrayError(ACode: TF_RESULT; const Msg: string = '');
begin
  raise EByteArrayError.Create(ACode, Msg);
end;

procedure HResCheck(ACode: TF_RESULT); inline;
begin
  if ACode <> TF_S_OK then
    raise EByteArrayError.Create(ACode, '');
end;

{ ByteArray }

function ByteArray.GetByte(Index: Integer): Byte;
begin
  if Cardinal(Index) < Cardinal(GetLen) then
    Result:= GetRawData[Index]
  else
    raise EArgumentOutOfRangeException.CreateResFmt(@SIndexOutOfRange, [Index]);
end;

procedure ByteArray.SetByte(Index: Integer; const Value: Byte);
begin
  if Cardinal(Index) < Cardinal(GetLen) then
    GetRawData[Index]:= Value
  else
    raise EArgumentOutOfRangeException.CreateResFmt(@SIndexOutOfRange, [Index]);
end;

function ByteArray.IsAssigned: Boolean;
begin
  Result:= FBytes <> nil;
end;

procedure ByteArray.Free;
begin
  FBytes:= nil;
end;

function ByteArray.GetEnumerator: IBytesEnumerator;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(FBytes.GetEnum(Result));
{$ELSE}
  HResCheck(TByteVector.GetEnum(PByteVector(FBytes), PByteVectorEnum(Result)));
{$ENDIF}
end;

function ByteArray.GetHashCode: Integer;
begin
{$IFDEF TFL_INTFCALL}
  Result:= FBytes.GetHashCode;
{$ELSE}
  Result:= TByteVector.GetHashCode(PByteVector(FBytes));
{$ENDIF}
end;

function ByteArray.GetLen: Integer;
begin
{$IFDEF TFL_HACK}
  Result:= PPByteArrayRec(@Self)^^.FUsed;
{$ELSE}
{$IFDEF TFL_INTFCALL}
  Result:= FBytes.GetLen;
{$ELSE}
  Result:= TByteVector.GetLen(PByteVector(FBytes));
{$ENDIF}
{$ENDIF}
end;

procedure ByteArray.SetLen(Value: Integer);
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(ByteVectorSetLen(FBytes, Value));
{$ELSE}
  HResCheck(ByteVectorSetLen(PByteVector(FBytes), Value));
{$ENDIF}
end;

procedure ByteArray.SetInstanceLen(Value: Integer);
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(FBytes.SetLen(Value));
{$ELSE}
  HResCheck(TByteVector.SetLen(PByteVector(FBytes), Value));
{$ENDIF}
end;

function ByteArray.GetRawData: PByte;
begin
{$IFDEF TFL_HACK}
  Result:= @PPByteArrayRec(@Self)^^.FData;
{$ELSE}
{$IFDEF TFL_INTFCALL}
  Result:= FBytes.GetRawData;
{$ELSE}
  Result:= TByteVector.GetRawData(PByteVector(FBytes));
{$ENDIF}
{$ENDIF}
end;

function ByteArray.TestBit(BitNo: Cardinal): Boolean;
begin
{$IFDEF TFL_INTFCALL}
  Result:= FBytes.GetBitSet(BitNo);
{$ELSE}
  Result:= TByteVector.GetBitSet(PByteVector(FBytes), BitNo);
{$ENDIF}
end;

function ByteArray.SeniorBit: Integer;
begin
{$IFDEF TFL_INTFCALL}
  Result:= FBytes.GetSeniorBit;
{$ELSE}
  Result:= TByteVector.GetSeniorBit(PByteVector(FBytes));
{$ENDIF}
end;

class function ByteArray.Allocate(ASize: Cardinal): ByteArray;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(ByteVectorAlloc(Result.FBytes, ASize));
{$ELSE}
  HResCheck(ByteVectorAlloc(PByteVector(Result.FBytes), ASize));
{$ENDIF}
end;

class function ByteArray.Allocate(ASize: Cardinal; Filler: Byte): ByteArray;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(ByteVectorAllocEx(Result.FBytes, ASize, Filler));
{$ELSE}
  HResCheck(ByteVectorAllocEx(PByteVector(Result.FBytes), ASize, Filler));
{$ENDIF}
end;

class function ByteArray.AllocateRand(ASize: Cardinal): ByteArray;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(ByteVectorAllocRand(Result.FBytes, ASize));
{$ELSE}
  HResCheck(ByteVectorAllocRand(PByteVector(Result.FBytes), ASize));
{$ENDIF}
end;

procedure ByteArray.ReAllocate(ASize: Cardinal);
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(ByteVectorReAlloc(FBytes, ASize));
{$ELSE}
  HResCheck(ByteVectorReAlloc(PByteVector(FBytes), ASize));
{$ENDIF}
end;

class function ByteArray.FromText(const S: string): ByteArray;
var
  S8: UTF8String;

begin
  S8:= UTF8String(S);
{$IFDEF TFL_INTFCALL}
  HResCheck(ByteVectorFromPByte(Result.FBytes, Pointer(S8), Length(S8)));
{$ELSE}
  HResCheck(ByteVectorFromPByte(PByteVector(Result.FBytes), Pointer(S8), Length(S8)));
{$ENDIF}
  if Pointer(S8) <> Pointer(S) then begin
    FillChar(Pointer(S8)^, Length(S8), 32);
  end;
end;

class function ByteArray.FromAnsi(const S: RawByteString): ByteArray;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(ByteVectorFromPByte(Result.FBytes, Pointer(S), Length(S)));
{$ELSE}
  HResCheck(ByteVectorFromPByte(PByteVector(Result.FBytes), Pointer(S), Length(S)));
{$ENDIF}
end;

class function ByteArray.FromBytes(const A: array of Byte): ByteArray;
var
  I: Integer;
  P: PByte;

begin
  Result:= ByteArray.Allocate(Length(A));
  P:= Result.RawData;
  for I:= 0 to Length(A) - 1 do begin
    P^:= A[I];
    Inc(P);
  end;
end;

class function ByteArray.FromInt(const Data; DataLen: Cardinal;
                 Reversed: Boolean): ByteArray;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(ByteVectorFromPByteEx(Result.FBytes, @Data, DataLen, Reversed));
{$ELSE}
  HResCheck(ByteVectorFromPByteEx(PByteVector(Result.FBytes), @Data, DataLen, Reversed));
{$ENDIF}
end;

class function ByteArray.FromMem(P: Pointer; Count: Cardinal): ByteArray;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(ByteVectorFromPByte(Result.FBytes, P, Count));
{$ELSE}
  HResCheck(ByteVectorFromPByte(PByteVector(Result.FBytes), P, Count));
{$ENDIF}
end;

class function ByteArray.Parse(const S: string; Delimiter: Char): ByteArray;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(ByteVectorParse(Result.FBytes, Pointer(S), Length(S),
            SizeOf(Char), Byte(Delimiter)));
{$ELSE}
  HResCheck(ByteVectorParse(PByteVector(Result.FBytes),
            Pointer(S), Length(S), SizeOf(Char), Byte(Delimiter)));
{$ENDIF}
end;

class function ByteArray.ParseHex(const S: string): ByteArray;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(ByteVectorFromPCharHex(Result.FBytes, Pointer(S), Length(S), SizeOf(Char)));
{$ELSE}
  HResCheck(ByteVectorFromPCharHex(PByteVector(Result.FBytes),
                                   Pointer(S), Length(S), SizeOf(Char)));
{$ENDIF}
end;

class function ByteArray.ParseHex(const S: string; Delimiter: Char): ByteArray;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(ByteVectorParseHex(Result.FBytes, Pointer(S), Length(S),
            SizeOf(Char), Byte(Delimiter)));
{$ELSE}
  HResCheck(ByteVectorParseHex(PByteVector(Result.FBytes),
            Pointer(S), Length(S), SizeOf(Char), Byte(Delimiter)));
{$ENDIF}
end;

class function ByteArray.TryParseHex(const S: string; var R: ByteArray): Boolean;
begin
  Result:= (
{$IFDEF TFL_INTFCALL}
    ByteVectorFromPCharHex(R.FBytes, Pointer(S), Length(S), SizeOf(Char))
{$ELSE}
    ByteVectorFromPCharHex(PByteVector(R.FBytes),
                                   Pointer(S), Length(S), SizeOf(Char))
{$ENDIF}
      = TF_S_OK);
end;

class function ByteArray.TryParse(const S: string; var R: ByteArray): Boolean;
begin
  Result:= (
{$IFDEF TFL_INTFCALL}
    ByteVectorParse(R.FBytes, Pointer(S), Length(S),
            SizeOf(Char), 0)
{$ELSE}
    ByteVectorParse(PByteVector(R.FBytes), Pointer(S), Length(S),
            SizeOf(Char), 0)
{$ENDIF}
      = TF_S_OK);
end;

class function ByteArray.TryParse(const S: string; Delimiter: Char;
  var R: ByteArray): Boolean;
begin
  Result:= (
{$IFDEF TFL_INTFCALL}
    ByteVectorParse(R.FBytes, Pointer(S), Length(S),
            SizeOf(Char), Byte(Delimiter))
{$ELSE}
    ByteVectorParse(PByteVector(R.FBytes), Pointer(S), Length(S),
            SizeOf(Char), Byte(Delimiter))
{$ENDIF}
      = TF_S_OK);
end;

class function ByteArray.TryParseHex(const S: string; Delimiter: Char;
  var R: ByteArray): Boolean;
begin
  Result:= (
{$IFDEF TFL_INTFCALL}
    ByteVectorParseHex(R.FBytes, Pointer(S), Length(S),
            SizeOf(Char), Byte(Delimiter))
{$ELSE}
    ByteVectorParseHex(PByteVector(R.FBytes), Pointer(S), Length(S),
            SizeOf(Char), Byte(Delimiter))
{$ENDIF}
      = TF_S_OK);
end;

class function ByteArray.ParseBitString(const S: string; ABitLen: Integer): ByteArray;
var
  Ch: Char;
  I: Integer;
  Tmp: Cardinal;
  P: PByte;

begin
  if (ABitLen <= 0) or (ABitLen > 8) or (Length(S) mod ABitLen <> 0) then
    raise Exception.Create('Wrong string length');

{$IFDEF TFL_INTFCALL}
  HResCheck(ByteVectorAlloc(Result.FBytes, Length(S) div ABitLen));
{$ELSE}
  HResCheck(ByteVectorAlloc(PByteVector(Result.FBytes), Length(S) div ABitLen));
{$ENDIF}

//  SetLength(Result.FBytes, Length(S) div 7);
  P:= Result.FBytes.GetRawData;
  I:= 0;
  Tmp:= 0;
  for Ch in S do begin
    Tmp:= Tmp shl 1;
    if Ch = '1' then Tmp:= Tmp or 1
    else if Ch <> '0' then
      raise Exception.Create('Wrong string char');
    Inc(I);
    if I mod 7 = 0 then begin
//      Result.FBytes[I div 7 - 1]:= Tmp;
      P^:= Tmp;
      Inc(P);
      Tmp:= 0;
    end;
  end;
end;

class operator ByteArray.Implicit(const Value: ByteArray): TBytes;
var
  L: Integer;

begin
  Result:= nil;
{$IFDEF TFL_HACK}
  L:= PPByteArrayRec(@Value)^^.FUsed;
  if L > 0 then begin
    SetLength(Result, L);
    Move(PPByteArrayRec(@Value)^^.FData, Pointer(Result)^, L);
  end;
{$ELSE}
{$IFDEF TFL_INTFCALL}
  L:= Value.FBytes.GetLen;
  if L > 0 then begin
    SetLength(Result, L);
    Move(Value.FBytes.GetRawData^, Pointer(Result)^, L);
  end;
{$ELSE}
  L:= TByteVector.GetLen(PByteVector(Value.FBytes));
  if L > 0 then begin
    SetLength(Result, L);
    Move(TByteVector.GetRawData(PByteVector(Value.FBytes))^, Pointer(Result)^, L);
  end;
{$ENDIF}
{$ENDIF}
end;

class operator ByteArray.Implicit(const Value: TBytes): ByteArray;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(ByteVectorFromPByte(Result.FBytes, Pointer(Value), Length(Value)));
{$ELSE}
  HResCheck(ByteVectorFromPByte(PByteVector(Result.FBytes), Pointer(Value), Length(Value)));
{$ENDIF}
end;

(*
class function ByteArray.Insert(const A: ByteArray; I: Cardinal; B: Byte): ByteArray;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(A.FBytes.InsertByte(I, B, Result.FBytes));
{$ELSE}
  HResCheck(TByteVector.InsertByte(PByteVector(A.FBytes), I, B, PByteVector(Result.FBytes)));
{$ENDIF}
end;

class function ByteArray.Insert(const A: ByteArray; I: Cardinal; B: ByteArray): ByteArray;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(A.FBytes.InsertBytes(I, B.FBytes, Result.FBytes));
{$ELSE}
  HResCheck(TByteVector.InsertBytes(PByteVector(A.FBytes), I, PByteVector(B.FBytes),
                                    PByteVector(Result.FBytes)));
{$ENDIF}
end;

class function ByteArray.Insert(const A: ByteArray; I: Cardinal; B: TBytes): ByteArray;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(A.FBytes.InsertPByte(I, Pointer(B), Length(B), Result.FBytes));
{$ELSE}
  HResCheck(TByteVector.InsertPByte(PByteVector(A.FBytes), I, Pointer(B), Length(B),
                        PByteVector(Result.FBytes)));
{$ENDIF}
end;
*)

function ByteArray.Insert(I: Cardinal; B: Byte): ByteArray;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(FBytes.InsertByte(I, B, Result.FBytes));
{$ELSE}
  HResCheck(TByteVector.InsertByte(PByteVector(FBytes), I, B, PByteVector(Result.FBytes)));
{$ENDIF}
end;

function ByteArray.Insert(I: Cardinal; const B: ByteArray): ByteArray;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(FBytes.InsertBytes(I, B.FBytes, Result.FBytes));
{$ELSE}
  HResCheck(TByteVector.InsertBytes(PByteVector(FBytes), I, PByteVector(B.FBytes),
                                    PByteVector(Result.FBytes)));
{$ENDIF}
end;

function ByteArray.Insert(I: Cardinal; const B: TBytes): ByteArray;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(FBytes.InsertPByte(I, Pointer(B), Length(B), Result.FBytes));
{$ELSE}
  HResCheck(TByteVector.InsertPByte(PByteVector(FBytes), I, Pointer(B), Length(B),
                        PByteVector(Result.FBytes)));
{$ENDIF}
end;

procedure ByteArray.Burn;
begin
{$IFDEF TFL_INTFCALL}
  FBytes.Burn;
{$ELSE}
  TByteVector.Burn(PByteVector(FBytes));
{$ENDIF}
end;

procedure ByteArray.Fill(AValue: Byte);
begin
{$IFDEF TFL_INTFCALL}
  FBytes.Fill(AValue);
{$ELSE}
  TByteVector.Fill(PByteVector(FBytes), AValue);
{$ENDIF}
end;

procedure ByteArray.Incr;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(FBytes.Incr);
{$ELSE}
  HResCheck(TByteVector.Incr(PByteVector(FBytes)));
{$ENDIF}
end;

procedure ByteArray.IncrLE;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(FBytes.IncrLE);
{$ELSE}
  HResCheck(TByteVector.IncrLE(PByteVector(FBytes)));
{$ENDIF}
end;

procedure ByteArray.Decr;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(FBytes.Decr);
{$ELSE}
  HResCheck(TByteVector.Decr(PByteVector(FBytes)));
{$ENDIF}
end;

procedure ByteArray.DecrLE;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(FBytes.DecrLE);
{$ELSE}
  HResCheck(TByteVector.DecrLE(PByteVector(FBytes)));
{$ENDIF}
end;

function ByteArray.Remove(I: Cardinal): ByteArray;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(FBytes.RemoveBytes1(Result.FBytes), I);
{$ELSE}
  HResCheck(TByteVector.RemoveBytes1(PByteVector(FBytes),
                                     PByteVector(Result.FBytes), I));
{$ENDIF}
end;

function ByteArray.Remove(I, L: Cardinal): ByteArray;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(FBytes.RemoveBytes2(Result.FBytes, I, L));
{$ELSE}
  HResCheck(TByteVector.RemoveBytes2(PByteVector(FBytes),
                        PByteVector(Result.FBytes), I, L));
{$ENDIF}
end;

function ByteArray.Reverse: ByteArray;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(FBytes.ReverseBytes(Result.FBytes));
{$ELSE}
  HResCheck(TByteVector.ReverseBytes(PByteVector(FBytes),
                                     PByteVector(Result.FBytes)));
{$ENDIF}
end;

{$WARNINGS OFF}
class operator ByteArray.Explicit(const Value: ByteArray): Byte;
var
  L: Integer;

begin
  L:= Value.GetLen;
  if L >= 1 then
    Result:= PByte(Value.GetRawData)[L-1]
  else
    ByteArrayError(TF_E_INVALIDARG);
end;
{$WARNINGS ON}

class operator ByteArray.Explicit(const Value: ByteArray): Word;
var
  L: Integer;
  P: PByte;

begin
  L:= Value.GetLen;
  if L = 1 then begin
    Result:= 0;
    WordRec(Result).Lo:= PByte(Value.GetRawData)^;
  end
  else if L >= 2 then begin
    P:= Value.GetRawData;
    WordRec(Result).Lo:= P[L-1];
    WordRec(Result).Hi:= P[L-2];
  end
  else
    ByteArrayError(TF_E_INVALIDARG);
end;

class operator ByteArray.Explicit(const Value: ByteArray): LongWord;
var
  L: Integer;
  P, PR: PByte;

begin
  L:= Value.GetLen;
  if (L > 0) then begin
    Result:= 0;
    P:= Value.GetRawData;
    Inc(P, L);
    if (L > SizeOf(LongWord)) then L:= SizeOf(LongWord);
    PR:= @Result;
    repeat
      Dec(P);
      PR^:= P^;
      Inc(PR);
      Dec(L);
    until L = 0;
  end
  else
    ByteArrayError(TF_E_INVALIDARG);
end;

class operator ByteArray.Explicit(const Value: ByteArray): UInt64;
var
  L: Integer;
  P, PR: PByte;

begin
  L:= Value.GetLen;
  if (L > 0) then begin
    Result:= 0;
    P:= Value.GetRawData;
    Inc(P, L);
    if (L > SizeOf(UInt64)) then L:= SizeOf(UInt64);
    PR:= @Result;
    repeat
      Dec(P);
      PR^:= P^;
      Inc(PR);
      Dec(L);
    until L = 0;
  end
  else
    ByteArrayError(TF_E_INVALIDARG);
end;

class operator ByteArray.Explicit(const Value: Byte): ByteArray;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(ByteVectorFromByte(Result.FBytes, Value));
{$ELSE}
  HResCheck(ByteVectorFromByte(PByteVector(Result.FBytes), Value));
{$ENDIF}
end;

class operator ByteArray.Explicit(const Value: Word): ByteArray;
var
  P: PByte;

begin
  if Value >= 256 then begin
    Result:= ByteArray.Allocate(SizeOf(Word));
    P:= Result.RawData;
    P[0]:= WordRec(Value).Hi;
    P[1]:= WordRec(Value).Lo;
  end
  else begin
    Result:= ByteArray.Allocate(SizeOf(Byte));
    P:= Result.RawData;
    P[0]:= WordRec(Value).Lo;
  end;
end;

class operator ByteArray.Explicit(const Value: LongWord): ByteArray;
var
  P, P1: PByte;
  L: Integer;

begin
  L:= SizeOf(LongWord);
  P1:= @Value;
  Inc(P1, SizeOf(LongWord) - 1);
  while (P1^ = 0) do begin
    Dec(L);
    Dec(P1);
    if L = 1 then Break;
  end;
  Result:= ByteArray.Allocate(L);
  P:= Result.RawData;
  repeat
    P^:= P1^;
    Inc(P);
    Dec(P1);
    Dec(L);
  until L = 0;
end;

class operator ByteArray.Explicit(const Value: UInt64): ByteArray;
var
  P, P1: PByte;
  L: Integer;

begin
  L:= SizeOf(UInt64);
  P1:= @Value;
  Inc(P1, SizeOf(UInt64) - 1);
  while (P1^ = 0) do begin
    Dec(L);
    Dec(P1);
    if L = 1 then Break;
  end;
  Result:= ByteArray.Allocate(L);
  P:= Result.RawData;
  repeat
    P^:= P1^;
    Inc(P);
    Dec(P1);
    Dec(L);
  until L = 0;
end;

procedure ByteArray.ToInt(var Data; DataLen: Cardinal; Reversed: Boolean);
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(FBytes.ToInt(@Data, DataLen, Reversed));
{$ELSE}
  HResCheck(TByteVector.ToInt(PByteVector(FBytes), @Data, DataLen, Reversed));
{$ENDIF}
end;

function ByteArray.ToHex: string;
const
  ASCII_0 = Ord('0');
  ASCII_A = Ord('A');

var
  L: Integer;
  P: PByte;
  B: Byte;
  PS: PChar;

begin
  L:= GetLen;
  SetLength(Result, 2 * L);
  P:= GetRawData;
  PS:= PChar(Result);
  while L > 0 do begin
    B:= P^ shr 4;
    if B < 10 then
      PS^:= Char(B + ASCII_0)
    else
      PS^:= Char(B - 10 + ASCII_A);
    Inc(PS);
    B:= P^ and $0F;
    if B < 10 then
      PS^:= Char(B + ASCII_0)
    else
      PS^:= Char(B - 10 + ASCII_A);
    Inc(PS);
    Inc(P);
    Dec(L);
  end;
end;

function ByteArray.ToString: string;
var
  Tmp: IBytes;
  L, N: Integer;
  P: PByte;
  P1: PChar;

begin
  Result:= '';
  L:= GetLen;
  if L = 0 then Exit;
{$IFDEF TFL_INTFCALL}
  HResCheck(FBytes.ToDec(Tmp));
{$ELSE}
  HResCheck(TByteVector.ToDec(PByteVector(FBytes), PByteVector(Tmp)));
{$ENDIF}
  P:= Tmp.GetRawData;
  N:= Tmp.GetLen;
  SetLength(Result, N);
  P1:= PChar(Result);
  repeat
    if P^ <> 0 then begin
      P1^:= Char(P^);
    end
    else begin
      P1^:= Char($20); // space
    end;
    Inc(P);
    Inc(P1);
    Dec(N);
  until N = 0;
end;

function ByteArray.ToText: string;
var
  S8: UTF8String;
  L: Integer;

begin
  if FBytes = nil then Result:= ''
  else begin
    L:= FBytes.GetLen;
    SetLength(S8, L);
    Move(FBytes.GetRawData^, Pointer(S8)^, L);
    Result:= string(S8);
    if Pointer(S8) <> Pointer(Result) then
      FillChar(Pointer(S8)^, Length(S8), 32);
  end;
end;

class operator ByteArray.Add(const A, B: ByteArray): ByteArray;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(A.FBytes.ConcatBytes(B.FBytes, Result.FBytes));
{$ELSE}
  HResCheck(TByteVector.ConcatBytes(PByteVector(A.FBytes),
            PByteVector(B.FBytes), PByteVector(Result.FBytes)));
{$ENDIF}
end;

class operator ByteArray.Add(const A: ByteArray; const B: TBytes): ByteArray;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(A.FBytes.AppendPByte(Pointer(B), Length(B), Result.FBytes));
{$ELSE}
  HResCheck(TByteVector.AppendPByte(PByteVector(A.FBytes),
            Pointer(B), Length(B), PByteVector(Result.FBytes)));
{$ENDIF}
end;

class operator ByteArray.Add(const A: TBytes; const B: ByteArray): ByteArray;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(B.FBytes.InsertPByte(0, Pointer(A), Length(A), Result.FBytes));
{$ELSE}
  HResCheck(TByteVector.InsertPByte(PByteVector(B.FBytes), 0,
            Pointer(A), Length(A), PByteVector(Result.FBytes)));
{$ENDIF}
end;

class operator ByteArray.Add(const A: ByteArray; const B: Byte): ByteArray;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(A.FBytes.AppendByte(B, Result.FBytes));
{$ELSE}
  HResCheck(TByteVector.AppendByte(PByteVector(A.FBytes),
            B, PByteVector(Result.FBytes)));
{$ENDIF}
end;

class operator ByteArray.Add(const A: Byte; const B: ByteArray): ByteArray;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(B.FBytes.InsertByte(0, A, Result.FBytes));
{$ELSE}
  HResCheck(TByteVector.InsertByte(PByteVector(B.FBytes), 0,
            A, PByteVector(Result.FBytes)));
{$ENDIF}
end;

class function ByteArray.AddBytes(const A, B: ByteArray): ByteArray;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(A.FBytes.AddBytes(B.FBytes, Result.FBytes));
{$ELSE}
  HResCheck(TByteVector.AddBytes(PByteVector(A.FBytes),
            PByteVector(B.FBytes), PByteVector(Result.FBytes)));
{$ENDIF}
end;

class function ByteArray.SubBytes(const A, B: ByteArray): ByteArray;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(A.FBytes.SubBytes(B.FBytes, Result.FBytes));
{$ELSE}
  HResCheck(TByteVector.SubBytes(PByteVector(A.FBytes),
            PByteVector(B.FBytes), PByteVector(Result.FBytes)));
{$ENDIF}
end;

class function ByteArray.AndBytes(const A, B: ByteArray): ByteArray;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(A.FBytes.AndBytes(B.FBytes, Result.FBytes));
{$ELSE}
  HResCheck(TByteVector.AndBytes(PByteVector(A.FBytes),
            PByteVector(B.FBytes), PByteVector(Result.FBytes)));
{$ENDIF}
end;

class function ByteArray.OrBytes(const A, B: ByteArray): ByteArray;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(A.FBytes.OrBytes(B.FBytes, Result.FBytes));
{$ELSE}
  HResCheck(TByteVector.OrBytes(PByteVector(A.FBytes),
            PByteVector(B.FBytes), PByteVector(Result.FBytes)));
{$ENDIF}
end;

class function ByteArray.XorBytes(const A, B: ByteArray): ByteArray;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(A.FBytes.XorBytes(B.FBytes, Result.FBytes));
{$ELSE}
  HResCheck(TByteVector.XorBytes(PByteVector(A.FBytes),
            PByteVector(B.FBytes), PByteVector(Result.FBytes)));
{$ENDIF}
end;

class operator ByteArray.BitwiseAnd(const A, B: ByteArray): ByteArray;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(A.FBytes.AndBytes(B.FBytes, Result.FBytes));
{$ELSE}
  HResCheck(TByteVector.AndBytes(PByteVector(A.FBytes),
            PByteVector(B.FBytes), PByteVector(Result.FBytes)));
{$ENDIF}
end;

class operator ByteArray.BitwiseOr(const A, B: ByteArray): ByteArray;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(A.FBytes.OrBytes(B.FBytes, Result.FBytes));
{$ELSE}
  HResCheck(TByteVector.OrBytes(PByteVector(A.FBytes),
            PByteVector(B.FBytes), PByteVector(Result.FBytes)));
{$ENDIF}
end;

class operator ByteArray.BitwiseXor(const A, B: ByteArray): ByteArray;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(A.FBytes.XorBytes(B.FBytes, Result.FBytes));
{$ELSE}
  HResCheck(TByteVector.XorBytes(PByteVector(A.FBytes),
            PByteVector(B.FBytes), PByteVector(Result.FBytes)));
{$ENDIF}
end;

class function ByteArray.ShlBytes(const A: ByteArray;
  Shift: Cardinal): ByteArray;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(A.FBytes.ShiftLeft(Shift, Result.FBytes));
{$ELSE}
  HResCheck(TByteVector.ShiftLeft(PByteVector(A.FBytes), Shift,
                       PByteVector(Result.FBytes)));
{$ENDIF}
end;

class function ByteArray.ShrBytes(const A: ByteArray;
  Shift: Cardinal): ByteArray;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(A.FBytes.ShiftRight(Shift, Result.FBytes));
{$ELSE}
  HResCheck(TByteVector.ShiftRight(PByteVector(A.FBytes), Shift,
                       PByteVector(Result.FBytes)));
{$ENDIF}
end;

class operator ByteArray.LeftShift(const A: ByteArray;
  Shift: Cardinal): ByteArray;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(A.FBytes.ShiftLeft(Shift, Result.FBytes));
{$ELSE}
  HResCheck(TByteVector.ShiftLeft(PByteVector(A.FBytes), Shift,
                       PByteVector(Result.FBytes)));
{$ENDIF}
end;

class operator ByteArray.RightShift(const A: ByteArray;
  Shift: Cardinal): ByteArray;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(A.FBytes.ShiftRight(Shift, Result.FBytes));
{$ELSE}
  HResCheck(TByteVector.ShiftRight(PByteVector(A.FBytes), Shift,
                       PByteVector(Result.FBytes)));
{$ENDIF}
end;

class operator ByteArray.Equal(const A, B: ByteArray): Boolean;
begin
{$IFDEF TFL_INTFCALL}
  Result:= A.FBytes.EqualBytes(B.FBytes);
{$ELSE}
  Result:= TByteVector.EqualBytes(PByteVector(A.FBytes), PByteVector(B.FBytes));
{$ENDIF}
end;

class operator ByteArray.Equal(const A: ByteArray; const B: TBytes): Boolean;
begin
{$IFDEF TFL_INTFCALL}
  Result:= A.FBytes.EqualToPByte(Pointer(B), Length(B));
{$ELSE}
  Result:= TByteVector.EqualToPByte(PByteVector(A.FBytes), Pointer(B), Length(B));
{$ENDIF}
end;

class operator ByteArray.Equal(const A: TBytes; const B: ByteArray): Boolean;
begin
{$IFDEF TFL_INTFCALL}
  Result:= B.FBytes.EqualToPByte(Pointer(A), Length(A));
{$ELSE}
  Result:= TByteVector.EqualToPByte(PByteVector(B.FBytes), Pointer(A), Length(A));
{$ENDIF}
end;

class operator ByteArray.Equal(const A: ByteArray; const B: Byte): Boolean;
begin
{$IFDEF TFL_INTFCALL}
  Result:= A.FBytes.EqualToByte(B);
{$ELSE}
  Result:= TByteVector.EqualToByte(PByteVector(A.FBytes), B);
{$ENDIF}
end;

class operator ByteArray.Equal(const A: Byte; const B: ByteArray): Boolean;
begin
{$IFDEF TFL_INTFCALL}
  Result:= B.FBytes.EqualToByte(A);
{$ELSE}
  Result:= TByteVector.EqualToByte(PByteVector(B.FBytes), A);
{$ENDIF}
end;

class operator ByteArray.NotEqual(const A, B: ByteArray): Boolean;
begin
{$IFDEF TFL_INTFCALL}
  Result:= not A.FBytes.EqualBytes(B.FBytes);
{$ELSE}
  Result:= not TByteVector.EqualBytes(PByteVector(A.FBytes), PByteVector(B.FBytes));
{$ENDIF}
end;

class operator ByteArray.NotEqual(const A: ByteArray; const B: TBytes): Boolean;
begin
{$IFDEF TFL_INTFCALL}
  Result:= not A.FBytes.EqualToPByte(Pointer(B), Length(B));
{$ELSE}
  Result:= not TByteVector.EqualToPByte(PByteVector(A.FBytes), Pointer(B), Length(B));
{$ENDIF}
end;

class operator ByteArray.NotEqual(const A: TBytes; const B: ByteArray): Boolean;
begin
{$IFDEF TFL_INTFCALL}
  Result:= not B.FBytes.EqualToPByte(Pointer(A), Length(A));
{$ELSE}
  Result:= not TByteVector.EqualToPByte(PByteVector(B.FBytes), Pointer(A), Length(A));
{$ENDIF}
end;

class operator ByteArray.NotEqual(const A: ByteArray; const B: Byte): Boolean;
begin
{$IFDEF TFL_INTFCALL}
  Result:= not A.FBytes.EqualToByte(B);
{$ELSE}
  Result:= not TByteVector.EqualToByte(PByteVector(A.FBytes), B);
{$ENDIF}
end;

class operator ByteArray.NotEqual(const A: Byte; const B: ByteArray): Boolean;
begin
{$IFDEF TFL_INTFCALL}
  Result:= not B.FBytes.EqualToByte(A);
{$ELSE}
  Result:= not TByteVector.EqualToByte(PByteVector(B.FBytes), A);
{$ENDIF}
end;

class function ByteArray.Concat(const A, B: ByteArray): ByteArray;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(A.FBytes.ConcatBytes(B.FBytes, Result.FBytes));
{$ELSE}
  HResCheck(TByteVector.ConcatBytes(PByteVector(A.FBytes), PByteVector(B.FBytes),
                                    PByteVector(Result.FBytes)));
{$ENDIF}
end;

function ByteArray.Copy: ByteArray;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(FBytes.CopyBytes(Result.FBytes));
{$ELSE}
  HResCheck(TByteVector.CopyBytes(PByteVector(FBytes),
                                  PByteVector(Result.FBytes)));
{$ENDIF}
end;

function ByteArray.Copy(I: Cardinal): ByteArray;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(FBytes.CopyBytes1(Result.FBytes), I);
{$ELSE}
  HResCheck(TByteVector.CopyBytes1(PByteVector(FBytes),
                                   PByteVector(Result.FBytes), I));
{$ENDIF}
end;

function ByteArray.Copy(I, L: Cardinal): ByteArray;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(FBytes.CopyBytes2(Result.FBytes, I, L));
{$ELSE}
  HResCheck(TByteVector.CopyBytes2(PByteVector(FBytes),
                                   PByteVector(Result.FBytes), I, L));
{$ENDIF}
end;

end.
