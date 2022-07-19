{ *********************************************************** }
{ *                     TForge Library                      * }
{ *       Copyright (c) Sergey Kasandrov 1997, 2015         * }
{ *********************************************************** }

unit tfCRCs;

interface

{$I TFL.inc}

uses
  tfTypes, tfBytes, tfExceptions;

type
  TCRC = record
  private
    FGenerator: UInt64;
    FDigest: UInt64;
    FXorIn: UInt64;
    FXorOut: UInt64;
    FBitSize: Cardinal;
    FRevIn: Boolean;
    FRevOut: Boolean;
  public
    class function Init(ABitSize: Cardinal; AGenerator: UInt64;
                        AXorIn, AXorOut: UInt64; ARevIn, ARevOut: Boolean;
                        ARevGen: Boolean = False): TCRC; static;

    class function BitReverse(AValue: UInt64; ABitSize: Cardinal): UInt64; static;
    procedure Reset;
    procedure Update(const Data; DataSize: Cardinal);
    function Digest: UInt64;
    function Hash(const Data; DataSize: Cardinal): UInt64; overload;
    function Hash(const Data: ByteArray): UInt64; overload;

    property BitSize: Cardinal read FBitSize;
    property Generator: UInt64 read FGenerator;

    class function CRC16: TCRC; static;         // ANSI, IBM, ARC, ..
    class function CRC16_AUG_CCITT: TCRC; static;
    class function CRC16_XMODEM: TCRC; static;
    class function CRC32: TCRC; static;         // ANSI, Ethernet, ..
    class function CRC32C: TCRC; static;        // Castagnoli
    class function CRC32K: TCRC; static;        // Koopman
  end;

implementation

function BitReverseByte(B: Byte): Byte;
begin
  B:= ((B and $F0) shr 4) or ((B and $0F) shl 4);
  B:= ((B and $CC) shr 2) or ((B and $33) shl 2);
  B:= ((B and $AA) shr 1) or ((B and $55) shl 1);
  Result:= B;
end;

{ TCRC }

class function TCRC.BitReverse(AValue: UInt64; ABitSize: Cardinal): UInt64;
var
  Mask: UInt64;
  S: Cardinal;

begin
  Mask:= UInt64($FFFFFFFFFFFFFFFF);
  S:= 32;
  repeat
    Mask:= Mask xor (Mask shl S);
    AValue:= ((AValue shr S) and Mask) or ((AValue shl S) and not Mask);
    S:= S shr 1;
  until S = 0;
  Result:= AValue shr (64 - ABitSize);
end;

class function TCRC.Init(ABitSize: Cardinal; AGenerator: UInt64;
                         AXorIn, AXorOut: UInt64; ARevIn, ARevOut: Boolean;
                         ARevGen: Boolean): TCRC;
begin
  if (ABitSize > 64) or (ABitSize = 0) then ForgeError(TF_E_INVALIDARG);
  Result.FBitSize:= ABitSize;
  if not ARevGen
    then Result.FGenerator:= BitReverse(AGenerator, ABitSize)
    else Result.FGenerator:= AGenerator;
  if not ARevIn
    then Result.FXorIn:= BitReverse(AXorIn, ABitSize)
    else Result.FXorIn:= AXorIn;
  Result.FXorOut:= AXorOut;
  Result.FRevIn:= ARevIn;
  Result.FRevOut:= ARevOut;
  Result.Reset;
end;

procedure TCRC.Reset;
begin
  FDigest:= FXorIn;
end;

class function TCRC.CRC16: TCRC;
begin
  Result:= Init(16, $8005, 0, 0, True, True);
end;

class function TCRC.CRC16_AUG_CCITT: TCRC;
begin
  Result:= Init(16, $1021, $1D0F, 0, False, False);
end;

class function TCRC.CRC16_XMODEM: TCRC;
begin
  Result:= Init(16, $1021, 0, 0, False, False);
end;

class function TCRC.CRC32: TCRC;
begin
  Result:= Init(32, $EDB88320, $FFFFFFFF, $FFFFFFFF, True, True, True);
end;

class function TCRC.CRC32C: TCRC;
begin
  Result:= Init(32, $82F63B78, $FFFFFFFF, $FFFFFFFF, True, True, True);
end;

class function TCRC.CRC32K: TCRC;
begin
  Result:= Init(32, $EB31D82E, $FFFFFFFF, $FFFFFFFF, True, True, True);
end;

function TCRC.Digest: UInt64;
begin
  if not FRevOut then FDigest:= BitReverse(FDigest, FBitSize);
  Result:= FDigest xor FXorOut;
  Reset;
end;

procedure TCRC.Update(const Data; DataSize: Cardinal);
var
  I: Cardinal;
  P: PByte;
  B: Byte;
  Carry: Boolean;

begin
  P:= @Data;
  while DataSize > 0 do begin
    if not FRevIn
      then B:= BitReverseByte(P^)
      else B:= P^;
    PLongWord(@FDigest)^:= LongWord(FDigest) xor B;
    I:= 8;
    Inc(P);
    repeat
      Carry:= Odd(FDigest);
      FDigest:= FDigest shr 1;
      if Carry then
        FDigest:= FDigest xor FGenerator;
      Dec(I);
    until I = 0;
    Dec(DataSize);
  end;
end;

function TCRC.Hash(const Data; DataSize: Cardinal): UInt64;
begin
  Update(Data, DataSize);
  Result:= Digest;
end;

function TCRC.Hash(const Data: ByteArray): UInt64;
begin
  Result:= Hash(Data.GetRawData^, Data.GetLen);
end;

end.
