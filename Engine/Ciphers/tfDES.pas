{ *********************************************************** }
{ *                     TForge Library                      * }
{ *       Copyright (c) Sergey Kasandrov 1997, 2016         * }
{ *********************************************************** }

unit tfDES;

{$I TFL.inc}

interface

uses
  tfTypes;

type
  PDESAlgorithm = ^TDESAlgorithm;
  TDESAlgorithm = record
  private const
    MaxRounds = 14;

  private type
    PDESBlock = ^TDESBlock;
    TDESBlock = record
      case Byte of
        0: (Bytes: array[0..7] of Byte);
        1: (LWords: array[0..1] of UInt32);
    end;

    PExpandedKey = ^TExpandedKey;
    TExpandedKey = array[0..31] of UInt32;

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
    FIVector:  TDESBlock;       // -- inherited fields end --
{$HINTS ON}

    FSubKeys:  TExpandedKey;

    class procedure DoExpandKey(Key: PByte; var SubKeys: TExpandedKey; Encryption: Boolean); static;
    class procedure DoEncryptBlock(var SubKeys: TExpandedKey; Data: PByte); static;
  public
    class function Release(Inst: PDESAlgorithm): Integer; stdcall; static;
    class function ExpandKey(Inst: PDESAlgorithm; Key: PByte; KeySize: Cardinal): TF_RESULT;
          {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function GetBlockSize(Inst: PDESAlgorithm): Integer;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function DuplicateKey(Inst: PDESAlgorithm; var Key: PDESAlgorithm): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class procedure DestroyKey(Inst: PDESAlgorithm);{$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function EncryptBlock(Inst: PDESAlgorithm; Data: PByte): TF_RESULT;
          {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;

//    class function DecryptBlock(Inst: PDESAlgorithm; Data: PByte);
//          {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
  end;

  P3DESAlgorithm = ^T3DESAlgorithm;
  T3DESAlgorithm = record
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
    FIVector:  TDESAlgorithm.TDESBlock;       // -- inherited fields end --
{$HINTS ON}

    FSubKeys:  array[0..2] of TDESAlgorithm.TExpandedKey;

  public
    class function Release(Inst: P3DESAlgorithm): Integer; stdcall; static;
    class function ExpandKey(Inst: P3DESAlgorithm; Key: PByte; KeySize: Cardinal): TF_RESULT;
          {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
//    class function GetBlockSize(Inst: P3DESAlgorithm): Integer;
//      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function DuplicateKey(Inst: P3DESAlgorithm; var Key: P3DESAlgorithm): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class procedure DestroyKey(Inst: P3DESAlgorithm);{$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function EncryptBlock(Inst: P3DESAlgorithm; Data: PByte): TF_RESULT;
          {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;

//    class function DecryptBlock(Inst: P3DESAlgorithm; Data: PByte);
//          {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
  end;

function GetDESAlgorithm(var A: PDESAlgorithm): TF_RESULT;
function Get3DESAlgorithm(var A: P3DESAlgorithm): TF_RESULT;

implementation

uses tfRecords, tfBaseCiphers;

const
  DES_BLOCK_SIZE = 8;  // 8 bytes = 64 bits

{ TDESCipher }

const
  DESCipherVTable: array[0..16] of Pointer = (
   @TForgeInstance.QueryIntf,
   @TForgeInstance.Addref,
   @TDESAlgorithm.Release,

   @TDESAlgorithm.DestroyKey,
   @TDESAlgorithm.DuplicateKey,
   @TDESAlgorithm.ExpandKey,
   @TBaseBlockCipher.SetKeyParam,
   @TBaseBlockCipher.GetKeyParam,
   @TDESAlgorithm.GetBlockSize,
   @TBaseBlockCipher.Encrypt,
   @TBaseBlockCipher.Decrypt,
   @TDESAlgorithm.EncryptBlock,
   @TDESAlgorithm.EncryptBlock,
   @TBaseBlockCipher.GetRand,
   @TBaseBlockCipher.RandBlock,
   @TBaseBlockCipher.RandCrypt,
   @TBaseBlockCipher.GetIsBlockCipher
   );

  TripleDESVTable: array[0..16] of Pointer = (
   @TForgeInstance.QueryIntf,
   @TForgeInstance.Addref,
   @T3DESAlgorithm.Release,

   @T3DESAlgorithm.DestroyKey,
   @T3DESAlgorithm.DuplicateKey,
   @T3DESAlgorithm.ExpandKey,
   @TBaseBlockCipher.SetKeyParam,
   @TBaseBlockCipher.GetKeyParam,
   @TDESAlgorithm.GetBlockSize,
   @TBaseBlockCipher.Encrypt,
   @TBaseBlockCipher.Decrypt,
   @T3DESAlgorithm.EncryptBlock,
   @T3DESAlgorithm.EncryptBlock,
   @TBaseBlockCipher.GetRand,
   @TBaseBlockCipher.RandBlock,
   @TBaseBlockCipher.RandCrypt,
   @TBaseBlockCipher.GetIsBlockCipher
   );

procedure BurnDESKey(Inst: PDESAlgorithm); inline;
var
  BurnSize: Integer;

begin
  BurnSize:= SizeOf(TDESAlgorithm) - Integer(@PDESAlgorithm(nil)^.FValidKey);
  FillChar(Inst.FValidKey, BurnSize, 0);
end;

procedure Burn3DESKey(Inst: P3DESAlgorithm); inline;
var
  BurnSize: Integer;

begin
  BurnSize:= SizeOf(T3DESAlgorithm) - Integer(@P3DESAlgorithm(nil)^.FValidKey);
  FillChar(Inst.FValidKey, BurnSize, 0);
end;

class function TDESAlgorithm.Release(Inst: PDESAlgorithm): Integer;
begin
  if Inst.FRefCount > 0 then begin
    Result:= tfDecrement(Inst.FRefCount);
    if Result = 0 then begin
      BurnDESKey(Inst);
      FreeMem(Inst);
    end;
  end
  else
    Result:= Inst.FRefCount;
end;

class function T3DESAlgorithm.Release(Inst: P3DESAlgorithm): Integer;
begin
  if Inst.FRefCount > 0 then begin
    Result:= tfDecrement(Inst.FRefCount);
    if Result = 0 then begin
      Burn3DESKey(Inst);
      FreeMem(Inst);
    end;
  end
  else
    Result:= Inst.FRefCount;
end;

function GetDESAlgorithm(var A: PDESAlgorithm): TF_RESULT;
var
  Tmp: PDESAlgorithm;
begin
  try
    Tmp:= AllocMem(SizeOf(TDESAlgorithm));
    Tmp^.FVTable:= @DESCipherVTable;
    Tmp^.FRefCount:= 1;
//    Tmp^.FMode:= TF_KEYMODE_CBC;
//    Tmp^.FPadding:= TF_PADDING_DEFAULT;
    if A <> nil then TDESAlgorithm.Release(A);
    A:= Tmp;
    Result:= TF_S_OK;
  except
    Result:= TF_E_OUTOFMEMORY;
  end;
end;

function Get3DESAlgorithm(var A: P3DESAlgorithm): TF_RESULT;
var
  Tmp: P3DESAlgorithm;
begin
  try
    Tmp:= AllocMem(SizeOf(T3DESAlgorithm));
    Tmp^.FVTable:= @TripleDESVTable;
    Tmp^.FRefCount:= 1;
//    Tmp^.FMode:= TF_KEYMODE_CBC;
//    Tmp^.FPadding:= TF_PADDING_DEFAULT;
    if A <> nil then T3DESAlgorithm.Release(A);
    A:= Tmp;
    Result:= TF_S_OK;
  except
    Result:= TF_E_OUTOFMEMORY;
  end;
end;


// 8-byte key is expected
class procedure TDESAlgorithm.DoExpandKey(Key: PByte; var SubKeys: TExpandedKey; Encryption: Boolean);
const
  PC1        : array [0..55] of Byte =
    (56, 48, 40, 32, 24, 16, 8, 0, 57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26,
     18, 10, 2, 59, 51, 43, 35, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21,
     13, 5, 60, 52, 44, 36, 28, 20, 12, 4, 27, 19, 11, 3);
  PC2        : array [0..47] of Byte =
    (13, 16, 10, 23, 0, 4, 2, 27, 14, 5, 20, 9, 22, 18, 11, 3, 25, 7,
     15, 6, 26, 19, 12, 1, 40, 51, 30, 36, 46, 54, 29, 39, 50, 44, 32, 47,
     43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31);
  CTotRot    : array [0..15] of Byte = (1, 2, 4, 6, 8, 10, 12, 14, 15, 17, 19, 21, 23, 25, 27, 28);
  CBitMask   : array [0..7] of Byte = (128, 64, 32, 16, 8, 4, 2, 1);

var
  PC1M       : array [0..55] of Byte;
  PC1R       : array [0..55] of Byte;
  KS         : array [0..7] of Byte;
  I, J, L, M : Int32;

begin
  {convert PC1 to bits of key}
  for J := 0 to 55 do begin
    L := PC1[J];
    M := L mod 8;
    PC1M[J] := Ord((Key[L div 8] and CBitMask[M]) <> 0);
  end;

  {key chunk for each iteration}
  for I := 0 to 15 do begin
    {rotate PC1 the right amount}
    for J := 0 to 27 do begin
      L := J + CTotRot[I];
      if (L < 28) then begin
        PC1R[J] := PC1M[L];
        PC1R[J + 28] := PC1M[L + 28];
      end else begin
        PC1R[J] := PC1M[L - 28];
        PC1R[J + 28] := PC1M[L];
      end;
    end;

    {select bits individually}
    FillChar(KS, SizeOf(KS), 0);
    for J := 0 to 47 do
      if Boolean(PC1R[PC2[J]]) then begin
        L := J div 6;
        KS[L] := KS[L] or CBitMask[J mod 6] shr 2;
      end;

    {now convert to odd/even interleaved form for use in F}
    if Encryption then begin
      SubKeys[I * 2] := (Int32(KS[0]) shl 24) or (Int32(KS[2]) shl 16) or
        (Int32(KS[4]) shl 8) or (Int32(KS[6]));
      SubKeys[I * 2 + 1] := (Int32(KS[1]) shl 24) or (Int32(KS[3]) shl 16) or
        (Int32(KS[5]) shl 8) or (Int32(KS[7]));
    end
    else begin
      SubKeys[31 - (I * 2 + 1)] := (Int32(KS[0]) shl 24) or (Int32(KS[2]) shl 16) or
        (Int32(KS[4]) shl 8) or (Int32(KS[6]));
      SubKeys[31 - (I * 2)] := (Int32(KS[1]) shl 24) or (Int32(KS[3]) shl 16) or
        (Int32(KS[5]) shl 8) or (Int32(KS[7]));
    end;
  end;
end;

class function TDESAlgorithm.ExpandKey(Inst: PDESAlgorithm; Key: PByte; KeySize: Cardinal): TF_RESULT;
var
  Encryption: Boolean;

begin
  if KeySize <> 8 then begin
    Result:= TF_E_INVALIDARG;
    Exit;
  end;

  if (Inst.FDir <> TF_KEYDIR_ENCRYPT) and (Inst.FDir <> TF_KEYDIR_DECRYPT) then begin
    Result:= TF_E_UNEXPECTED;
    Exit;
  end;

  Encryption:= (Inst.FDir = TF_KEYDIR_ENCRYPT) or (Inst.FMode = TF_KEYMODE_CTR);

  DoExpandKey(Key, Inst.FSubKeys, Encryption);

  Inst.FValidKey:= True;
  Result:= TF_S_OK;
end;

class function T3DESAlgorithm.ExpandKey(Inst: P3DESAlgorithm; Key: PByte; KeySize: Cardinal): TF_RESULT;
//var
//  Encryption: Boolean;

begin
  if (KeySize <> 8) and (KeySize <> 16) and (KeySize <> 24) then begin
    Result:= TF_E_INVALIDARG;
    Exit;
  end;

  if (Inst.FDir <> TF_KEYDIR_ENCRYPT) and (Inst.FDir <> TF_KEYDIR_DECRYPT) then begin
    Result:= TF_E_UNEXPECTED;
    Exit;
  end;

  if (Inst.FDir = TF_KEYDIR_ENCRYPT) or (Inst.FMode = TF_KEYMODE_CTR) then begin
    TDESAlgorithm.DoExpandKey(Key, Inst.FSubKeys[0], True);

    if KeySize > 8 then
      TDESAlgorithm.DoExpandKey(Key + 8, Inst.FSubKeys[1], False)
    else
      TDESAlgorithm.DoExpandKey(Key, Inst.FSubKeys[1], False);

    if KeySize > 16 then
      TDESAlgorithm.DoExpandKey(Key + 16, Inst.FSubKeys[2], True)
    else
      TDESAlgorithm.DoExpandKey(Key, Inst.FSubKeys[2], True);
  end
  else begin
    if KeySize > 16 then
      TDESAlgorithm.DoExpandKey(Key + 16, Inst.FSubKeys[0], False)
    else
      TDESAlgorithm.DoExpandKey(Key, Inst.FSubKeys[0], False);

    if KeySize > 8 then
      TDESAlgorithm.DoExpandKey(Key + 8, Inst.FSubKeys[1], True)
    else
      TDESAlgorithm.DoExpandKey(Key, Inst.FSubKeys[1], True);

    TDESAlgorithm.DoExpandKey(Key, Inst.FSubKeys[2], False);
  end;

  Inst.FValidKey:= True;
  Result:= TF_S_OK;
end;

class function TDESAlgorithm.GetBlockSize(Inst: PDESAlgorithm): Integer;
begin
  Result:= DES_BLOCK_SIZE;
end;

const
  SPBox: array[0..7,0..63] of UInt32 = ({$I DES_SPBoxes.inc});

procedure SplitBlock(Block: PByte; var L, R: UInt32);
{$IFDEF ASM86}
asm
        PUSH    EBX
        PUSH    EAX
        MOV     EAX,[EAX]
        MOV     BH,AL
        MOV     BL,AH
        ROL     EBX,16      // Block.Bytes[0] --> L.Bytes[3]
        SHR     EAX,16      // Block.Bytes[1] --> L.Bytes[2]
        MOV     BH,AL       // Block.Bytes[2] --> L.Bytes[1]
        MOV     BL,AH       // Block.Bytes[3] --> L.Bytes[0]
        MOV     [EDX],EBX
        POP     EAX
        MOV     EAX,[EAX+4]
        MOV     BH,AL
        MOV     BL,AH
        ROL     EBX,16      // Block.Bytes[4] --> R.Bytes[3]
        SHR     EAX,16      // Block.Bytes[5] --> R.Bytes[2]
        MOV     BH,AL       // Block.Bytes[6] --> R.Bytes[1]
        MOV     BL,AH       // Block.Bytes[7] --> R.Bytes[0]
        MOV     [ECX],EBX
        POP     EBX
end;
{$ELSE}
var
  P: PByte;

begin
  P:= PByte(@L) + 3;
  P^:= Block^; Inc(Block); Dec(P);
  P^:= Block^; Inc(Block); Dec(P);
  P^:= Block^; Inc(Block); Dec(P);
  P^:= Block^; Inc(Block);
  P:= PByte(@R) + 3;
  P^:= Block^; Inc(Block); Dec(P);
  P^:= Block^; Inc(Block); Dec(P);
  P^:= Block^; Inc(Block); Dec(P);
  P^:= Block^;
end;
{$ENDIF}

procedure JoinBlock(const L, R: UInt32; Block: PByte);
{$IFDEF ASM86}
asm
        PUSH    EBX
        MOV     BH,AL
        MOV     BL,AH
        ROL     EBX,16      // L.Bytes[0] --> Block.Bytes[7]
        SHR     EAX,16      // L.Bytes[1] --> Block.Bytes[6]
        MOV     BH,AL       // L.Bytes[2] --> Block.Bytes[5]
        MOV     BL,AH       // L.Bytes[3] --> Block.Bytes[4]
        MOV     [ECX+4],EBX
        MOV     BH,DL
        MOV     BL,DH
        ROL     EBX,16      // R.Bytes[0] --> Block.Bytes[3]
        SHR     EDX,16      // R.Bytes[1] --> Block.Bytes[2]
        MOV     BH,DL       // R.Bytes[2] --> Block.Bytes[1]
        MOV     BL,DH       // R.Bytes[3] --> Block.Bytes[0]
        MOV     [ECX],EBX
        POP     EBX
end;
{$ELSE}
var
  P: PByte;

begin
  P:= PByte(@R) + 3;
  Block^:= P^; Inc(Block); Dec(P);
  Block^:= P^; Inc(Block); Dec(P);
  Block^:= P^; Inc(Block); Dec(P);
  Block^:= P^; Inc(Block);
  P:= PByte(@L) + 3;
  Block^:= P^; Inc(Block); Dec(P);
  Block^:= P^; Inc(Block); Dec(P);
  Block^:= P^; Inc(Block); Dec(P);
  Block^:= P^;
end;
{$ENDIF}

  procedure IPerm(var L, R : UInt32);
  var
    Work : UInt32;
  begin
    Work := ((L shr 4) xor R) and $0F0F0F0F;
    R := R xor Work;
    L := L xor Work shl 4;

    Work := ((L shr 16) xor R) and $0000FFFF;
    R := R xor Work;
    L := L xor Work shl 16;

    Work := ((R shr 2) xor L) and $33333333;
    L := L xor Work;
    R := R xor Work shl 2;

    Work := ((R shr 8) xor L) and $00FF00FF;
    L := L xor Work;
    R := R xor Work shl 8;

    R := (R shl 1) or (R shr 31);
    Work := (L xor R) and $AAAAAAAA;
    L := L xor Work;
    R := R xor Work;
    L := (L shl 1) or (L shr 31);
  end;

  procedure FPerm(var L, R : UInt32);
  var
    Work : UInt32;
  begin
    L := L;

    R := (R shl 31) or (R shr 1);
    Work := (L xor R) and $AAAAAAAA;
    L := L xor Work;
    R := R xor Work;
    L := (L shr 1) or (L shl 31);

    Work := ((L shr 8) xor R) and $00FF00FF;
    R := R xor Work;
    L := L xor Work shl 8;

    Work := ((L shr 2) xor R) and $33333333;
    R := R xor Work;
    L := L xor Work shl 2;

    Work := ((R shr 16) xor L) and $0000FFFF;
    L := L xor Work;
    R := R xor Work shl 16;

    Work := ((R shr 4) xor L) and $0F0F0F0F;
    L := L xor Work;
    R := R xor Work shl 4;
  end;

class procedure TDESAlgorithm.DestroyKey(Inst: PDESAlgorithm);
begin
  BurnDESKey(Inst);
end;

class procedure T3DESAlgorithm.DestroyKey(Inst: P3DESAlgorithm);
begin
  Burn3DESKey(Inst);
end;

class function TDESAlgorithm.DuplicateKey(Inst: PDESAlgorithm;
  var Key: PDESAlgorithm): TF_RESULT;
begin
  Result:= GetDESAlgorithm(Key);
  if Result = TF_S_OK then begin
    Key.FValidKey:= Inst.FValidKey;
    Key.FDir:= Inst.FDir;
    Key.FMode:= Inst.FMode;
    Key.FPadding:= Inst.FPadding;
    Key.FIVector:= Inst.FIVector;
    Key.FSubKeys:= Inst.FSubKeys;
  end;
end;

class function T3DESAlgorithm.DuplicateKey(Inst: P3DESAlgorithm;
  var Key: P3DESAlgorithm): TF_RESULT;
begin
  Result:= Get3DESAlgorithm(Key);
  if Result = TF_S_OK then begin
    Key.FValidKey:= Inst.FValidKey;
    Key.FDir:= Inst.FDir;
    Key.FMode:= Inst.FMode;
    Key.FPadding:= Inst.FPadding;
    Key.FIVector:= Inst.FIVector;
    Key.FSubKeys:= Inst.FSubKeys;
  end;
end;

class procedure TDESAlgorithm.DoEncryptBlock(var SubKeys: TExpandedKey;
                  Data: PByte);
var
  I, L, R, Work : UInt32;
  CPtr          : PUInt32;

begin
  SplitBlock(Data, L, R);
  IPerm(L, R);

  CPtr := @SubKeys;
  for I := 0 to 7 do begin
    Work := (((R shr 4) or (R shl 28)) xor CPtr^);
    Inc(CPtr);
    L := L xor SPBox[6, Work and $3F];
    L := L xor SPBox[4, Work shr 8 and $3F];
    L := L xor SPBox[2, Work shr 16 and $3F];
    L := L xor SPBox[0, Work shr 24 and $3F];

    Work := (R xor CPtr^);
    Inc(CPtr);
    L := L xor SPBox[7, Work and $3F];
    L := L xor SPBox[5, Work shr 8 and $3F];
    L := L xor SPBox[3, Work shr 16 and $3F];
    L := L xor SPBox[1, Work shr 24 and $3F];

    Work := (((L shr 4) or (L shl 28)) xor CPtr^);
    Inc(CPtr);
    R := R xor SPBox[6, Work and $3F];
    R := R xor SPBox[4, Work shr 8 and $3F];
    R := R xor SPBox[2, Work shr 16 and $3F];
    R := R xor SPBox[0, Work shr 24 and $3F];

    Work := (L xor CPtr^);
    Inc(CPtr);
    R := R xor SPBox[7, Work and $3F];
    R := R xor SPBox[5, Work shr 8 and $3F];
    R := R xor SPBox[3, Work shr 16 and $3F];
    R := R xor SPBox[1, Work shr 24 and $3F];
  end;

  FPerm(L, R);
  JoinBlock(L, R, Data);
end;

class function T3DESAlgorithm.EncryptBlock(Inst: P3DESAlgorithm; Data: PByte): TF_RESULT;
begin
  TDESAlgorithm.DoEncryptBlock(Inst.FSubKeys[0], Data);
  TDESAlgorithm.DoEncryptBlock(Inst.FSubKeys[1], Data);
  TDESAlgorithm.DoEncryptBlock(Inst.FSubKeys[2], Data);
  Result:= TF_S_OK;
end;

class function TDESAlgorithm.EncryptBlock(Inst: PDESAlgorithm; Data: PByte): TF_RESULT;
var
  I, L, R, Work : UInt32;
  CPtr          : PUInt32;

begin
  SplitBlock(Data, L, R);
  IPerm(L, R);

  CPtr := @Inst.FSubKeys;
  for I := 0 to 7 do begin
    Work := (((R shr 4) or (R shl 28)) xor CPtr^);
    Inc(CPtr);
    L := L xor SPBox[6, Work and $3F];
    L := L xor SPBox[4, Work shr 8 and $3F];
    L := L xor SPBox[2, Work shr 16 and $3F];
    L := L xor SPBox[0, Work shr 24 and $3F];

    Work := (R xor CPtr^);
    Inc(CPtr);
    L := L xor SPBox[7, Work and $3F];
    L := L xor SPBox[5, Work shr 8 and $3F];
    L := L xor SPBox[3, Work shr 16 and $3F];
    L := L xor SPBox[1, Work shr 24 and $3F];

    Work := (((L shr 4) or (L shl 28)) xor CPtr^);
    Inc(CPtr);
    R := R xor SPBox[6, Work and $3F];
    R := R xor SPBox[4, Work shr 8 and $3F];
    R := R xor SPBox[2, Work shr 16 and $3F];
    R := R xor SPBox[0, Work shr 24 and $3F];

    Work := (L xor CPtr^);
    Inc(CPtr);
    R := R xor SPBox[7, Work and $3F];
    R := R xor SPBox[5, Work shr 8 and $3F];
    R := R xor SPBox[3, Work shr 16 and $3F];
    R := R xor SPBox[1, Work shr 24 and $3F];
  end;

  FPerm(L, R);
  JoinBlock(L, R, Data);
  Result:= TF_S_OK;
end;

end.
