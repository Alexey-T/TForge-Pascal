{ *********************************************************** }
{ *                     TForge Library                      * }
{ *       Copyright (c) Sergey Kasandrov 1997, 2016         * }
{ *********************************************************** }

unit tfSHA1;

{$I TFL.inc}

{$IFDEF TFL_CPUX86_WIN32}
  {$DEFINE CPUX86_WIN32}
{$ENDIF}

{$IFDEF TFL_CPUX64_WIN64}
  {$DEFINE CPUX64_WIN64}
{$ENDIF}

interface

uses tfTypes;

type
  PSHA1Alg = ^TSHA1Alg;
  TSHA1Alg = record
  private type
    TData = record
      Digest: TSHA1Digest;
      Block: array[0..63] of Byte;   // 512-bit message block
      Count: UInt64;                 // number of bytes processed
    end;
  private
    FVTable: Pointer;
    FRefCount: Integer;
    FData: TData;

    procedure Compress;
  public
    class procedure Init(Inst: PSHA1Alg);
         {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class procedure Update(Inst: PSHA1Alg; Data: PByte; DataSize: Cardinal);
         {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class procedure Done(Inst: PSHA1Alg; PDigest: PSHA1Digest);
         {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
//    class procedure Burn(Inst: PSHA1Alg);  -- redirected to Init
//         {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function GetDigestSize(Inst: PSHA1Alg): Integer;
         {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function GetBlockSize(Inst: PSHA1Alg): Integer;
         {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function Duplicate(Inst: PSHA1Alg; var DupInst: PSHA1Alg): TF_RESULT;
         {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
  end;

function GetSHA1Algorithm(var Inst: PSHA1Alg): TF_RESULT;

implementation

uses tfRecords;

const
  SHA1VTable: array[0..9] of Pointer = (
    @TForgeInstance.QueryIntf,
    @TForgeInstance.Addref,
    @HashAlgRelease,

    @TSHA1Alg.Init,
    @TSHA1Alg.Update,
    @TSHA1Alg.Done,
    @TSHA1Alg.Init,
    @TSHA1Alg.GetDigestSize,
    @TSHA1Alg.GetBlockSize,
    @TSHA1Alg.Duplicate
  );

function GetSHA1Algorithm(var Inst: PSHA1Alg): TF_RESULT;
var
  P: PSHA1Alg;

begin
  try
    New(P);
    P^.FVTable:= @SHA1VTable;
    P^.FRefCount:= 1;
    TSHA1Alg.Init(P);
    if Inst <> nil then HashAlgRelease(Inst);
    Inst:= P;
    Result:= TF_S_OK;
  except
    Result:= TF_E_OUTOFMEMORY;
  end;
end;

{ TSHA1Alg }

function Swap32(Value: UInt32): UInt32;
begin
  Result:= ((Value and $FF) shl 24) or ((Value and $FF00) shl 8) or
           ((Value and $FF0000) shr 8) or ((Value and $FF000000) shr 24);
end;

{$IFDEF CPUX86_WIN32}
procedure TSHA1Alg.Compress;
asm
        PUSH    ESI
        PUSH    EDI
        PUSH    EBX
        PUSH    EBP
        PUSH    EAX       // work register

        LEA     EDI,[EAX].TSHA1Alg.FData.Block    // W:= @FData.Block;

        MOV     EAX,[EDI - 20]      // A:= FData.Digest[0];
        MOV     EBX,[EDI - 16]      // B:= FData.Digest[1];
        MOV     ECX,[EDI - 12]      // C:= FData.Digest[2];
        MOV     EDX,[EDI - 8]       // D:= FData.Digest[3];
        MOV     EBP,[EDI - 4]       // E:= FData.Digest[4];

                                                    { 0}
//  W[0]:= Swap32(W[0]);
//  Inc(E,((A shl 5) or (A shr 27)) + (D xor (B and (C xor D))) + $5A827999 + W[0]);
//  B:= (B shl 30) or (B shr 2);

        MOV     ESI,[EDI]
        BSWAP   ESI
        MOV     [EDI],ESI
        ADD     EBP,ESI
        MOV     ESI,ECX
        XOR     ESI,EDX
        AND     ESI,EBX
        XOR     ESI,EDX
        ROL     EBX,30
        LEA     EBP,[EBP + ESI + $5A827999]
        MOV     ESI,EAX
        ROL     ESI,5
        ADD     EBP,ESI
                                                    { 1}
//  W[1]:= Swap32(W[1]);
//  Inc(D,((E shl 5) or (E shr 27)) + (C xor (A and (B xor C))) + $5A827999 + W[1]);
//  A:= (A shl 30) or (A shr 2);

        MOV     ESI,[EDI + 4]
        BSWAP   ESI
        MOV     [EDI + 4],ESI
        ADD     EDX,ESI
        MOV     ESI,EBX
        XOR     ESI,ECX
        AND     ESI,EAX
        XOR     ESI,ECX
        ROL     EAX,30
        LEA     EDX,[EDX + ESI + $5A827999]
        MOV     ESI,EBP
        ROL     ESI,5
        ADD     EDX,ESI
                                                    { 2}
//  W[2]:= Swap32(W[2]);
//  Inc(C,((D shl 5) or (D shr 27)) + (B xor (E and (A xor B))) + $5A827999 + W[2]);
//  E:= (E shl 30) or (E shr 2);

        MOV     ESI,[EDI + 8]
        BSWAP   ESI
        MOV     [EDI + 8],ESI
        ADD     ECX,ESI
        MOV     ESI,EAX
        XOR     ESI,EBX
        AND     ESI,EBP
        XOR     ESI,EBX
        ROL     EBP,30
        LEA     ECX,[ECX + ESI + $5A827999]
        MOV     ESI,EDX
        ROL     ESI,5
        ADD     ECX,ESI
                                                    { 3}
//  W[3]:= Swap32(W[3]);
//  Inc(B,((C shl 5) or (C shr 27)) + (A xor (D and (E xor A))) + $5A827999 + W[3]);
//  D:= (D shl 30) or (D shr 2);

        MOV     ESI,[EDI + 12]
        BSWAP   ESI
        MOV     [EDI + 12],ESI
        ADD     EBX,ESI
        MOV     ESI,EBP
        XOR     ESI,EAX
        AND     ESI,EDX
        XOR     ESI,EAX
        ROL     EDX,30
        LEA     EBX,[EBX + ESI + $5A827999]
        MOV     ESI,ECX
        ROL     ESI,5
        ADD     EBX,ESI
                                                    { 4}
//  W[4]:= Swap32(W[4]);
//  Inc(A,((B shl 5) or (B shr 27)) + (E xor (C and (D xor E))) + $5A827999 + W[4]);
//  C:= (C shl 30) or (C shr 2);

        MOV     ESI,[EDI + 16]
        BSWAP   ESI
        MOV     [EDI + 16],ESI
        ADD     EAX,ESI
        MOV     ESI,EDX
        XOR     ESI,EBP
        AND     ESI,ECX
        XOR     ESI,EBP
        ROL     ECX,30
        LEA     EAX,[EAX + ESI + $5A827999]
        MOV     ESI,EBX
        ROL     ESI,5
        ADD     EAX,ESI
                                                    { 5}
//  W[5]:= Swap32(W[5]);
//  Inc(E,((A shl 5) or (A shr 27)) + (D xor (B and (C xor D))) + $5A827999 + W[5]);
//  B:= (B shl 30) or (B shr 2);

        MOV     ESI,[EDI + 20]
        BSWAP   ESI
        MOV     [EDI + 20],ESI
        ADD     EBP,ESI
        MOV     ESI,ECX
        XOR     ESI,EDX
        AND     ESI,EBX
        XOR     ESI,EDX
        ROL     EBX,30
        LEA     EBP,[EBP + ESI + $5A827999]
        MOV     ESI,EAX
        ROL     ESI,5
        ADD     EBP,ESI
                                                    { 6}
//  W[6]:= Swap32(W[6]);
//  Inc(D,((E shl 5) or (E shr 27)) + (C xor (A and (B xor C))) + $5A827999 + W[6]);
//  A:= (A shl 30) or (A shr 2);

        MOV     ESI,[EDI + 24]
        BSWAP   ESI
        MOV     [EDI + 24],ESI
        ADD     EDX,ESI
        MOV     ESI,EBX
        XOR     ESI,ECX
        AND     ESI,EAX
        XOR     ESI,ECX
        ROL     EAX,30
        LEA     EDX,[EDX + ESI + $5A827999]
        MOV     ESI,EBP
        ROL     ESI,5
        ADD     EDX,ESI
                                                    { 7}
//  W[7]:= Swap32(W[7]);
//  Inc(C,((D shl 5) or (D shr 27)) + (B xor (E and (A xor B))) + $5A827999 + W[7]);
//  E:= (E shl 30) or (E shr 2);

        MOV     ESI,[EDI + 28]
        BSWAP   ESI
        MOV     [EDI + 28],ESI
        ADD     ECX,ESI
        MOV     ESI,EAX
        XOR     ESI,EBX
        AND     ESI,EBP
        XOR     ESI,EBX
        ROL     EBP,30
        LEA     ECX,[ECX + ESI + $5A827999]
        MOV     ESI,EDX
        ROL     ESI,5
        ADD     ECX,ESI
                                                    { 8}
//  W[8]:= Swap32(W[8]);
//  Inc(B,((C shl 5) or (C shr 27)) + (A xor (D and (E xor A))) + $5A827999 + W[8]);
//  D:= (D shl 30) or (D shr 2);

        MOV     ESI,[EDI + 32]
        BSWAP   ESI
        MOV     [EDI + 32],ESI
        ADD     EBX,ESI
        MOV     ESI,EBP
        XOR     ESI,EAX
        AND     ESI,EDX
        XOR     ESI,EAX
        ROL     EDX,30
        LEA     EBX,[EBX + ESI + $5A827999]
        MOV     ESI,ECX
        ROL     ESI,5
        ADD     EBX,ESI
                                                    { 9}
//  W[9]:= Swap32(W[9]);
//  Inc(A,((B shl 5) or (B shr 27)) + (E xor (C and (D xor E))) + $5A827999 + W[9]);
//  C:= (C shl 30) or (C shr 2);
                                    { 9}
        MOV     ESI,[EDI + 36]
        BSWAP   ESI
        MOV     [EDI + 36],ESI
        ADD     EAX,ESI
        MOV     ESI,EDX
        XOR     ESI,EBP
        AND     ESI,ECX
        XOR     ESI,EBP
        ROL     ECX,30
        LEA     EAX,[EAX + ESI + $5A827999]
        MOV     ESI,EBX
        ROL     ESI,5
        ADD     EAX,ESI
                                                    {10}
//  W[10]:= Swap32(W[10]);
//  Inc(E,((A shl 5) or (A shr 27)) + (D xor (B and (C xor D))) + $5A827999 + W[10]);
//  B:= (B shl 30) or (B shr 2);

        MOV     ESI,[EDI + 40]
        BSWAP   ESI
        MOV     [EDI + 40],ESI
        ADD     EBP,ESI
        MOV     ESI,ECX
        XOR     ESI,EDX
        AND     ESI,EBX
        XOR     ESI,EDX
        ROL     EBX,30
        LEA     EBP,[EBP + ESI + $5A827999]
        MOV     ESI,EAX
        ROL     ESI,5
        ADD     EBP,ESI
                                                    {11}
//  W[11]:= Swap32(W[11]);
//  Inc(D,((E shl 5) or (E shr 27)) + (C xor (A and (B xor C))) + $5A827999 + W[11]);
//  A:= (A shl 30) or (A shr 2);

        MOV     ESI,[EDI + 44]
        BSWAP   ESI
        MOV     [EDI + 44],ESI
        ADD     EDX,ESI
        MOV     ESI,EBX
        XOR     ESI,ECX
        AND     ESI,EAX
        XOR     ESI,ECX
        ROL     EAX,30
        LEA     EDX,[EDX + ESI + $5A827999]
        MOV     ESI,EBP
        ROL     ESI,5
        ADD     EDX,ESI
                                                    {12}
//  W[12]:= Swap32(W[12]);
//  Inc(C,((D shl 5) or (D shr 27)) + (B xor (E and (A xor B))) + $5A827999 + W[12]);
//  E:= (E shl 30) or (E shr 2);

        MOV     ESI,[EDI + 48]
        BSWAP   ESI
        MOV     [EDI + 48],ESI
        ADD     ECX,ESI
        MOV     ESI,EAX
        XOR     ESI,EBX
        AND     ESI,EBP
        XOR     ESI,EBX
        ROL     EBP,30
        LEA     ECX,[ECX + ESI + $5A827999]
        MOV     ESI,EDX
        ROL     ESI,5
        ADD     ECX,ESI
                                                    {13}
//  W[13]:= Swap32(W[13]);
//  Inc(B,((C shl 5) or (C shr 27)) + (A xor (D and (E xor A))) + $5A827999 + W[13]);
//  D:= (D shl 30) or (D shr 2);

        MOV     ESI,[EDI + 52]
        BSWAP   ESI
        MOV     [EDI + 52],ESI
        ADD     EBX,ESI
        MOV     ESI,EBP
        XOR     ESI,EAX
        AND     ESI,EDX
        XOR     ESI,EAX
        ROL     EDX,30
        LEA     EBX,[EBX + ESI + $5A827999]
        MOV     ESI,ECX
        ROL     ESI,5
        ADD     EBX,ESI
                                                    {14}
//  W[14]:= Swap32(W[14]);
//  Inc(A,((B shl 5) or (B shr 27)) + (E xor (C and (D xor E))) + $5A827999 + W[14]);
//  C:= (C shl 30) or (C shr 2);

        MOV     ESI,[EDI + 56]
        BSWAP   ESI
        MOV     [EDI + 56],ESI
        ADD     EAX,ESI
        MOV     ESI,EDX
        XOR     ESI,EBP
        AND     ESI,ECX
        XOR     ESI,EBP
        ROL     ECX,30
        LEA     EAX,[EAX + ESI + $5A827999]
        MOV     ESI,EBX
        ROL     ESI,5
        ADD     EAX,ESI
                                                    {15}
//  W[15]:= Swap32(W[15]);
//  Inc(E,((A shl 5) or (A shr 27)) + (D xor (B and (C xor D))) + $5A827999 + W[15]);
//  B:= (B shl 30) or (B shr 2);

        MOV     ESI,[EDI + 60]
        BSWAP   ESI
        MOV     [EDI + 60],ESI
        ADD     EBP,ESI
        MOV     ESI,ECX
        XOR     ESI,EDX
        AND     ESI,EBX
        XOR     ESI,EDX
        ROL     EBX,30
        LEA     EBP,[EBP + ESI + $5A827999]
        MOV     ESI,EAX
        ROL     ESI,5
        ADD     EBP,ESI

                                                    {16}
//  Tmp:= W[13] xor W[8] xor W[2] xor W[0];
//  W[0]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(D,((E shl 5) or (E shr 27)) + (C xor (A and (B xor C))) + $5A827999 + W[0]);
//  A:= (A shl 30) or (A shr 2);

        MOV     ESI,[EDI + 52]
        XOR     ESI,[EDI + 32]
        XOR     ESI,[EDI + 8]
        XOR     ESI,[EDI]
        ROL     ESI,1
        MOV     [EDI],ESI
        ADD     EDX,ESI
        MOV     ESI,EBX
        XOR     ESI,ECX
        AND     ESI,EAX
        XOR     ESI,ECX
        ROL     EAX,30
        LEA     EDX,[EDX + ESI + $5A827999]
        MOV     ESI,EBP
        ROL     ESI,5
        ADD     EDX,ESI
                                                    {17}
//  Tmp:= W[14] xor W[9] xor W[3] xor W[1];
//  W[1]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(C,((D shl 5) or (D shr 27)) + (B xor (E and (A xor B))) + $5A827999 + W[1]);
//  E:= (E shl 30) or (E shr 2);

        MOV     ESI,[EDI + 56]
        XOR     ESI,[EDI + 36]
        XOR     ESI,[EDI + 12]
        XOR     ESI,[EDI + 4]
        ROL     ESI,1
        MOV     [EDI + 4],ESI
        ADD     ECX,ESI
        MOV     ESI,EAX
        XOR     ESI,EBX
        AND     ESI,EBP
        XOR     ESI,EBX
        ROL     EBP,30
        LEA     ECX,[ECX + ESI + $5A827999]
        MOV     ESI,EDX
        ROL     ESI,5
        ADD     ECX,ESI
                                                    {18}
//  Tmp:= W[15] xor W[10] xor W[4] xor W[2];
//  W[2]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(B,((C shl 5) or (C shr 27)) + (A xor (D and (E xor A))) + $5A827999 + W[2]);
//  D:= (D shl 30) or (D shr 2);

        MOV     ESI,[EDI + 60]
        XOR     ESI,[EDI + 40]
        XOR     ESI,[EDI + 16]
        XOR     ESI,[EDI + 8]
        ROL     ESI,1
        MOV     [EDI + 8],ESI
        ADD     EBX,ESI
        MOV     ESI,EBP
        XOR     ESI,EAX
        AND     ESI,EDX
        XOR     ESI,EAX
        ROL     EDX,30
        LEA     EBX,[EBX + ESI + $5A827999]
        MOV     ESI,ECX
        ROL     ESI,5
        ADD     EBX,ESI
                                                    {19}
//  Tmp:= W[0] xor W[11] xor W[5] xor W[3];
//  W[3]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(A,((B shl 5) or (B shr 27)) + (E xor (C and (D xor E))) + $5A827999 + W[3]);
//  C:= (C shl 30) or (C shr 2);

        MOV     ESI,[EDI]
        XOR     ESI,[EDI + 44]
        XOR     ESI,[EDI + 20]
        XOR     ESI,[EDI + 12]
        ROL     ESI,1
        MOV     [EDI + 12],ESI
        ADD     EAX,ESI
        MOV     ESI,EDX
        XOR     ESI,EBP
        AND     ESI,ECX
        XOR     ESI,EBP
        ROL     ECX,30
        LEA     EAX,[EAX + ESI + $5A827999]
        MOV     ESI,EBX
        ROL     ESI,5
        ADD     EAX,ESI
                                                    {20}
//  Tmp:= W[1] xor W[12] xor W[6] xor W[4];
//  W[4]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(E,((A shl 5) or (A shr 27)) + (B xor C xor D) + $6ED9EBA1 + W[4]);
//  B:= (B shl 30) or (B shr 2);

        MOV     ESI,[EDI + 4]
        XOR     ESI,[EDI + 48]
        XOR     ESI,[EDI + 24]
        XOR     ESI,[EDI + 16]
        ROL     ESI,1
        MOV     [EDI + 16],ESI
        ADD     EBP,ESI
        MOV     ESI,EBX
        XOR     ESI,ECX
        XOR     ESI,EDX
        ROL     EBX,30
        LEA     EBP,[EBP + ESI + $6ED9EBA1]
        MOV     ESI,EAX
        ROL     ESI,5
        ADD     EBP,ESI
                                                    {21}
//  Tmp:= W[2] xor W[13] xor W[7] xor W[5];
//  W[5]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(D,((E shl 5) or (E shr 27)) + (A xor B xor C) + $6ED9EBA1 + W[5]);
//  A:= (A shl 30) or (A shr 2);

        MOV     ESI,[EDI + 8]
        XOR     ESI,[EDI + 52]
        XOR     ESI,[EDI + 28]
        XOR     ESI,[EDI + 20]
        ROL     ESI,1
        MOV     [EDI + 20],ESI
        ADD     EDX,ESI
        MOV     ESI,EAX
        XOR     ESI,EBX
        XOR     ESI,ECX
        ROL     EAX,30
        LEA     EDX,[EDX + ESI + $6ED9EBA1]
        MOV     ESI,EBP
        ROL     ESI,5
        ADD     EDX,ESI
                                                    {22}
//  Tmp:= W[3] xor W[14] xor W[8] xor W[6];
//  W[6]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(C,((D shl 5) or (D shr 27)) + (E xor A xor B) + $6ED9EBA1 + W[6]);
//  E:= (E shl 30) or (E shr 2);

        MOV     ESI,[EDI + 12]
        XOR     ESI,[EDI + 56]
        XOR     ESI,[EDI + 32]
        XOR     ESI,[EDI + 24]
        ROL     ESI,1
        MOV     [EDI + 24],ESI
        ADD     ECX,ESI
        MOV     ESI,EBP
        XOR     ESI,EAX
        XOR     ESI,EBX
        ROL     EBP,30
        LEA     ECX,[ECX + ESI + $6ED9EBA1]
        MOV     ESI,EDX
        ROL     ESI,5
        ADD     ECX,ESI
                                                    {23}
//  Tmp:= W[4] xor W[15] xor W[9] xor W[7];
//  W[7]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(B,((C shl 5) or (C shr 27)) + (D xor E xor A) + $6ED9EBA1 + W[7]);
//  D:= (D shl 30) or (D shr 2);

        MOV     ESI,[EDI + 16]
        XOR     ESI,[EDI + 60]
        XOR     ESI,[EDI + 36]
        XOR     ESI,[EDI + 28]
        ROL     ESI,1
        MOV     [EDI + 28],ESI
        ADD     EBX,ESI
        MOV     ESI,EDX
        XOR     ESI,EBP
        XOR     ESI,EAX
        ROL     EDX,30
        LEA     EBX,[EBX + ESI + $6ED9EBA1]
        MOV     ESI,ECX
        ROL     ESI,5
        ADD     EBX,ESI
                                                    {24}
//  Tmp:= W[5] xor W[0] xor W[10] xor W[8];
//  W[8]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(A,((B shl 5) or (B shr 27)) + (C xor D xor E) + $6ED9EBA1 + W[8]);
//  C:= (C shl 30) or (C shr 2);

        MOV     ESI,[EDI + 20]
        XOR     ESI,[EDI]
        XOR     ESI,[EDI + 40]
        XOR     ESI,[EDI + 32]
        ROL     ESI,1
        MOV     [EDI + 32],ESI
        ADD     EAX,ESI
        MOV     ESI,ECX
        XOR     ESI,EDX
        XOR     ESI,EBP
        ROL     ECX,30
        LEA     EAX,[EAX + ESI + $6ED9EBA1]
        MOV     ESI,EBX
        ROL     ESI,5
        ADD     EAX,ESI
                                                    {25}
//  Tmp:= W[6] xor W[1] xor W[11] xor W[9];
//  W[9]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(E,((A shl 5) or (A shr 27)) + (B xor C xor D) + $6ED9EBA1 + W[9]);
//  B:= (B shl 30) or (B shr 2);

        MOV     ESI,[EDI + 24]
        XOR     ESI,[EDI + 4]
        XOR     ESI,[EDI + 44]
        XOR     ESI,[EDI + 36]
        ROL     ESI,1
        MOV     [EDI + 36],ESI
        ADD     EBP,ESI
        MOV     ESI,EBX
        XOR     ESI,ECX
        XOR     ESI,EDX
        ROL     EBX,30
        LEA     EBP,[EBP + ESI + $6ED9EBA1]
        MOV     ESI,EAX
        ROL     ESI,5
        ADD     EBP,ESI
                                                    {26}
//  Tmp:= W[7] xor W[2] xor W[12] xor W[10];
//  W[10]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(D,((E shl 5) or (E shr 27)) + (A xor B xor C) + $6ED9EBA1 + W[10]);
//  A:= (A shl 30) or (A shr 2);

        MOV     ESI,[EDI + 28]
        XOR     ESI,[EDI + 8]
        XOR     ESI,[EDI + 48]
        XOR     ESI,[EDI + 40]
        ROL     ESI,1
        MOV     [EDI + 40],ESI
        ADD     EDX,ESI
        MOV     ESI,EAX
        XOR     ESI,EBX
        XOR     ESI,ECX
        ROL     EAX,30
        LEA     EDX,[EDX + ESI + $6ED9EBA1]
        MOV     ESI,EBP
        ROL     ESI,5
        ADD     EDX,ESI
                                                    {27}
//  Tmp:= W[8] xor W[3] xor W[13] xor W[11];
//  W[11]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(C,((D shl 5) or (D shr 27)) + (E xor A xor B) + $6ED9EBA1 + W[11]);
//  E:= (E shl 30) or (E shr 2);

        MOV     ESI,[EDI + 32]
        XOR     ESI,[EDI + 12]
        XOR     ESI,[EDI + 52]
        XOR     ESI,[EDI + 44]
        ROL     ESI,1
        MOV     [EDI + 44],ESI
        ADD     ECX,ESI
        MOV     ESI,EBP
        XOR     ESI,EAX
        XOR     ESI,EBX
        ROL     EBP,30
        LEA     ECX,[ECX + ESI + $6ED9EBA1]
        MOV     ESI,EDX
        ROL     ESI,5
        ADD     ECX,ESI
                                                    {28}
//  Tmp:= W[9] xor W[4] xor W[14] xor W[12];
//  W[12]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(B,((C shl 5) or (C shr 27)) + (D xor E xor A) + $6ED9EBA1 + W[12]);
//  D:= (D shl 30) or (D shr 2);

        MOV     ESI,[EDI + 36]
        XOR     ESI,[EDI + 16]
        XOR     ESI,[EDI + 56]
        XOR     ESI,[EDI + 48]
        ROL     ESI,1
        MOV     [EDI + 48],ESI
        ADD     EBX,ESI
        MOV     ESI,EDX
        XOR     ESI,EBP
        XOR     ESI,EAX
        ROL     EDX,30
        LEA     EBX,[EBX + ESI + $6ED9EBA1]
        MOV     ESI,ECX
        ROL     ESI,5
        ADD     EBX,ESI
                                                    {29}
//  Tmp:= W[10] xor W[5] xor W[15] xor W[13];
//  W[13]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(A,((B shl 5) or (B shr 27)) + (C xor D xor E) + $6ED9EBA1 + W[13]);
//  C:= (C shl 30) or (C shr 2);

        MOV     ESI,[EDI + 40]
        XOR     ESI,[EDI + 20]
        XOR     ESI,[EDI + 60]
        XOR     ESI,[EDI + 52]
        ROL     ESI,1
        MOV     [EDI + 52],ESI
        ADD     EAX,ESI
        MOV     ESI,ECX
        XOR     ESI,EDX
        XOR     ESI,EBP
        ROL     ECX,30
        LEA     EAX,[EAX + ESI + $6ED9EBA1]
        MOV     ESI,EBX
        ROL     ESI,5
        ADD     EAX,ESI
                                                    {30}
//  Tmp:= W[11] xor W[6] xor W[0] xor W[14];
//  W[14]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(E,((A shl 5) or (A shr 27)) + (B xor C xor D) + $6ED9EBA1 + W[14]);
//  B:= (B shl 30) or (B shr 2);

        MOV     ESI,[EDI + 44]
        XOR     ESI,[EDI + 24]
        XOR     ESI,[EDI]
        XOR     ESI,[EDI + 56]
        ROL     ESI,1
        MOV     [EDI + 56],ESI
        ADD     EBP,ESI
        MOV     ESI,EBX
        XOR     ESI,ECX
        XOR     ESI,EDX
        ROL     EBX,30
        LEA     EBP,[EBP + ESI + $6ED9EBA1]
        MOV     ESI,EAX
        ROL     ESI,5
        ADD     EBP,ESI
                                                    {31}
//  Tmp:= W[12] xor W[7] xor W[1] xor W[15];
//  W[15]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(D,((E shl 5) or (E shr 27)) + (A xor B xor C) + $6ED9EBA1 + W[15]);
//  A:= (A shl 30) or (A shr 2);

        MOV     ESI,[EDI + 48]
        XOR     ESI,[EDI + 28]
        XOR     ESI,[EDI + 4]
        XOR     ESI,[EDI + 60]
        ROL     ESI,1
        MOV     [EDI + 60],ESI
        ADD     EDX,ESI
        MOV     ESI,EAX
        XOR     ESI,EBX
        XOR     ESI,ECX
        ROL     EAX,30
        LEA     EDX,[EDX + ESI + $6ED9EBA1]
        MOV     ESI,EBP
        ROL     ESI,5
        ADD     EDX,ESI
                                                    {32}
//  Tmp:= W[13] xor W[8] xor W[2] xor W[0];
//  W[0]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(C,((D shl 5) or (D shr 27)) + (E xor A xor B) + $6ED9EBA1 + W[0]);
//  E:= (E shl 30) or (E shr 2);

        MOV     ESI,[EDI + 52]
        XOR     ESI,[EDI + 32]
        XOR     ESI,[EDI + 8]
        XOR     ESI,[EDI]
        ROL     ESI,1
        MOV     [EDI],ESI
        ADD     ECX,ESI
        MOV     ESI,EBP
        XOR     ESI,EAX
        XOR     ESI,EBX
        ROL     EBP,30
        LEA     ECX,[ECX + ESI + $6ED9EBA1]
        MOV     ESI,EDX
        ROL     ESI,5
        ADD     ECX,ESI
                                                    {33}
//  Tmp:= W[14] xor W[9] xor W[3] xor W[1];
//  W[1]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(B,((C shl 5) or (C shr 27)) + (D xor E xor A) + $6ED9EBA1 + W[1]);
//  D:= (D shl 30) or (D shr 2);

        MOV     ESI,[EDI + 56]
        XOR     ESI,[EDI + 36]
        XOR     ESI,[EDI + 12]
        XOR     ESI,[EDI + 4]
        ROL     ESI,1
        MOV     [EDI + 4],ESI
        ADD     EBX,ESI
        MOV     ESI,EDX
        XOR     ESI,EBP
        XOR     ESI,EAX
        ROL     EDX,30
        LEA     EBX,[EBX + ESI + $6ED9EBA1]
        MOV     ESI,ECX
        ROL     ESI,5
        ADD     EBX,ESI
                                                    {34}
//  Tmp:= W[15] xor W[10] xor W[4] xor W[2];
//  W[2]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(A,((B shl 5) or (B shr 27)) + (C xor D xor E) + $6ED9EBA1 + W[2]);
//  C:= (C shl 30) or (C shr 2);

        MOV     ESI,[EDI + 60]
        XOR     ESI,[EDI + 40]
        XOR     ESI,[EDI + 16]
        XOR     ESI,[EDI + 8]
        ROL     ESI,1
        MOV     [EDI + 8],ESI
        ADD     EAX,ESI
        MOV     ESI,ECX
        XOR     ESI,EDX
        XOR     ESI,EBP
        ROL     ECX,30
        LEA     EAX,[EAX + ESI + $6ED9EBA1]
        MOV     ESI,EBX
        ROL     ESI,5
        ADD     EAX,ESI
                                                    {35}
//  Tmp:= W[0] xor W[11] xor W[5] xor W[3];
//  W[3]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(E,((A shl 5) or (A shr 27)) + (B xor C xor D) + $6ED9EBA1 + W[3]);
//  B:= (B shl 30) or (B shr 2);

        MOV     ESI,[EDI]
        XOR     ESI,[EDI + 44]
        XOR     ESI,[EDI + 20]
        XOR     ESI,[EDI + 12]
        ROL     ESI,1
        MOV     [EDI + 12],ESI
        ADD     EBP,ESI
        MOV     ESI,EBX
        XOR     ESI,ECX
        XOR     ESI,EDX
        ROL     EBX,30
        LEA     EBP,[EBP + ESI + $6ED9EBA1]
        MOV     ESI,EAX
        ROL     ESI,5
        ADD     EBP,ESI
                                                    {36}
//  Tmp:= W[1] xor W[12] xor W[6] xor W[4];
//  W[4]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(D,((E shl 5) or (E shr 27)) + (A xor B xor C) + $6ED9EBA1 + W[4]);
//  A:= (A shl 30) or (A shr 2);

        MOV     ESI,[EDI + 4]
        XOR     ESI,[EDI + 48]
        XOR     ESI,[EDI + 24]
        XOR     ESI,[EDI + 16]
        ROL     ESI,1
        MOV     [EDI + 16],ESI
        ADD     EDX,ESI
        MOV     ESI,EAX
        XOR     ESI,EBX
        XOR     ESI,ECX
        ROL     EAX,30
        LEA     EDX,[EDX + ESI + $6ED9EBA1]
        MOV     ESI,EBP
        ROL     ESI,5
        ADD     EDX,ESI
                                                    {37}
//  Tmp:= W[2] xor W[13] xor W[7] xor W[5];
//  W[5]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(C,((D shl 5) or (D shr 27)) + (E xor A xor B) + $6ED9EBA1 + W[5]);
//  E:= (E shl 30) or (E shr 2);

        MOV     ESI,[EDI + 8]
        XOR     ESI,[EDI + 52]
        XOR     ESI,[EDI + 28]
        XOR     ESI,[EDI + 20]
        ROL     ESI,1
        MOV     [EDI + 20],ESI
        ADD     ECX,ESI
        MOV     ESI,EBP
        XOR     ESI,EAX
        XOR     ESI,EBX
        ROL     EBP,30
        LEA     ECX,[ECX + ESI + $6ED9EBA1]
        MOV     ESI,EDX
        ROL     ESI,5
        ADD     ECX,ESI
                                                    {38}
//  Tmp:= W[3] xor W[14] xor W[8] xor W[6];
//  W[6]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(B,((C shl 5) or (C shr 27)) + (D xor E xor A) + $6ED9EBA1 + W[6]);
//  D:= (D shl 30) or (D shr 2);

        MOV     ESI,[EDI + 12]
        XOR     ESI,[EDI + 56]
        XOR     ESI,[EDI + 32]
        XOR     ESI,[EDI + 24]
        ROL     ESI,1
        MOV     [EDI + 24],ESI
        ADD     EBX,ESI
        MOV     ESI,EDX
        XOR     ESI,EBP
        XOR     ESI,EAX
        ROL     EDX,30
        LEA     EBX,[EBX + ESI + $6ED9EBA1]
        MOV     ESI,ECX
        ROL     ESI,5
        ADD     EBX,ESI
                                                    {39}
//  Tmp:= W[4] xor W[15] xor W[9] xor W[7];
//  W[7]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(A,((B shl 5) or (B shr 27)) + (C xor D xor E) + $6ED9EBA1 + W[7]);
//  C:= (C shl 30) or (C shr 2);

        MOV     ESI,[EDI + 16]
        XOR     ESI,[EDI + 60]
        XOR     ESI,[EDI + 36]
        XOR     ESI,[EDI + 28]
        ROL     ESI,1
        MOV     [EDI + 28],ESI
        ADD     EAX,ESI
        MOV     ESI,ECX
        XOR     ESI,EDX
        XOR     ESI,EBP
        ROL     ECX,30
        LEA     EAX,[EAX + ESI + $6ED9EBA1]
        MOV     ESI,EBX
        ROL     ESI,5
        ADD     EAX,ESI

                                                    {40}
//  Tmp:= W[5] xor W[0] xor W[10] xor W[8];
//  W[8]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(E,((A shl 5) or (A shr 27)) + ((B and C) or (D and (B or C))) + $8F1BBCDC + W[8]);
//  B:= (B shl 30) or (B shr 2);

        MOV     ESI,[EDI + 20]
        XOR     ESI,[EDI]
        XOR     ESI,[EDI + 40]
        XOR     ESI,[EDI + 32]
        ROL     ESI,1
        MOV     [EDI + 32],ESI
        ADD     EBP,ESI
        MOV     [ESP],EBX
        MOV     ESI,EBX
        AND     [ESP],ECX
        OR      ESI,ECX
        AND     ESI,EDX
        OR      ESI,[ESP]
        ROL     EBX,30
        LEA     EBP,[EBP + ESI + $8F1BBCDC]
        MOV     ESI,EAX
        ROL     ESI,5
        ADD     EBP,ESI
                                                    {41}
//  Tmp:= W[6] xor W[1] xor W[11] xor W[9];
//  W[9]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(D,((E shl 5) or (E shr 27)) + ((A and B) or (C and (A or B))) + $8F1BBCDC + W[9]);
//  A:= (A shl 30) or (A shr 2);

        MOV     ESI,[EDI + 24]
        XOR     ESI,[EDI + 4]
        XOR     ESI,[EDI + 44]
        XOR     ESI,[EDI + 36]
        ROL     ESI,1
        MOV     [EDI + 36],ESI
        ADD     EDX,ESI
        MOV     [ESP],EAX
        MOV     ESI,EAX
        AND     [ESP],EBX
        OR      ESI,EBX
        AND     ESI,ECX
        OR      ESI,[ESP]
        ROL     EAX,30
        LEA     EDX,[EDX + ESI + $8F1BBCDC]
        MOV     ESI,EBP
        ROL     ESI,5
        ADD     EDX,ESI
                                                    {42}
//  Tmp:= W[7] xor W[2] xor W[12] xor W[10];
//  W[10]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(C,((D shl 5) or (D shr 27)) + ((E and A) or (B and (E or A))) + $8F1BBCDC + W[10]);
//  E:= (E shl 30) or (E shr 2);

        MOV     ESI,[EDI + 28]
        XOR     ESI,[EDI + 8]
        XOR     ESI,[EDI + 48]
        XOR     ESI,[EDI + 40]
        ROL     ESI,1
        MOV     [EDI + 40],ESI
        ADD     ECX,ESI
        MOV     [ESP],EBP
        MOV     ESI,EBP
        AND     [ESP],EAX
        OR      ESI,EAX
        AND     ESI,EBX
        OR      ESI,[ESP]
        ROL     EBP,30
        LEA     ECX,[ECX + ESI + $8F1BBCDC]
        MOV     ESI,EDX
        ROL     ESI,5
        ADD     ECX,ESI
                                                    {43}
//  Tmp:= W[8] xor W[3] xor W[13] xor W[11];
//  W[11]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(B,((C shl 5) or (C shr 27)) + ((D and E) or (A and (D or E))) + $8F1BBCDC + W[11]);
//  D:= (D shl 30) or (D shr 2);

        MOV     ESI,[EDI + 32]
        XOR     ESI,[EDI + 12]
        XOR     ESI,[EDI + 52]
        XOR     ESI,[EDI + 44]
        ROL     ESI,1
        MOV     [EDI + 44],ESI
        ADD     EBX,ESI
        MOV     [ESP],EDX
        MOV     ESI,EDX
        AND     [ESP],EBP
        OR      ESI,EBP
        AND     ESI,EAX
        OR      ESI,[ESP]
        ROL     EDX,30
        LEA     EBX,[EBX + ESI + $8F1BBCDC]
        MOV     ESI,ECX
        ROL     ESI,5
        ADD     EBX,ESI
                                                    {44}
//  Tmp:= W[9] xor W[4] xor W[14] xor W[12];
//  W[12]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(A,((B shl 5) or (B shr 27)) + ((C and D) or (E and (C or D))) + $8F1BBCDC + W[12]);
//  C:= (C shl 30) or (C shr 2);

        MOV     ESI,[EDI + 36]
        XOR     ESI,[EDI + 16]
        XOR     ESI,[EDI + 56]
        XOR     ESI,[EDI + 48]
        ROL     ESI,1
        MOV     [EDI + 48],ESI
        ADD     EAX,ESI
        MOV     [ESP],ECX
        MOV     ESI,ECX
        AND     [ESP],EDX
        OR      ESI,EDX
        AND     ESI,EBP
        OR      ESI,[ESP]
        ROL     ECX,30
        LEA     EAX,[EAX + ESI + $8F1BBCDC]
        MOV     ESI,EBX
        ROL     ESI,5
        ADD     EAX,ESI
                                                    {45}
//  Tmp:= W[10] xor W[5] xor W[15] xor W[13];
//  W[13]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(E,((A shl 5) or (A shr 27)) + ((B and C) or (D and (B or C))) + $8F1BBCDC + W[13]);
//  B:= (B shl 30) or (B shr 2);

        MOV     ESI,[EDI + 40]
        XOR     ESI,[EDI + 20]
        XOR     ESI,[EDI + 60]
        XOR     ESI,[EDI + 52]
        ROL     ESI,1
        MOV     [EDI + 52],ESI
        ADD     EBP,ESI
        MOV     [ESP],EBX
        MOV     ESI,EBX
        AND     [ESP],ECX
        OR      ESI,ECX
        AND     ESI,EDX
        OR      ESI,[ESP]
        ROL     EBX,30
        LEA     EBP,[EBP + ESI + $8F1BBCDC]
        MOV     ESI,EAX
        ROL     ESI,5
        ADD     EBP,ESI
                                                    {46}
//  Tmp:= W[11] xor W[6] xor W[0] xor W[14];
//  W[14]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(D,((E shl 5) or (E shr 27)) + ((A and B) or (C and (A or B))) + $8F1BBCDC + W[14]);
//  A:= (A shl 30) or (A shr 2);

        MOV     ESI,[EDI + 44]
        XOR     ESI,[EDI + 24]
        XOR     ESI,[EDI]
        XOR     ESI,[EDI + 56]
        ROL     ESI,1
        MOV     [EDI + 56],ESI
        ADD     EDX,ESI
        MOV     [ESP],EAX
        MOV     ESI,EAX
        AND     [ESP],EBX
        OR      ESI,EBX
        AND     ESI,ECX
        OR      ESI,[ESP]
        ROL     EAX,30
        LEA     EDX,[EDX + ESI + $8F1BBCDC]
        MOV     ESI,EBP
        ROL     ESI,5
        ADD     EDX,ESI
                                                    {47}
//  Tmp:= W[12] xor W[7] xor W[1] xor W[15];
//  W[15]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(C,((D shl 5) or (D shr 27)) + ((E and A) or (B and (E or A))) + $8F1BBCDC + W[15]);
//  E:= (E shl 30) or (E shr 2);

        MOV     ESI,[EDI + 48]
        XOR     ESI,[EDI + 28]
        XOR     ESI,[EDI + 4]
        XOR     ESI,[EDI + 60]
        ROL     ESI,1
        MOV     [EDI + 60],ESI
        ADD     ECX,ESI
        MOV     [ESP],EBP
        MOV     ESI,EBP
        AND     [ESP],EAX
        OR      ESI,EAX
        AND     ESI,EBX
        OR      ESI,[ESP]
        ROL     EBP,30
        LEA     ECX,[ECX + ESI + $8F1BBCDC]
        MOV     ESI,EDX
        ROL     ESI,5
        ADD     ECX,ESI
                                                    {48}
//  Tmp:= W[13] xor W[8] xor W[2] xor W[0];
//  W[0]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(B,((C shl 5) or (C shr 27)) + ((D and E) or (A and (D or E))) + $8F1BBCDC + W[0]);
//  D:= (D shl 30) or (D shr 2);

        MOV     ESI,[EDI + 52]
        XOR     ESI,[EDI + 32]
        XOR     ESI,[EDI + 8]
        XOR     ESI,[EDI]
        ROL     ESI,1
        MOV     [EDI],ESI
        ADD     EBX,ESI
        MOV     [ESP],EDX
        MOV     ESI,EDX
        AND     [ESP],EBP
        OR      ESI,EBP
        AND     ESI,EAX
        OR      ESI,[ESP]
        ROL     EDX,30
        LEA     EBX,[EBX + ESI + $8F1BBCDC]
        MOV     ESI,ECX
        ROL     ESI,5
        ADD     EBX,ESI
                                                    {49}
//  Tmp:= W[14] xor W[9] xor W[3] xor W[1];
//  W[1]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(A,((B shl 5) or (B shr 27)) + ((C and D) or (E and (C or D))) + $8F1BBCDC + W[1]);
//  C:= (C shl 30) or (C shr 2);

        MOV     ESI,[EDI + 56]
        XOR     ESI,[EDI + 36]
        XOR     ESI,[EDI + 12]
        XOR     ESI,[EDI + 4]
        ROL     ESI,1
        MOV     [EDI + 4],ESI
        ADD     EAX,ESI
        MOV     [ESP],ECX
        MOV     ESI,ECX
        AND     [ESP],EDX
        OR      ESI,EDX
        AND     ESI,EBP
        OR      ESI,[ESP]
        ROL     ECX,30
        LEA     EAX,[EAX + ESI + $8F1BBCDC]
        MOV     ESI,EBX
        ROL     ESI,5
        ADD     EAX,ESI
                                                    {50}
//  Tmp:= W[15] xor W[10] xor W[4] xor W[2];
//  W[2]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(E,((A shl 5) or (A shr 27)) + ((B and C) or (D and (B or C))) + $8F1BBCDC + W[2]);
//  B:= (B shl 30) or (B shr 2);

        MOV     ESI,[EDI + 60]
        XOR     ESI,[EDI + 40]
        XOR     ESI,[EDI + 16]
        XOR     ESI,[EDI + 8]
        ROL     ESI,1
        MOV     [EDI + 8],ESI
        ADD     EBP,ESI
        MOV     [ESP],EBX
        MOV     ESI,EBX
        AND     [ESP],ECX
        OR      ESI,ECX
        AND     ESI,EDX
        OR      ESI,[ESP]
        ROL     EBX,30
        LEA     EBP,[EBP + ESI + $8F1BBCDC]
        MOV     ESI,EAX
        ROL     ESI,5
        ADD     EBP,ESI
                                                    {51}
//  Tmp:= W[0] xor W[11] xor W[5] xor W[3];
//  W[3]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(D,((E shl 5) or (E shr 27)) + ((A and B) or (C and (A or B))) + $8F1BBCDC + W[3]);
//  A:= (A shl 30) or (A shr 2);

        MOV     ESI,[EDI]
        XOR     ESI,[EDI + 44]
        XOR     ESI,[EDI + 20]
        XOR     ESI,[EDI + 12]
        ROL     ESI,1
        MOV     [EDI + 12],ESI
        ADD     EDX,ESI
        MOV     [ESP],EAX
        MOV     ESI,EAX
        AND     [ESP],EBX
        OR      ESI,EBX
        AND     ESI,ECX
        OR      ESI,[ESP]
        ROL     EAX,30
        LEA     EDX,[EDX + ESI + $8F1BBCDC]
        MOV     ESI,EBP
        ROL     ESI,5
        ADD     EDX,ESI
                                                    {52}
//  Tmp:= W[1] xor W[12] xor W[6] xor W[4];
//  W[4]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(C,((D shl 5) or (D shr 27)) + ((E and A) or (B and (E or A))) + $8F1BBCDC + W[4]);
//  E:= (E shl 30) or (E shr 2);

        MOV     ESI,[EDI + 4]
        XOR     ESI,[EDI + 48]
        XOR     ESI,[EDI + 24]
        XOR     ESI,[EDI + 16]
        ROL     ESI,1
        MOV     [EDI + 16],ESI
        ADD     ECX,ESI
        MOV     [ESP],EBP
        MOV     ESI,EBP
        AND     [ESP],EAX
        OR      ESI,EAX
        AND     ESI,EBX
        OR      ESI,[ESP]
        ROL     EBP,30
        LEA     ECX,[ECX + ESI + $8F1BBCDC]
        MOV     ESI,EDX
        ROL     ESI,5
        ADD     ECX,ESI
                                                    {53}
//  Tmp:= W[2] xor W[13] xor W[7] xor W[5];
//  W[5]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(B,((C shl 5) or (C shr 27)) + ((D and E) or (A and (D or E))) + $8F1BBCDC + W[5]);
//  D:= (D shl 30) or (D shr 2);

        MOV     ESI,[EDI + 8]
        XOR     ESI,[EDI + 52]
        XOR     ESI,[EDI + 28]
        XOR     ESI,[EDI + 20]
        ROL     ESI,1
        MOV     [EDI + 20],ESI
        ADD     EBX,ESI
        MOV     [ESP],EDX
        MOV     ESI,EDX
        AND     [ESP],EBP
        OR      ESI,EBP
        AND     ESI,EAX
        OR      ESI,[ESP]
        ROL     EDX,30
        LEA     EBX,[EBX + ESI + $8F1BBCDC]
        MOV     ESI,ECX
        ROL     ESI,5
        ADD     EBX,ESI
                                                    {54}
//  Tmp:= W[3] xor W[14] xor W[8] xor W[6];
//  W[6]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(A,((B shl 5) or (B shr 27)) + ((C and D) or (E and (C or D))) + $8F1BBCDC + W[6]);
//  C:= (C shl 30) or (C shr 2);

        MOV     ESI,[EDI + 12]
        XOR     ESI,[EDI + 56]
        XOR     ESI,[EDI + 32]
        XOR     ESI,[EDI + 24]
        ROL     ESI,1
        MOV     [EDI + 24],ESI
        ADD     EAX,ESI
        MOV     [ESP],ECX
        MOV     ESI,ECX
        AND     [ESP],EDX
        OR      ESI,EDX
        AND     ESI,EBP
        OR      ESI,[ESP]
        ROL     ECX,30
        LEA     EAX,[EAX + ESI + $8F1BBCDC]
        MOV     ESI,EBX
        ROL     ESI,5
        ADD     EAX,ESI
                                                    {55}
//  Tmp:= W[4] xor W[15] xor W[9] xor W[7];
//  W[7]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(E,((A shl 5) or (A shr 27)) + ((B and C) or (D and (B or C))) + $8F1BBCDC + W[7]);
//  B:= (B shl 30) or (B shr 2);

        MOV     ESI,[EDI + 16]
        XOR     ESI,[EDI + 60]
        XOR     ESI,[EDI + 36]
        XOR     ESI,[EDI + 28]
        ROL     ESI,1
        MOV     [EDI + 28],ESI
        ADD     EBP,ESI
        MOV     [ESP],EBX
        MOV     ESI,EBX
        AND     [ESP],ECX
        OR      ESI,ECX
        AND     ESI,EDX
        OR      ESI,[ESP]
        ROL     EBX,30
        LEA     EBP,[EBP + ESI + $8F1BBCDC]
        MOV     ESI,EAX
        ROL     ESI,5
        ADD     EBP,ESI
                                                    {56}
//  Tmp:= W[5] xor W[0] xor W[10] xor W[8];
//  W[8]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(D,((E shl 5) or (E shr 27)) + ((A and B) or (C and (A or B))) + $8F1BBCDC + W[8]);
//  A:= (A shl 30) or (A shr 2);

        MOV     ESI,[EDI + 20]
        XOR     ESI,[EDI]
        XOR     ESI,[EDI + 40]
        XOR     ESI,[EDI + 32]
        ROL     ESI,1
        MOV     [EDI + 32],ESI
        ADD     EDX,ESI
        MOV     [ESP],EAX
        MOV     ESI,EAX
        AND     [ESP],EBX
        OR      ESI,EBX
        AND     ESI,ECX
        OR      ESI,[ESP]
        ROL     EAX,30
        LEA     EDX,[EDX + ESI + $8F1BBCDC]
        MOV     ESI,EBP
        ROL     ESI,5
        ADD     EDX,ESI
                                                    {57}
//  Tmp:= W[6] xor W[1] xor W[11] xor W[9];
//  W[9]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(C,((D shl 5) or (D shr 27)) + ((E and A) or (B and (E or A))) + $8F1BBCDC + W[9]);
//  E:= (E shl 30) or (E shr 2);

        MOV     ESI,[EDI + 24]
        XOR     ESI,[EDI + 4]
        XOR     ESI,[EDI + 44]
        XOR     ESI,[EDI + 36]
        ROL     ESI,1
        MOV     [EDI + 36],ESI
        ADD     ECX,ESI
        MOV     [ESP],EBP
        MOV     ESI,EBP
        AND     [ESP],EAX
        OR      ESI,EAX
        AND     ESI,EBX
        OR      ESI,[ESP]
        ROL     EBP,30
        LEA     ECX,[ECX + ESI + $8F1BBCDC]
        MOV     ESI,EDX
        ROL     ESI,5
        ADD     ECX,ESI
                                                    {58}
//  Tmp:= W[7] xor W[2] xor W[12] xor W[10];
//  W[10]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(B,((C shl 5) or (C shr 27)) + ((D and E) or (A and (D or E))) + $8F1BBCDC + W[10]);
//  D:= (D shl 30) or (D shr 2);

        MOV     ESI,[EDI + 28]
        XOR     ESI,[EDI + 8]
        XOR     ESI,[EDI + 48]
        XOR     ESI,[EDI + 40]
        ROL     ESI,1
        MOV     [EDI + 40],ESI
        ADD     EBX,ESI
        MOV     [ESP],EDX
        MOV     ESI,EDX
        AND     [ESP],EBP
        OR      ESI,EBP
        AND     ESI,EAX
        OR      ESI,[ESP]
        ROL     EDX,30
        LEA     EBX,[EBX + ESI + $8F1BBCDC]
        MOV     ESI,ECX
        ROL     ESI,5
        ADD     EBX,ESI
                                                    {59}
//  Tmp:= W[8] xor W[3] xor W[13] xor W[11];
//  W[11]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(A,((B shl 5) or (B shr 27)) + ((C and D) or (E and (C or D))) + $8F1BBCDC + W[11]);
//  C:= (C shl 30) or (C shr 2);

        MOV     ESI,[EDI + 32]
        XOR     ESI,[EDI + 12]
        XOR     ESI,[EDI + 52]
        XOR     ESI,[EDI + 44]
        ROL     ESI,1
        MOV     [EDI + 44],ESI
        ADD     EAX,ESI
        MOV     [ESP],ECX
        MOV     ESI,ECX
        AND     [ESP],EDX
        OR      ESI,EDX
        AND     ESI,EBP
        OR      ESI,[ESP]
        ROL     ECX,30
        LEA     EAX,[EAX + ESI + $8F1BBCDC]
        MOV     ESI,EBX
        ROL     ESI,5
        ADD     EAX,ESI
                                                    {60}
//  Tmp:= W[9] xor W[4] xor W[14] xor W[12];
//  W[12]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(E,((A shl 5) or (A shr 27)) + (B xor C xor D) + $CA62C1D6 + W[12]);
//  B:= (B shl 30) or (B shr 2);

        MOV     ESI,[EDI + 36]
        XOR     ESI,[EDI + 16]
        XOR     ESI,[EDI + 56]
        XOR     ESI,[EDI + 48]
        ROL     ESI,1
        MOV     [EDI + 48],ESI
        ADD     EBP,ESI
        MOV     ESI,EBX
        XOR     ESI,ECX
        XOR     ESI,EDX
        ROL     EBX,30
        LEA     EBP,[EBP + ESI + $CA62C1D6]
        MOV     ESI,EAX
        ROL     ESI,5
        ADD     EBP,ESI
                                                    {61}
//  Tmp:= W[10] xor W[5] xor W[15] xor W[13];
//  W[13]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(D,((E shl 5) or (E shr 27)) + (A xor B xor C) + $CA62C1D6 + W[13]);
//  A:= (A shl 30) or (A shr 2);

        MOV     ESI,[EDI + 40]
        XOR     ESI,[EDI + 20]
        XOR     ESI,[EDI + 60]
        XOR     ESI,[EDI + 52]
        ROL     ESI,1
        MOV     [EDI + 52],ESI
        ADD     EDX,ESI
        MOV     ESI,EAX
        XOR     ESI,EBX
        XOR     ESI,ECX
        ROL     EAX,30
        LEA     EDX,[EDX + ESI + $CA62C1D6]
        MOV     ESI,EBP
        ROL     ESI,5
        ADD     EDX,ESI
                                                    {62}
//  Tmp:= W[11] xor W[6] xor W[0] xor W[14];
//  W[14]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(C,((D shl 5) or (D shr 27)) + (E xor A xor B) + $CA62C1D6 + W[14]);
//  E:= (E shl 30) or (E shr 2);

        MOV     ESI,[EDI + 44]
        XOR     ESI,[EDI + 24]
        XOR     ESI,[EDI]
        XOR     ESI,[EDI + 56]
        ROL     ESI,1
        MOV     [EDI + 56],ESI
        ADD     ECX,ESI
        MOV     ESI,EBP
        XOR     ESI,EAX
        XOR     ESI,EBX
        ROL     EBP,30
        LEA     ECX,[ECX + ESI + $CA62C1D6]
        MOV     ESI,EDX
        ROL     ESI,5
        ADD     ECX,ESI
                                                    {63}
//  Tmp:= W[12] xor W[7] xor W[1] xor W[15];
//  W[15]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(B,((C shl 5) or (C shr 27)) + (D xor E xor A) + $CA62C1D6 + W[15]);
//  D:= (D shl 30) or (D shr 2);

        MOV     ESI,[EDI + 48]
        XOR     ESI,[EDI + 28]
        XOR     ESI,[EDI + 4]
        XOR     ESI,[EDI + 60]
        ROL     ESI,1
        MOV     [EDI + 60],ESI
        ADD     EBX,ESI
        MOV     ESI,EDX
        XOR     ESI,EBP
        XOR     ESI,EAX
        ROL     EDX,30
        LEA     EBX,[EBX + ESI + $CA62C1D6]
        MOV     ESI,ECX
        ROL     ESI,5
        ADD     EBX,ESI
                                                    {64}
//  Tmp:= W[13] xor W[8] xor W[2] xor W[0];
//  W[0]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(A,((B shl 5) or (B shr 27)) + (C xor D xor E) + $CA62C1D6 + W[0]);
//  C:= (C shl 30) or (C shr 2);

        MOV     ESI,[EDI + 52]
        XOR     ESI,[EDI + 32]
        XOR     ESI,[EDI + 8]
        XOR     ESI,[EDI]
        ROL     ESI,1
        MOV     [EDI],ESI
        ADD     EAX,ESI
        MOV     ESI,ECX
        XOR     ESI,EDX
        XOR     ESI,EBP
        ROL     ECX,30
        LEA     EAX,[EAX + ESI + $CA62C1D6]
        MOV     ESI,EBX
        ROL     ESI,5
        ADD     EAX,ESI
                                                    {65}
//  Tmp:= W[14] xor W[9] xor W[3] xor W[1];
//  W[1]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(E,((A shl 5) or (A shr 27)) + (B xor C xor D) + $CA62C1D6 + W[1]);
//  B:= (B shl 30) or (B shr 2);

        MOV     ESI,[EDI + 56]
        XOR     ESI,[EDI + 36]
        XOR     ESI,[EDI + 12]
        XOR     ESI,[EDI + 4]
        ROL     ESI,1
        MOV     [EDI + 4],ESI
        ADD     EBP,ESI
        MOV     ESI,EBX
        XOR     ESI,ECX
        XOR     ESI,EDX
        ROL     EBX,30
        LEA     EBP,[EBP + ESI + $CA62C1D6]
        MOV     ESI,EAX
        ROL     ESI,5
        ADD     EBP,ESI
                                                    {66}
//  Tmp:= W[15] xor W[10] xor W[4] xor W[2];
//  W[2]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(D,((E shl 5) or (E shr 27)) + (A xor B xor C) + $CA62C1D6 + W[2]);
//  A:= (A shl 30) or (A shr 2);

        MOV     ESI,[EDI + 60]
        XOR     ESI,[EDI + 40]
        XOR     ESI,[EDI + 16]
        XOR     ESI,[EDI + 8]
        ROL     ESI,1
        MOV     [EDI + 8],ESI
        ADD     EDX,ESI
        MOV     ESI,EAX
        XOR     ESI,EBX
        XOR     ESI,ECX
        ROL     EAX,30
        LEA     EDX,[EDX + ESI + $CA62C1D6]
        MOV     ESI,EBP
        ROL     ESI,5
        ADD     EDX,ESI
                                                    {67}
//  Tmp:= W[0] xor W[11] xor W[5] xor W[3];
//  W[3]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(C,((D shl 5) or (D shr 27)) + (E xor A xor B) + $CA62C1D6 + W[3]);
//  E:= (E shl 30) or (E shr 2);

        MOV     ESI,[EDI]
        XOR     ESI,[EDI + 44]
        XOR     ESI,[EDI + 20]
        XOR     ESI,[EDI + 12]
        ROL     ESI,1
        MOV     [EDI + 12],ESI
        ADD     ECX,ESI
        MOV     ESI,EBP
        XOR     ESI,EAX
        XOR     ESI,EBX
        ROL     EBP,30
        LEA     ECX,[ECX + ESI + $CA62C1D6]
        MOV     ESI,EDX
        ROL     ESI,5
        ADD     ECX,ESI
                                                    {68}
//  Tmp:= W[1] xor W[12] xor W[6] xor W[4];
//  W[4]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(B,((C shl 5) or (C shr 27)) + (D xor E xor A) + $CA62C1D6 + W[4]);
//  D:= (D shl 30) or (D shr 2);

        MOV     ESI,[EDI + 4]
        XOR     ESI,[EDI + 48]
        XOR     ESI,[EDI + 24]
        XOR     ESI,[EDI + 16]
        ROL     ESI,1
        MOV     [EDI + 16],ESI
        ADD     EBX,ESI
        MOV     ESI,EDX
        XOR     ESI,EBP
        XOR     ESI,EAX
        ROL     EDX,30
        LEA     EBX,[EBX + ESI + $CA62C1D6]
        MOV     ESI,ECX
        ROL     ESI,5
        ADD     EBX,ESI
                                                    {69}
//  Tmp:= W[2] xor W[13] xor W[7] xor W[5];
//  W[5]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(A,((B shl 5) or (B shr 27)) + (C xor D xor E) + $CA62C1D6 + W[5]);
//  C:= (C shl 30) or (C shr 2);

        MOV     ESI,[EDI + 8]
        XOR     ESI,[EDI + 52]
        XOR     ESI,[EDI + 28]
        XOR     ESI,[EDI + 20]
        ROL     ESI,1
        MOV     [EDI + 20],ESI
        ADD     EAX,ESI
        MOV     ESI,ECX
        XOR     ESI,EDX
        XOR     ESI,EBP
        ROL     ECX,30
        LEA     EAX,[EAX + ESI + $CA62C1D6]
        MOV     ESI,EBX
        ROL     ESI,5
        ADD     EAX,ESI
                                                    {70}
//  Tmp:= W[3] xor W[14] xor W[8] xor W[6];
//  W[6]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(E,((A shl 5) or (A shr 27)) + (B xor C xor D) + $CA62C1D6 + W[6]);
//  B:= (B shl 30) or (B shr 2);

        MOV     ESI,[EDI + 12]
        XOR     ESI,[EDI + 56]
        XOR     ESI,[EDI + 32]
        XOR     ESI,[EDI + 24]
        ROL     ESI,1
        MOV     [EDI + 24],ESI
        ADD     EBP,ESI
        MOV     ESI,EBX
        XOR     ESI,ECX
        XOR     ESI,EDX
        ROL     EBX,30
        LEA     EBP,[EBP + ESI + $CA62C1D6]
        MOV     ESI,EAX
        ROL     ESI,5
        ADD     EBP,ESI
                                                    {71}
//  Tmp:= W[4] xor W[15] xor W[9] xor W[7];
//  W[7]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(D,((E shl 5) or (E shr 27)) + (A xor B xor C) + $CA62C1D6 + W[7]);
//  A:= (A shl 30) or (A shr 2);

        MOV     ESI,[EDI + 16]
        XOR     ESI,[EDI + 60]
        XOR     ESI,[EDI + 36]
        XOR     ESI,[EDI + 28]
        ROL     ESI,1
        MOV     [EDI + 28],ESI
        ADD     EDX,ESI
        MOV     ESI,EAX
        XOR     ESI,EBX
        XOR     ESI,ECX
        ROL     EAX,30
        LEA     EDX,[EDX + ESI + $CA62C1D6]
        MOV     ESI,EBP
        ROL     ESI,5
        ADD     EDX,ESI
                                                    {72}
//  Tmp:= W[5] xor W[0] xor W[10] xor W[8];
//  W[8]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(C,((D shl 5) or (D shr 27)) + (E xor A xor B) + $CA62C1D6 + W[8]);
//  E:= (E shl 30) or (E shr 2);

        MOV     ESI,[EDI + 20]
        XOR     ESI,[EDI]
        XOR     ESI,[EDI + 40]
        XOR     ESI,[EDI + 32]
        ROL     ESI,1
        MOV     [EDI + 32],ESI
        ADD     ECX,ESI
        MOV     ESI,EBP
        XOR     ESI,EAX
        XOR     ESI,EBX
        ROL     EBP,30
        LEA     ECX,[ECX + ESI + $CA62C1D6]
        MOV     ESI,EDX
        ROL     ESI,5
        ADD     ECX,ESI
                                                    {73}
//  Tmp:= W[6] xor W[1] xor W[11] xor W[9];
//  W[9]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(B,((C shl 5) or (C shr 27)) + (D xor E xor A) + $CA62C1D6 + W[9]);
//  D:= (D shl 30) or (D shr 2);

        MOV     ESI,[EDI + 24]
        XOR     ESI,[EDI + 4]
        XOR     ESI,[EDI + 44]
        XOR     ESI,[EDI + 36]
        ROL     ESI,1
        MOV     [EDI + 36],ESI
        ADD     EBX,ESI
        MOV     ESI,EDX
        XOR     ESI,EBP
        XOR     ESI,EAX
        ROL     EDX,30
        LEA     EBX,[EBX + ESI + $CA62C1D6]
        MOV     ESI,ECX
        ROL     ESI,5
        ADD     EBX,ESI
                                                    {74}
//  Tmp:= W[7] xor W[2] xor W[12] xor W[10];
//  W[10]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(A,((B shl 5) or (B shr 27)) + (C xor D xor E) + $CA62C1D6 + W[10]);
//  C:= (C shl 30) or (C shr 2);

        MOV     ESI,[EDI + 28]
        XOR     ESI,[EDI + 8]
        XOR     ESI,[EDI + 48]
        XOR     ESI,[EDI + 40]
        ROL     ESI,1
        MOV     [EDI + 40],ESI
        ADD     EAX,ESI
        MOV     ESI,ECX
        XOR     ESI,EDX
        XOR     ESI,EBP
        ROL     ECX,30
        LEA     EAX,[EAX + ESI + $CA62C1D6]
        MOV     ESI,EBX
        ROL     ESI,5
        ADD     EAX,ESI
                                                    {75}
//  Tmp:= W[8] xor W[3] xor W[13] xor W[11];
//  W[11]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(E,((A shl 5) or (A shr 27)) + (B xor C xor D) + $CA62C1D6 + W[11]);
//  B:= (B shl 30) or (B shr 2);

        MOV     ESI,[EDI + 32]
        XOR     ESI,[EDI + 12]
        XOR     ESI,[EDI + 52]
        XOR     ESI,[EDI + 44]
        ROL     ESI,1
        MOV     [EDI + 44],ESI
        ADD     EBP,ESI
        MOV     ESI,EBX
        XOR     ESI,ECX
        XOR     ESI,EDX
        ROL     EBX,30
        LEA     EBP,[EBP + ESI + $CA62C1D6]
        MOV     ESI,EAX
        ROL     ESI,5
        ADD     EBP,ESI
                                                    {76}
//  Tmp:= W[9] xor W[4] xor W[14] xor W[12];
//  W[12]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(D,((E shl 5) or (E shr 27)) + (A xor B xor C) + $CA62C1D6 + W[12]);
//  A:= (A shl 30) or (A shr 2);

        MOV     ESI,[EDI + 36]
        XOR     ESI,[EDI + 16]
        XOR     ESI,[EDI + 56]
        XOR     ESI,[EDI + 48]
        ROL     ESI,1
        MOV     [EDI + 48],ESI
        ADD     EDX,ESI
        MOV     ESI,EAX
        XOR     ESI,EBX
        XOR     ESI,ECX
        ROL     EAX,30
        LEA     EDX,[EDX + ESI + $CA62C1D6]
        MOV     ESI,EBP
        ROL     ESI,5
        ADD     EDX,ESI
                                                    {77}
//  Tmp:= W[10] xor W[5] xor W[15] xor W[13];
//  W[13]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(C,((D shl 5) or (D shr 27)) + (E xor A xor B) + $CA62C1D6 + W[13]);
//  E:= (E shl 30) or (E shr 2);

        MOV     ESI,[EDI + 40]
        XOR     ESI,[EDI + 20]
        XOR     ESI,[EDI + 60]
        XOR     ESI,[EDI + 52]
        ROL     ESI,1
//        MOV     [EDI + 52],ESI
        ADD     ECX,ESI
        MOV     ESI,EBP
        XOR     ESI,EAX
        XOR     ESI,EBX
        ROL     EBP,30
        LEA     ECX,[ECX + ESI + $CA62C1D6]
        MOV     ESI,EDX
        ROL     ESI,5
        ADD     ECX,ESI
                                                    {78}
//  Tmp:= W[11] xor W[6] xor W[0] xor W[14];
//  W[14]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(B,((C shl 5) or (C shr 27)) + (D xor E xor A) + $CA62C1D6 + W[14]);
//  D:= (D shl 30) or (D shr 2);

        MOV     ESI,[EDI + 44]
        XOR     ESI,[EDI + 24]
        XOR     ESI,[EDI]
        XOR     ESI,[EDI + 56]
        ROL     ESI,1
//        MOV     [EDI + 56],ESI
        ADD     EBX,ESI
        MOV     ESI,EDX
        XOR     ESI,EBP
        XOR     ESI,EAX
        ROL     EDX,30
        LEA     EBX,[EBX + ESI + $CA62C1D6]
        MOV     ESI,ECX
        ROL     ESI,5
        ADD     EBX,ESI
                                                    {79}
//  Tmp:= W[12] xor W[7] xor W[1] xor W[15];
//  W[15]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(A,((B shl 5) or (B shr 27)) + (C xor D xor E) + $CA62C1D6 + W[15]);
//  C:= (C shl 30) or (C shr 2);

        MOV     ESI,[EDI + 48]
        XOR     ESI,[EDI + 28]
        XOR     ESI,[EDI + 4]
        XOR     ESI,[EDI + 60]
        ROL     ESI,1
//        MOV     [EDI + 60],ESI
        ADD     EAX,ESI
        MOV     ESI,ECX
        XOR     ESI,EDX
        XOR     ESI,EBP
        ROL     ECX,30
        LEA     EAX,[EAX + ESI + $CA62C1D6]
        MOV     ESI,EBX
        ROL     ESI,5
        ADD     EAX,ESI


        ADD     [EDI - 20],EAX      // Inc(FData.Digest[0], A);
        ADD     [EDI - 16],EBX      // Inc(FData.Digest[1], B);
        ADD     [EDI - 12],ECX      // Inc(FData.Digest[2], C);
        ADD     [EDI - 8],EDX       // Inc(FData.Digest[3], D);
        ADD     [EDI - 4],EBP       // Inc(FData.Digest[4], E);

                                  //  FillChar(Block, SizeOf(Block), 0);
        XOR     EAX,EAX
//        MOV     [ESP],EAX
        MOV     [EDI],EAX
        MOV     [EDI + 4],EAX
        MOV     [EDI + 8],EAX
        MOV     [EDI + 12],EAX
        MOV     [EDI + 16],EAX
        MOV     [EDI + 20],EAX
        MOV     [EDI + 24],EAX
        MOV     [EDI + 28],EAX
        MOV     [EDI + 32],EAX
        MOV     [EDI + 36],EAX
        MOV     [EDI + 40],EAX
        MOV     [EDI + 44],EAX
        MOV     [EDI + 48],EAX
        MOV     [EDI + 52],EAX
        MOV     [EDI + 56],EAX
        MOV     [EDI + 60],EAX

        POP     EAX
        POP     EBP
        POP     EBX
        POP     EDI
        POP     ESI
end;
{$ELSE}
{$IFDEF CPUX64_WIN64}
procedure TSHA1Alg.Compress;{$IFDEF FPC}assembler; nostackframe;{$ENDIF}
asm
{$IFNDEF FPC}
        .NOFRAME
{$ENDIF}
        PUSH    RSI
        PUSH    RDI
        PUSH    RBX
        PUSH    RBP
        SUB     RSP,8

        LEA     R8,[RCX].TSHA1Alg.FData.Block    // W:= @FData.Block;

        MOV     EAX,[R8 - 20]       // A:= FData.Digest[0];
        MOV     EBX,[R8 - 16]       // B:= FData.Digest[1];
        MOV     ECX,[R8 - 12]       // C:= FData.Digest[2];
        MOV     EDX,[R8 - 8]        // D:= FData.Digest[3];
        MOV     EBP,[R8 - 4]        // E:= FData.Digest[4];

                                                    { 0}
//  W[0]:= Swap32(W[0]);
//  Inc(E,((A shl 5) or (A shr 27)) + (D xor (B and (C xor D))) + $5A827999 + W[0]);
//  B:= (B shl 30) or (B shr 2);

        MOV     ESI,[R8]
        BSWAP   ESI
        MOV     [R8],ESI
        ADD     EBP,ESI
        MOV     ESI,ECX
        XOR     ESI,EDX
        AND     ESI,EBX
        XOR     ESI,EDX
        ROL     EBX,30
        LEA     EBP,[RBP + RSI + $5A827999]
        MOV     ESI,EAX
        ROL     ESI,5
        ADD     EBP,ESI
                                                    { 1}
//  W[1]:= Swap32(W[1]);
//  Inc(D,((E shl 5) or (E shr 27)) + (C xor (A and (B xor C))) + $5A827999 + W[1]);
//  A:= (A shl 30) or (A shr 2);

        MOV     ESI,[R8 + 4]
        BSWAP   ESI
        MOV     [R8 + 4],ESI
        ADD     EDX,ESI
        MOV     ESI,EBX
        XOR     ESI,ECX
        AND     ESI,EAX
        XOR     ESI,ECX
        ROL     EAX,30
        LEA     EDX,[RDX + RSI + $5A827999]
        MOV     ESI,EBP
        ROL     ESI,5
        ADD     EDX,ESI
                                                    { 2}
//  W[2]:= Swap32(W[2]);
//  Inc(C,((D shl 5) or (D shr 27)) + (B xor (E and (A xor B))) + $5A827999 + W[2]);
//  E:= (E shl 30) or (E shr 2);

        MOV     ESI,[R8 + 8]
        BSWAP   ESI
        MOV     [R8 + 8],ESI
        ADD     ECX,ESI
        MOV     ESI,EAX
        XOR     ESI,EBX
        AND     ESI,EBP
        XOR     ESI,EBX
        ROL     EBP,30
        LEA     ECX,[RCX + RSI + $5A827999]
        MOV     ESI,EDX
        ROL     ESI,5
        ADD     ECX,ESI
                                                    { 3}
//  W[3]:= Swap32(W[3]);
//  Inc(B,((C shl 5) or (C shr 27)) + (A xor (D and (E xor A))) + $5A827999 + W[3]);
//  D:= (D shl 30) or (D shr 2);

        MOV     ESI,[R8 + 12]
        BSWAP   ESI
        MOV     [R8 + 12],ESI
        ADD     EBX,ESI
        MOV     ESI,EBP
        XOR     ESI,EAX
        AND     ESI,EDX
        XOR     ESI,EAX
        ROL     EDX,30
        LEA     EBX,[RBX + RSI + $5A827999]
        MOV     ESI,ECX
        ROL     ESI,5
        ADD     EBX,ESI
                                                    { 4}
//  W[4]:= Swap32(W[4]);
//  Inc(A,((B shl 5) or (B shr 27)) + (E xor (C and (D xor E))) + $5A827999 + W[4]);
//  C:= (C shl 30) or (C shr 2);

        MOV     ESI,[R8 + 16]
        BSWAP   ESI
        MOV     [R8 + 16],ESI
        ADD     EAX,ESI
        MOV     ESI,EDX
        XOR     ESI,EBP
        AND     ESI,ECX
        XOR     ESI,EBP
        ROL     ECX,30
        LEA     EAX,[RAX + RSI + $5A827999]
        MOV     ESI,EBX
        ROL     ESI,5
        ADD     EAX,ESI
                                                    { 5}
//  W[5]:= Swap32(W[5]);
//  Inc(E,((A shl 5) or (A shr 27)) + (D xor (B and (C xor D))) + $5A827999 + W[5]);
//  B:= (B shl 30) or (B shr 2);

        MOV     ESI,[R8 + 20]
        BSWAP   ESI
        MOV     [R8 + 20],ESI
        ADD     EBP,ESI
        MOV     ESI,ECX
        XOR     ESI,EDX
        AND     ESI,EBX
        XOR     ESI,EDX
        ROL     EBX,30
        LEA     EBP,[RBP + RSI + $5A827999]
        MOV     ESI,EAX
        ROL     ESI,5
        ADD     EBP,ESI
                                                    { 6}
//  W[6]:= Swap32(W[6]);
//  Inc(D,((E shl 5) or (E shr 27)) + (C xor (A and (B xor C))) + $5A827999 + W[6]);
//  A:= (A shl 30) or (A shr 2);

        MOV     ESI,[R8 + 24]
        BSWAP   ESI
        MOV     [R8 + 24],ESI
        ADD     EDX,ESI
        MOV     ESI,EBX
        XOR     ESI,ECX
        AND     ESI,EAX
        XOR     ESI,ECX
        ROL     EAX,30
        LEA     EDX,[RDX + RSI + $5A827999]
        MOV     ESI,EBP
        ROL     ESI,5
        ADD     EDX,ESI
                                                    { 7}
//  W[7]:= Swap32(W[7]);
//  Inc(C,((D shl 5) or (D shr 27)) + (B xor (E and (A xor B))) + $5A827999 + W[7]);
//  E:= (E shl 30) or (E shr 2);

        MOV     ESI,[R8 + 28]
        BSWAP   ESI
        MOV     [R8 + 28],ESI
        ADD     ECX,ESI
        MOV     ESI,EAX
        XOR     ESI,EBX
        AND     ESI,EBP
        XOR     ESI,EBX
        ROL     EBP,30
        LEA     ECX,[RCX + RSI + $5A827999]
        MOV     ESI,EDX
        ROL     ESI,5
        ADD     ECX,ESI
                                                    { 8}
//  W[8]:= Swap32(W[8]);
//  Inc(B,((C shl 5) or (C shr 27)) + (A xor (D and (E xor A))) + $5A827999 + W[8]);
//  D:= (D shl 30) or (D shr 2);

        MOV     ESI,[R8 + 32]
        BSWAP   ESI
        MOV     [R8 + 32],ESI
        ADD     EBX,ESI
        MOV     ESI,EBP
        XOR     ESI,EAX
        AND     ESI,EDX
        XOR     ESI,EAX
        ROL     EDX,30
        LEA     EBX,[RBX + RSI + $5A827999]
        MOV     ESI,ECX
        ROL     ESI,5
        ADD     EBX,ESI
                                                    { 9}
//  W[9]:= Swap32(W[9]);
//  Inc(A,((B shl 5) or (B shr 27)) + (E xor (C and (D xor E))) + $5A827999 + W[9]);
//  C:= (C shl 30) or (C shr 2);
                                    { 9}
        MOV     ESI,[R8 + 36]
        BSWAP   ESI
        MOV     [R8 + 36],ESI
        ADD     EAX,ESI
        MOV     ESI,EDX
        XOR     ESI,EBP
        AND     ESI,ECX
        XOR     ESI,EBP
        ROL     ECX,30
        LEA     EAX,[RAX + RSI + $5A827999]
        MOV     ESI,EBX
        ROL     ESI,5
        ADD     EAX,ESI
                                                    {10}
//  W[10]:= Swap32(W[10]);
//  Inc(E,((A shl 5) or (A shr 27)) + (D xor (B and (C xor D))) + $5A827999 + W[10]);
//  B:= (B shl 30) or (B shr 2);

        MOV     ESI,[R8 + 40]
        BSWAP   ESI
        MOV     [R8 + 40],ESI
        ADD     EBP,ESI
        MOV     ESI,ECX
        XOR     ESI,EDX
        AND     ESI,EBX
        XOR     ESI,EDX
        ROL     EBX,30
        LEA     EBP,[RBP + RSI + $5A827999]
        MOV     ESI,EAX
        ROL     ESI,5
        ADD     EBP,ESI
                                                    {11}
//  W[11]:= Swap32(W[11]);
//  Inc(D,((E shl 5) or (E shr 27)) + (C xor (A and (B xor C))) + $5A827999 + W[11]);
//  A:= (A shl 30) or (A shr 2);

        MOV     ESI,[R8 + 44]
        BSWAP   ESI
        MOV     [R8 + 44],ESI
        ADD     EDX,ESI
        MOV     ESI,EBX
        XOR     ESI,ECX
        AND     ESI,EAX
        XOR     ESI,ECX
        ROL     EAX,30
        LEA     EDX,[RDX + RSI + $5A827999]
        MOV     ESI,EBP
        ROL     ESI,5
        ADD     EDX,ESI
                                                    {12}
//  W[12]:= Swap32(W[12]);
//  Inc(C,((D shl 5) or (D shr 27)) + (B xor (E and (A xor B))) + $5A827999 + W[12]);
//  E:= (E shl 30) or (E shr 2);

        MOV     ESI,[R8 + 48]
        BSWAP   ESI
        MOV     [R8 + 48],ESI
        ADD     ECX,ESI
        MOV     ESI,EAX
        XOR     ESI,EBX
        AND     ESI,EBP
        XOR     ESI,EBX
        ROL     EBP,30
        LEA     ECX,[RCX + RSI + $5A827999]
        MOV     ESI,EDX
        ROL     ESI,5
        ADD     ECX,ESI
                                                    {13}
//  W[13]:= Swap32(W[13]);
//  Inc(B,((C shl 5) or (C shr 27)) + (A xor (D and (E xor A))) + $5A827999 + W[13]);
//  D:= (D shl 30) or (D shr 2);

        MOV     ESI,[R8 + 52]
        BSWAP   ESI
        MOV     [R8 + 52],ESI
        ADD     EBX,ESI
        MOV     ESI,EBP
        XOR     ESI,EAX
        AND     ESI,EDX
        XOR     ESI,EAX
        ROL     EDX,30
        LEA     EBX,[RBX + RSI + $5A827999]
        MOV     ESI,ECX
        ROL     ESI,5
        ADD     EBX,ESI
                                                    {14}
//  W[14]:= Swap32(W[14]);
//  Inc(A,((B shl 5) or (B shr 27)) + (E xor (C and (D xor E))) + $5A827999 + W[14]);
//  C:= (C shl 30) or (C shr 2);

        MOV     ESI,[R8 + 56]
        BSWAP   ESI
        MOV     [R8 + 56],ESI
        ADD     EAX,ESI
        MOV     ESI,EDX
        XOR     ESI,EBP
        AND     ESI,ECX
        XOR     ESI,EBP
        ROL     ECX,30
        LEA     EAX,[RAX + RSI + $5A827999]
        MOV     ESI,EBX
        ROL     ESI,5
        ADD     EAX,ESI
                                                    {15}
//  W[15]:= Swap32(W[15]);
//  Inc(E,((A shl 5) or (A shr 27)) + (D xor (B and (C xor D))) + $5A827999 + W[15]);
//  B:= (B shl 30) or (B shr 2);

        MOV     ESI,[R8 + 60]
        BSWAP   ESI
        MOV     [R8 + 60],ESI
        ADD     EBP,ESI
        MOV     ESI,ECX
        XOR     ESI,EDX
        AND     ESI,EBX
        XOR     ESI,EDX
        ROL     EBX,30
        LEA     EBP,[RBP + RSI + $5A827999]
        MOV     ESI,EAX
        ROL     ESI,5
        ADD     EBP,ESI

                                                    {16}
//  Tmp:= W[13] xor W[8] xor W[2] xor W[0];
//  W[0]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(D,((E shl 5) or (E shr 27)) + (C xor (A and (B xor C))) + $5A827999 + W[0]);
//  A:= (A shl 30) or (A shr 2);

        MOV     ESI,[R8 + 52]
        XOR     ESI,[R8 + 32]
        XOR     ESI,[R8 + 8]
        XOR     ESI,[R8]
        ROL     ESI,1
        MOV     [R8],ESI
        ADD     EDX,ESI
        MOV     ESI,EBX
        XOR     ESI,ECX
        AND     ESI,EAX
        XOR     ESI,ECX
        ROL     EAX,30
        LEA     EDX,[RDX + RSI + $5A827999]
        MOV     ESI,EBP
        ROL     ESI,5
        ADD     EDX,ESI
                                                    {17}
//  Tmp:= W[14] xor W[9] xor W[3] xor W[1];
//  W[1]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(C,((D shl 5) or (D shr 27)) + (B xor (E and (A xor B))) + $5A827999 + W[1]);
//  E:= (E shl 30) or (E shr 2);

        MOV     ESI,[R8 + 56]
        XOR     ESI,[R8 + 36]
        XOR     ESI,[R8 + 12]
        XOR     ESI,[R8 + 4]
        ROL     ESI,1
        MOV     [R8 + 4],ESI
        ADD     ECX,ESI
        MOV     ESI,EAX
        XOR     ESI,EBX
        AND     ESI,EBP
        XOR     ESI,EBX
        ROL     EBP,30
        LEA     ECX,[RCX + RSI + $5A827999]
        MOV     ESI,EDX
        ROL     ESI,5
        ADD     ECX,ESI
                                                    {18}
//  Tmp:= W[15] xor W[10] xor W[4] xor W[2];
//  W[2]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(B,((C shl 5) or (C shr 27)) + (A xor (D and (E xor A))) + $5A827999 + W[2]);
//  D:= (D shl 30) or (D shr 2);

        MOV     ESI,[R8 + 60]
        XOR     ESI,[R8 + 40]
        XOR     ESI,[R8 + 16]
        XOR     ESI,[R8 + 8]
        ROL     ESI,1
        MOV     [R8 + 8],ESI
        ADD     EBX,ESI
        MOV     ESI,EBP
        XOR     ESI,EAX
        AND     ESI,EDX
        XOR     ESI,EAX
        ROL     EDX,30
        LEA     EBX,[RBX + RSI + $5A827999]
        MOV     ESI,ECX
        ROL     ESI,5
        ADD     EBX,ESI
                                                    {19}
//  Tmp:= W[0] xor W[11] xor W[5] xor W[3];
//  W[3]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(A,((B shl 5) or (B shr 27)) + (E xor (C and (D xor E))) + $5A827999 + W[3]);
//  C:= (C shl 30) or (C shr 2);

        MOV     ESI,[R8]
        XOR     ESI,[R8 + 44]
        XOR     ESI,[R8 + 20]
        XOR     ESI,[R8 + 12]
        ROL     ESI,1
        MOV     [R8 + 12],ESI
        ADD     EAX,ESI
        MOV     ESI,EDX
        XOR     ESI,EBP
        AND     ESI,ECX
        XOR     ESI,EBP
        ROL     ECX,30
        LEA     EAX,[RAX + RSI + $5A827999]
        MOV     ESI,EBX
        ROL     ESI,5
        ADD     EAX,ESI
                                                    {20}
//  Tmp:= W[1] xor W[12] xor W[6] xor W[4];
//  W[4]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(E,((A shl 5) or (A shr 27)) + (B xor C xor D) + $6ED9EBA1 + W[4]);
//  B:= (B shl 30) or (B shr 2);

        MOV     ESI,[R8 + 4]
        XOR     ESI,[R8 + 48]
        XOR     ESI,[R8 + 24]
        XOR     ESI,[R8 + 16]
        ROL     ESI,1
        MOV     [R8 + 16],ESI
        ADD     EBP,ESI
        MOV     ESI,EBX
        XOR     ESI,ECX
        XOR     ESI,EDX
        ROL     EBX,30
        LEA     EBP,[RBP + RSI + $6ED9EBA1]
        MOV     ESI,EAX
        ROL     ESI,5
        ADD     EBP,ESI
                                                    {21}
//  Tmp:= W[2] xor W[13] xor W[7] xor W[5];
//  W[5]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(D,((E shl 5) or (E shr 27)) + (A xor B xor C) + $6ED9EBA1 + W[5]);
//  A:= (A shl 30) or (A shr 2);

        MOV     ESI,[R8 + 8]
        XOR     ESI,[R8 + 52]
        XOR     ESI,[R8 + 28]
        XOR     ESI,[R8 + 20]
        ROL     ESI,1
        MOV     [R8 + 20],ESI
        ADD     EDX,ESI
        MOV     ESI,EAX
        XOR     ESI,EBX
        XOR     ESI,ECX
        ROL     EAX,30
        LEA     EDX,[RDX + RSI + $6ED9EBA1]
        MOV     ESI,EBP
        ROL     ESI,5
        ADD     EDX,ESI
                                                    {22}
//  Tmp:= W[3] xor W[14] xor W[8] xor W[6];
//  W[6]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(C,((D shl 5) or (D shr 27)) + (E xor A xor B) + $6ED9EBA1 + W[6]);
//  E:= (E shl 30) or (E shr 2);

        MOV     ESI,[R8 + 12]
        XOR     ESI,[R8 + 56]
        XOR     ESI,[R8 + 32]
        XOR     ESI,[R8 + 24]
        ROL     ESI,1
        MOV     [R8 + 24],ESI
        ADD     ECX,ESI
        MOV     ESI,EBP
        XOR     ESI,EAX
        XOR     ESI,EBX
        ROL     EBP,30
        LEA     ECX,[RCX + RSI + $6ED9EBA1]
        MOV     ESI,EDX
        ROL     ESI,5
        ADD     ECX,ESI
                                                    {23}
//  Tmp:= W[4] xor W[15] xor W[9] xor W[7];
//  W[7]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(B,((C shl 5) or (C shr 27)) + (D xor E xor A) + $6ED9EBA1 + W[7]);
//  D:= (D shl 30) or (D shr 2);

        MOV     ESI,[R8 + 16]
        XOR     ESI,[R8 + 60]
        XOR     ESI,[R8 + 36]
        XOR     ESI,[R8 + 28]
        ROL     ESI,1
        MOV     [R8 + 28],ESI
        ADD     EBX,ESI
        MOV     ESI,EDX
        XOR     ESI,EBP
        XOR     ESI,EAX
        ROL     EDX,30
        LEA     EBX,[RBX + RSI + $6ED9EBA1]
        MOV     ESI,ECX
        ROL     ESI,5
        ADD     EBX,ESI
                                                    {24}
//  Tmp:= W[5] xor W[0] xor W[10] xor W[8];
//  W[8]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(A,((B shl 5) or (B shr 27)) + (C xor D xor E) + $6ED9EBA1 + W[8]);
//  C:= (C shl 30) or (C shr 2);

        MOV     ESI,[R8 + 20]
        XOR     ESI,[R8]
        XOR     ESI,[R8 + 40]
        XOR     ESI,[R8 + 32]
        ROL     ESI,1
        MOV     [R8 + 32],ESI
        ADD     EAX,ESI
        MOV     ESI,ECX
        XOR     ESI,EDX
        XOR     ESI,EBP
        ROL     ECX,30
        LEA     EAX,[RAX + RSI + $6ED9EBA1]
        MOV     ESI,EBX
        ROL     ESI,5
        ADD     EAX,ESI
                                                    {25}
//  Tmp:= W[6] xor W[1] xor W[11] xor W[9];
//  W[9]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(E,((A shl 5) or (A shr 27)) + (B xor C xor D) + $6ED9EBA1 + W[9]);
//  B:= (B shl 30) or (B shr 2);

        MOV     ESI,[R8 + 24]
        XOR     ESI,[R8 + 4]
        XOR     ESI,[R8 + 44]
        XOR     ESI,[R8 + 36]
        ROL     ESI,1
        MOV     [R8 + 36],ESI
        ADD     EBP,ESI
        MOV     ESI,EBX
        XOR     ESI,ECX
        XOR     ESI,EDX
        ROL     EBX,30
        LEA     EBP,[RBP + RSI + $6ED9EBA1]
        MOV     ESI,EAX
        ROL     ESI,5
        ADD     EBP,ESI
                                                    {26}
//  Tmp:= W[7] xor W[2] xor W[12] xor W[10];
//  W[10]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(D,((E shl 5) or (E shr 27)) + (A xor B xor C) + $6ED9EBA1 + W[10]);
//  A:= (A shl 30) or (A shr 2);

        MOV     ESI,[R8 + 28]
        XOR     ESI,[R8 + 8]
        XOR     ESI,[R8 + 48]
        XOR     ESI,[R8 + 40]
        ROL     ESI,1
        MOV     [R8 + 40],ESI
        ADD     EDX,ESI
        MOV     ESI,EAX
        XOR     ESI,EBX
        XOR     ESI,ECX
        ROL     EAX,30
        LEA     EDX,[RDX + RSI + $6ED9EBA1]
        MOV     ESI,EBP
        ROL     ESI,5
        ADD     EDX,ESI
                                                    {27}
//  Tmp:= W[8] xor W[3] xor W[13] xor W[11];
//  W[11]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(C,((D shl 5) or (D shr 27)) + (E xor A xor B) + $6ED9EBA1 + W[11]);
//  E:= (E shl 30) or (E shr 2);

        MOV     ESI,[R8 + 32]
        XOR     ESI,[R8 + 12]
        XOR     ESI,[R8 + 52]
        XOR     ESI,[R8 + 44]
        ROL     ESI,1
        MOV     [R8 + 44],ESI
        ADD     ECX,ESI
        MOV     ESI,EBP
        XOR     ESI,EAX
        XOR     ESI,EBX
        ROL     EBP,30
        LEA     ECX,[RCX + RSI + $6ED9EBA1]
        MOV     ESI,EDX
        ROL     ESI,5
        ADD     ECX,ESI
                                                    {28}
//  Tmp:= W[9] xor W[4] xor W[14] xor W[12];
//  W[12]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(B,((C shl 5) or (C shr 27)) + (D xor E xor A) + $6ED9EBA1 + W[12]);
//  D:= (D shl 30) or (D shr 2);

        MOV     ESI,[R8 + 36]
        XOR     ESI,[R8 + 16]
        XOR     ESI,[R8 + 56]
        XOR     ESI,[R8 + 48]
        ROL     ESI,1
        MOV     [R8 + 48],ESI
        ADD     EBX,ESI
        MOV     ESI,EDX
        XOR     ESI,EBP
        XOR     ESI,EAX
        ROL     EDX,30
        LEA     EBX,[RBX + RSI + $6ED9EBA1]
        MOV     ESI,ECX
        ROL     ESI,5
        ADD     EBX,ESI
                                                    {29}
//  Tmp:= W[10] xor W[5] xor W[15] xor W[13];
//  W[13]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(A,((B shl 5) or (B shr 27)) + (C xor D xor E) + $6ED9EBA1 + W[13]);
//  C:= (C shl 30) or (C shr 2);

        MOV     ESI,[R8 + 40]
        XOR     ESI,[R8 + 20]
        XOR     ESI,[R8 + 60]
        XOR     ESI,[R8 + 52]
        ROL     ESI,1
        MOV     [R8 + 52],ESI
        ADD     EAX,ESI
        MOV     ESI,ECX
        XOR     ESI,EDX
        XOR     ESI,EBP
        ROL     ECX,30
        LEA     EAX,[RAX + RSI + $6ED9EBA1]
        MOV     ESI,EBX
        ROL     ESI,5
        ADD     EAX,ESI
                                                    {30}
//  Tmp:= W[11] xor W[6] xor W[0] xor W[14];
//  W[14]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(E,((A shl 5) or (A shr 27)) + (B xor C xor D) + $6ED9EBA1 + W[14]);
//  B:= (B shl 30) or (B shr 2);

        MOV     ESI,[R8 + 44]
        XOR     ESI,[R8 + 24]
        XOR     ESI,[R8]
        XOR     ESI,[R8 + 56]
        ROL     ESI,1
        MOV     [R8 + 56],ESI
        ADD     EBP,ESI
        MOV     ESI,EBX
        XOR     ESI,ECX
        XOR     ESI,EDX
        ROL     EBX,30
        LEA     EBP,[RBP + RSI + $6ED9EBA1]
        MOV     ESI,EAX
        ROL     ESI,5
        ADD     EBP,ESI
                                                    {31}
//  Tmp:= W[12] xor W[7] xor W[1] xor W[15];
//  W[15]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(D,((E shl 5) or (E shr 27)) + (A xor B xor C) + $6ED9EBA1 + W[15]);
//  A:= (A shl 30) or (A shr 2);

        MOV     ESI,[R8 + 48]
        XOR     ESI,[R8 + 28]
        XOR     ESI,[R8 + 4]
        XOR     ESI,[R8 + 60]
        ROL     ESI,1
        MOV     [R8 + 60],ESI
        ADD     EDX,ESI
        MOV     ESI,EAX
        XOR     ESI,EBX
        XOR     ESI,ECX
        ROL     EAX,30
        LEA     EDX,[RDX + RSI + $6ED9EBA1]
        MOV     ESI,EBP
        ROL     ESI,5
        ADD     EDX,ESI
                                                    {32}
//  Tmp:= W[13] xor W[8] xor W[2] xor W[0];
//  W[0]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(C,((D shl 5) or (D shr 27)) + (E xor A xor B) + $6ED9EBA1 + W[0]);
//  E:= (E shl 30) or (E shr 2);

        MOV     ESI,[R8 + 52]
        XOR     ESI,[R8 + 32]
        XOR     ESI,[R8 + 8]
        XOR     ESI,[R8]
        ROL     ESI,1
        MOV     [R8],ESI
        ADD     ECX,ESI
        MOV     ESI,EBP
        XOR     ESI,EAX
        XOR     ESI,EBX
        ROL     EBP,30
        LEA     ECX,[RCX + RSI + $6ED9EBA1]
        MOV     ESI,EDX
        ROL     ESI,5
        ADD     ECX,ESI
                                                    {33}
//  Tmp:= W[14] xor W[9] xor W[3] xor W[1];
//  W[1]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(B,((C shl 5) or (C shr 27)) + (D xor E xor A) + $6ED9EBA1 + W[1]);
//  D:= (D shl 30) or (D shr 2);

        MOV     ESI,[R8 + 56]
        XOR     ESI,[R8 + 36]
        XOR     ESI,[R8 + 12]
        XOR     ESI,[R8 + 4]
        ROL     ESI,1
        MOV     [R8 + 4],ESI
        ADD     EBX,ESI
        MOV     ESI,EDX
        XOR     ESI,EBP
        XOR     ESI,EAX
        ROL     EDX,30
        LEA     EBX,[RBX + RSI + $6ED9EBA1]
        MOV     ESI,ECX
        ROL     ESI,5
        ADD     EBX,ESI
                                                    {34}
//  Tmp:= W[15] xor W[10] xor W[4] xor W[2];
//  W[2]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(A,((B shl 5) or (B shr 27)) + (C xor D xor E) + $6ED9EBA1 + W[2]);
//  C:= (C shl 30) or (C shr 2);

        MOV     ESI,[R8 + 60]
        XOR     ESI,[R8 + 40]
        XOR     ESI,[R8 + 16]
        XOR     ESI,[R8 + 8]
        ROL     ESI,1
        MOV     [R8 + 8],ESI
        ADD     EAX,ESI
        MOV     ESI,ECX
        XOR     ESI,EDX
        XOR     ESI,EBP
        ROL     ECX,30
        LEA     EAX,[RAX + RSI + $6ED9EBA1]
        MOV     ESI,EBX
        ROL     ESI,5
        ADD     EAX,ESI
                                                    {35}
//  Tmp:= W[0] xor W[11] xor W[5] xor W[3];
//  W[3]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(E,((A shl 5) or (A shr 27)) + (B xor C xor D) + $6ED9EBA1 + W[3]);
//  B:= (B shl 30) or (B shr 2);

        MOV     ESI,[R8]
        XOR     ESI,[R8 + 44]
        XOR     ESI,[R8 + 20]
        XOR     ESI,[R8 + 12]
        ROL     ESI,1
        MOV     [R8 + 12],ESI
        ADD     EBP,ESI
        MOV     ESI,EBX
        XOR     ESI,ECX
        XOR     ESI,EDX
        ROL     EBX,30
        LEA     EBP,[RBP + RSI + $6ED9EBA1]
        MOV     ESI,EAX
        ROL     ESI,5
        ADD     EBP,ESI
                                                    {36}
//  Tmp:= W[1] xor W[12] xor W[6] xor W[4];
//  W[4]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(D,((E shl 5) or (E shr 27)) + (A xor B xor C) + $6ED9EBA1 + W[4]);
//  A:= (A shl 30) or (A shr 2);

        MOV     ESI,[R8 + 4]
        XOR     ESI,[R8 + 48]
        XOR     ESI,[R8 + 24]
        XOR     ESI,[R8 + 16]
        ROL     ESI,1
        MOV     [R8 + 16],ESI
        ADD     EDX,ESI
        MOV     ESI,EAX
        XOR     ESI,EBX
        XOR     ESI,ECX
        ROL     EAX,30
        LEA     EDX,[RDX + RSI + $6ED9EBA1]
        MOV     ESI,EBP
        ROL     ESI,5
        ADD     EDX,ESI
                                                    {37}
//  Tmp:= W[2] xor W[13] xor W[7] xor W[5];
//  W[5]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(C,((D shl 5) or (D shr 27)) + (E xor A xor B) + $6ED9EBA1 + W[5]);
//  E:= (E shl 30) or (E shr 2);

        MOV     ESI,[R8 + 8]
        XOR     ESI,[R8 + 52]
        XOR     ESI,[R8 + 28]
        XOR     ESI,[R8 + 20]
        ROL     ESI,1
        MOV     [R8 + 20],ESI
        ADD     ECX,ESI
        MOV     ESI,EBP
        XOR     ESI,EAX
        XOR     ESI,EBX
        ROL     EBP,30
        LEA     ECX,[RCX + RSI + $6ED9EBA1]
        MOV     ESI,EDX
        ROL     ESI,5
        ADD     ECX,ESI
                                                    {38}
//  Tmp:= W[3] xor W[14] xor W[8] xor W[6];
//  W[6]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(B,((C shl 5) or (C shr 27)) + (D xor E xor A) + $6ED9EBA1 + W[6]);
//  D:= (D shl 30) or (D shr 2);

        MOV     ESI,[R8 + 12]
        XOR     ESI,[R8 + 56]
        XOR     ESI,[R8 + 32]
        XOR     ESI,[R8 + 24]
        ROL     ESI,1
        MOV     [R8 + 24],ESI
        ADD     EBX,ESI
        MOV     ESI,EDX
        XOR     ESI,EBP
        XOR     ESI,EAX
        ROL     EDX,30
        LEA     EBX,[RBX + RSI + $6ED9EBA1]
        MOV     ESI,ECX
        ROL     ESI,5
        ADD     EBX,ESI
                                                    {39}
//  Tmp:= W[4] xor W[15] xor W[9] xor W[7];
//  W[7]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(A,((B shl 5) or (B shr 27)) + (C xor D xor E) + $6ED9EBA1 + W[7]);
//  C:= (C shl 30) or (C shr 2);

        MOV     ESI,[R8 + 16]
        XOR     ESI,[R8 + 60]
        XOR     ESI,[R8 + 36]
        XOR     ESI,[R8 + 28]
        ROL     ESI,1
        MOV     [R8 + 28],ESI
        ADD     EAX,ESI
        MOV     ESI,ECX
        XOR     ESI,EDX
        XOR     ESI,EBP
        ROL     ECX,30
        LEA     EAX,[RAX + RSI + $6ED9EBA1]
        MOV     ESI,EBX
        ROL     ESI,5
        ADD     EAX,ESI

                                                    {40}
//  Tmp:= W[5] xor W[0] xor W[10] xor W[8];
//  W[8]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(E,((A shl 5) or (A shr 27)) + ((B and C) or (D and (B or C))) + $8F1BBCDC + W[8]);
//  B:= (B shl 30) or (B shr 2);

        MOV     ESI,[R8 + 20]
        XOR     ESI,[R8]
        XOR     ESI,[R8 + 40]
        XOR     ESI,[R8 + 32]
        ROL     ESI,1
        MOV     [R8 + 32],ESI
        ADD     EBP,ESI
        MOV     EDI,EBX
        MOV     ESI,EBX
        AND     EDI,ECX
        OR      ESI,ECX
        AND     ESI,EDX
        OR      ESI,EDI
        ROL     EBX,30
        LEA     EBP,[RBP + RSI + $8F1BBCDC]
        MOV     ESI,EAX
        ROL     ESI,5
        ADD     EBP,ESI
                                                    {41}
//  Tmp:= W[6] xor W[1] xor W[11] xor W[9];
//  W[9]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(D,((E shl 5) or (E shr 27)) + ((A and B) or (C and (A or B))) + $8F1BBCDC + W[9]);
//  A:= (A shl 30) or (A shr 2);

        MOV     ESI,[R8 + 24]
        XOR     ESI,[R8 + 4]
        XOR     ESI,[R8 + 44]
        XOR     ESI,[R8 + 36]
        ROL     ESI,1
        MOV     [R8 + 36],ESI
        ADD     EDX,ESI
        MOV     EDI,EAX
        MOV     ESI,EAX
        AND     EDI,EBX
        OR      ESI,EBX
        AND     ESI,ECX
        OR      ESI,EDI
        ROL     EAX,30
        LEA     EDX,[RDX + RSI + $8F1BBCDC]
        MOV     ESI,EBP
        ROL     ESI,5
        ADD     EDX,ESI
                                                    {42}
//  Tmp:= W[7] xor W[2] xor W[12] xor W[10];
//  W[10]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(C,((D shl 5) or (D shr 27)) + ((E and A) or (B and (E or A))) + $8F1BBCDC + W[10]);
//  E:= (E shl 30) or (E shr 2);

        MOV     ESI,[R8 + 28]
        XOR     ESI,[R8 + 8]
        XOR     ESI,[R8 + 48]
        XOR     ESI,[R8 + 40]
        ROL     ESI,1
        MOV     [R8 + 40],ESI
        ADD     ECX,ESI
        MOV     EDI,EBP
        MOV     ESI,EBP
        AND     EDI,EAX
        OR      ESI,EAX
        AND     ESI,EBX
        OR      ESI,EDI
        ROL     EBP,30
        LEA     ECX,[RCX + RSI + $8F1BBCDC]
        MOV     ESI,EDX
        ROL     ESI,5
        ADD     ECX,ESI
                                                    {43}
//  Tmp:= W[8] xor W[3] xor W[13] xor W[11];
//  W[11]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(B,((C shl 5) or (C shr 27)) + ((D and E) or (A and (D or E))) + $8F1BBCDC + W[11]);
//  D:= (D shl 30) or (D shr 2);

        MOV     ESI,[R8 + 32]
        XOR     ESI,[R8 + 12]
        XOR     ESI,[R8 + 52]
        XOR     ESI,[R8 + 44]
        ROL     ESI,1
        MOV     [R8 + 44],ESI
        ADD     EBX,ESI
        MOV     EDI,EDX
        MOV     ESI,EDX
        AND     EDI,EBP
        OR      ESI,EBP
        AND     ESI,EAX
        OR      ESI,EDI
        ROL     EDX,30
        LEA     EBX,[RBX + RSI + $8F1BBCDC]
        MOV     ESI,ECX
        ROL     ESI,5
        ADD     EBX,ESI
                                                    {44}
//  Tmp:= W[9] xor W[4] xor W[14] xor W[12];
//  W[12]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(A,((B shl 5) or (B shr 27)) + ((C and D) or (E and (C or D))) + $8F1BBCDC + W[12]);
//  C:= (C shl 30) or (C shr 2);

        MOV     ESI,[R8 + 36]
        XOR     ESI,[R8 + 16]
        XOR     ESI,[R8 + 56]
        XOR     ESI,[R8 + 48]
        ROL     ESI,1
        MOV     [R8 + 48],ESI
        ADD     EAX,ESI
        MOV     EDI,ECX
        MOV     ESI,ECX
        AND     EDI,EDX
        OR      ESI,EDX
        AND     ESI,EBP
        OR      ESI,EDI
        ROL     ECX,30
        LEA     EAX,[RAX + RSI + $8F1BBCDC]
        MOV     ESI,EBX
        ROL     ESI,5
        ADD     EAX,ESI
                                                    {45}
//  Tmp:= W[10] xor W[5] xor W[15] xor W[13];
//  W[13]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(E,((A shl 5) or (A shr 27)) + ((B and C) or (D and (B or C))) + $8F1BBCDC + W[13]);
//  B:= (B shl 30) or (B shr 2);

        MOV     ESI,[R8 + 40]
        XOR     ESI,[R8 + 20]
        XOR     ESI,[R8 + 60]
        XOR     ESI,[R8 + 52]
        ROL     ESI,1
        MOV     [R8 + 52],ESI
        ADD     EBP,ESI
        MOV     EDI,EBX
        MOV     ESI,EBX
        AND     EDI,ECX
        OR      ESI,ECX
        AND     ESI,EDX
        OR      ESI,EDI
        ROL     EBX,30
        LEA     EBP,[RBP + RSI + $8F1BBCDC]
        MOV     ESI,EAX
        ROL     ESI,5
        ADD     EBP,ESI
                                                    {46}
//  Tmp:= W[11] xor W[6] xor W[0] xor W[14];
//  W[14]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(D,((E shl 5) or (E shr 27)) + ((A and B) or (C and (A or B))) + $8F1BBCDC + W[14]);
//  A:= (A shl 30) or (A shr 2);

        MOV     ESI,[R8 + 44]
        XOR     ESI,[R8 + 24]
        XOR     ESI,[R8]
        XOR     ESI,[R8 + 56]
        ROL     ESI,1
        MOV     [R8 + 56],ESI
        ADD     EDX,ESI
        MOV     EDI,EAX
        MOV     ESI,EAX
        AND     EDI,EBX
        OR      ESI,EBX
        AND     ESI,ECX
        OR      ESI,EDI
        ROL     EAX,30
        LEA     EDX,[RDX + RSI + $8F1BBCDC]
        MOV     ESI,EBP
        ROL     ESI,5
        ADD     EDX,ESI
                                                    {47}
//  Tmp:= W[12] xor W[7] xor W[1] xor W[15];
//  W[15]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(C,((D shl 5) or (D shr 27)) + ((E and A) or (B and (E or A))) + $8F1BBCDC + W[15]);
//  E:= (E shl 30) or (E shr 2);

        MOV     ESI,[R8 + 48]
        XOR     ESI,[R8 + 28]
        XOR     ESI,[R8 + 4]
        XOR     ESI,[R8 + 60]
        ROL     ESI,1
        MOV     [R8 + 60],ESI
        ADD     ECX,ESI
        MOV     EDI,EBP
        MOV     ESI,EBP
        AND     EDI,EAX
        OR      ESI,EAX
        AND     ESI,EBX
        OR      ESI,EDI
        ROL     EBP,30
        LEA     ECX,[RCX + RSI + $8F1BBCDC]
        MOV     ESI,EDX
        ROL     ESI,5
        ADD     ECX,ESI
                                                    {48}
//  Tmp:= W[13] xor W[8] xor W[2] xor W[0];
//  W[0]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(B,((C shl 5) or (C shr 27)) + ((D and E) or (A and (D or E))) + $8F1BBCDC + W[0]);
//  D:= (D shl 30) or (D shr 2);

        MOV     ESI,[R8 + 52]
        XOR     ESI,[R8 + 32]
        XOR     ESI,[R8 + 8]
        XOR     ESI,[R8]
        ROL     ESI,1
        MOV     [R8],ESI
        ADD     EBX,ESI
        MOV     EDI,EDX
        MOV     ESI,EDX
        AND     EDI,EBP
        OR      ESI,EBP
        AND     ESI,EAX
        OR      ESI,EDI
        ROL     EDX,30
        LEA     EBX,[RBX + RSI + $8F1BBCDC]
        MOV     ESI,ECX
        ROL     ESI,5
        ADD     EBX,ESI
                                                    {49}
//  Tmp:= W[14] xor W[9] xor W[3] xor W[1];
//  W[1]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(A,((B shl 5) or (B shr 27)) + ((C and D) or (E and (C or D))) + $8F1BBCDC + W[1]);
//  C:= (C shl 30) or (C shr 2);

        MOV     ESI,[R8 + 56]
        XOR     ESI,[R8 + 36]
        XOR     ESI,[R8 + 12]
        XOR     ESI,[R8 + 4]
        ROL     ESI,1
        MOV     [R8 + 4],ESI
        ADD     EAX,ESI
        MOV     EDI,ECX
        MOV     ESI,ECX
        AND     EDI,EDX
        OR      ESI,EDX
        AND     ESI,EBP
        OR      ESI,EDI
        ROL     ECX,30
        LEA     EAX,[RAX + RSI + $8F1BBCDC]
        MOV     ESI,EBX
        ROL     ESI,5
        ADD     EAX,ESI
                                                    {50}
//  Tmp:= W[15] xor W[10] xor W[4] xor W[2];
//  W[2]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(E,((A shl 5) or (A shr 27)) + ((B and C) or (D and (B or C))) + $8F1BBCDC + W[2]);
//  B:= (B shl 30) or (B shr 2);

        MOV     ESI,[R8 + 60]
        XOR     ESI,[R8 + 40]
        XOR     ESI,[R8 + 16]
        XOR     ESI,[R8 + 8]
        ROL     ESI,1
        MOV     [R8 + 8],ESI
        ADD     EBP,ESI
        MOV     EDI,EBX
        MOV     ESI,EBX
        AND     EDI,ECX
        OR      ESI,ECX
        AND     ESI,EDX
        OR      ESI,EDI
        ROL     EBX,30
        LEA     EBP,[RBP + RSI + $8F1BBCDC]
        MOV     ESI,EAX
        ROL     ESI,5
        ADD     EBP,ESI
                                                    {51}
//  Tmp:= W[0] xor W[11] xor W[5] xor W[3];
//  W[3]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(D,((E shl 5) or (E shr 27)) + ((A and B) or (C and (A or B))) + $8F1BBCDC + W[3]);
//  A:= (A shl 30) or (A shr 2);

        MOV     ESI,[R8]
        XOR     ESI,[R8 + 44]
        XOR     ESI,[R8 + 20]
        XOR     ESI,[R8 + 12]
        ROL     ESI,1
        MOV     [R8 + 12],ESI
        ADD     EDX,ESI
        MOV     EDI,EAX
        MOV     ESI,EAX
        AND     EDI,EBX
        OR      ESI,EBX
        AND     ESI,ECX
        OR      ESI,EDI
        ROL     EAX,30
        LEA     EDX,[RDX + RSI + $8F1BBCDC]
        MOV     ESI,EBP
        ROL     ESI,5
        ADD     EDX,ESI
                                                    {52}
//  Tmp:= W[1] xor W[12] xor W[6] xor W[4];
//  W[4]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(C,((D shl 5) or (D shr 27)) + ((E and A) or (B and (E or A))) + $8F1BBCDC + W[4]);
//  E:= (E shl 30) or (E shr 2);

        MOV     ESI,[R8 + 4]
        XOR     ESI,[R8 + 48]
        XOR     ESI,[R8 + 24]
        XOR     ESI,[R8 + 16]
        ROL     ESI,1
        MOV     [R8 + 16],ESI
        ADD     ECX,ESI
        MOV     EDI,EBP
        MOV     ESI,EBP
        AND     EDI,EAX
        OR      ESI,EAX
        AND     ESI,EBX
        OR      ESI,EDI
        ROL     EBP,30
        LEA     ECX,[RCX + RSI + $8F1BBCDC]
        MOV     ESI,EDX
        ROL     ESI,5
        ADD     ECX,ESI
                                                    {53}
//  Tmp:= W[2] xor W[13] xor W[7] xor W[5];
//  W[5]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(B,((C shl 5) or (C shr 27)) + ((D and E) or (A and (D or E))) + $8F1BBCDC + W[5]);
//  D:= (D shl 30) or (D shr 2);

        MOV     ESI,[R8 + 8]
        XOR     ESI,[R8 + 52]
        XOR     ESI,[R8 + 28]
        XOR     ESI,[R8 + 20]
        ROL     ESI,1
        MOV     [R8 + 20],ESI
        ADD     EBX,ESI
        MOV     EDI,EDX
        MOV     ESI,EDX
        AND     EDI,EBP
        OR      ESI,EBP
        AND     ESI,EAX
        OR      ESI,EDI
        ROL     EDX,30
        LEA     EBX,[RBX + RSI + $8F1BBCDC]
        MOV     ESI,ECX
        ROL     ESI,5
        ADD     EBX,ESI
                                                    {54}
//  Tmp:= W[3] xor W[14] xor W[8] xor W[6];
//  W[6]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(A,((B shl 5) or (B shr 27)) + ((C and D) or (E and (C or D))) + $8F1BBCDC + W[6]);
//  C:= (C shl 30) or (C shr 2);

        MOV     ESI,[R8 + 12]
        XOR     ESI,[R8 + 56]
        XOR     ESI,[R8 + 32]
        XOR     ESI,[R8 + 24]
        ROL     ESI,1
        MOV     [R8 + 24],ESI
        ADD     EAX,ESI
        MOV     EDI,ECX
        MOV     ESI,ECX
        AND     EDI,EDX
        OR      ESI,EDX
        AND     ESI,EBP
        OR      ESI,EDI
        ROL     ECX,30
        LEA     EAX,[RAX + RSI + $8F1BBCDC]
        MOV     ESI,EBX
        ROL     ESI,5
        ADD     EAX,ESI
                                                    {55}
//  Tmp:= W[4] xor W[15] xor W[9] xor W[7];
//  W[7]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(E,((A shl 5) or (A shr 27)) + ((B and C) or (D and (B or C))) + $8F1BBCDC + W[7]);
//  B:= (B shl 30) or (B shr 2);

        MOV     ESI,[R8 + 16]
        XOR     ESI,[R8 + 60]
        XOR     ESI,[R8 + 36]
        XOR     ESI,[R8 + 28]
        ROL     ESI,1
        MOV     [R8 + 28],ESI
        ADD     EBP,ESI
        MOV     EDI,EBX
        MOV     ESI,EBX
        AND     EDI,ECX
        OR      ESI,ECX
        AND     ESI,EDX
        OR      ESI,EDI
        ROL     EBX,30
        LEA     EBP,[RBP + RSI + $8F1BBCDC]
        MOV     ESI,EAX
        ROL     ESI,5
        ADD     EBP,ESI
                                                    {56}
//  Tmp:= W[5] xor W[0] xor W[10] xor W[8];
//  W[8]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(D,((E shl 5) or (E shr 27)) + ((A and B) or (C and (A or B))) + $8F1BBCDC + W[8]);
//  A:= (A shl 30) or (A shr 2);

        MOV     ESI,[R8 + 20]
        XOR     ESI,[R8]
        XOR     ESI,[R8 + 40]
        XOR     ESI,[R8 + 32]
        ROL     ESI,1
        MOV     [R8 + 32],ESI
        ADD     EDX,ESI
        MOV     EDI,EAX
        MOV     ESI,EAX
        AND     EDI,EBX
        OR      ESI,EBX
        AND     ESI,ECX
        OR      ESI,EDI
        ROL     EAX,30
        LEA     EDX,[RDX + RSI + $8F1BBCDC]
        MOV     ESI,EBP
        ROL     ESI,5
        ADD     EDX,ESI
                                                    {57}
//  Tmp:= W[6] xor W[1] xor W[11] xor W[9];
//  W[9]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(C,((D shl 5) or (D shr 27)) + ((E and A) or (B and (E or A))) + $8F1BBCDC + W[9]);
//  E:= (E shl 30) or (E shr 2);

        MOV     ESI,[R8 + 24]
        XOR     ESI,[R8 + 4]
        XOR     ESI,[R8 + 44]
        XOR     ESI,[R8 + 36]
        ROL     ESI,1
        MOV     [R8 + 36],ESI
        ADD     ECX,ESI
        MOV     EDI,EBP
        MOV     ESI,EBP
        AND     EDI,EAX
        OR      ESI,EAX
        AND     ESI,EBX
        OR      ESI,EDI
        ROL     EBP,30
        LEA     ECX,[RCX + RSI + $8F1BBCDC]
        MOV     ESI,EDX
        ROL     ESI,5
        ADD     ECX,ESI
                                                    {58}
//  Tmp:= W[7] xor W[2] xor W[12] xor W[10];
//  W[10]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(B,((C shl 5) or (C shr 27)) + ((D and E) or (A and (D or E))) + $8F1BBCDC + W[10]);
//  D:= (D shl 30) or (D shr 2);

        MOV     ESI,[R8 + 28]
        XOR     ESI,[R8 + 8]
        XOR     ESI,[R8 + 48]
        XOR     ESI,[R8 + 40]
        ROL     ESI,1
        MOV     [R8 + 40],ESI
        ADD     EBX,ESI
        MOV     EDI,EDX
        MOV     ESI,EDX
        AND     EDI,EBP
        OR      ESI,EBP
        AND     ESI,EAX
        OR      ESI,EDI
        ROL     EDX,30
        LEA     EBX,[RBX + RSI + $8F1BBCDC]
        MOV     ESI,ECX
        ROL     ESI,5
        ADD     EBX,ESI
                                                    {59}
//  Tmp:= W[8] xor W[3] xor W[13] xor W[11];
//  W[11]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(A,((B shl 5) or (B shr 27)) + ((C and D) or (E and (C or D))) + $8F1BBCDC + W[11]);
//  C:= (C shl 30) or (C shr 2);

        MOV     ESI,[R8 + 32]
        XOR     ESI,[R8 + 12]
        XOR     ESI,[R8 + 52]
        XOR     ESI,[R8 + 44]
        ROL     ESI,1
        MOV     [R8 + 44],ESI
        ADD     EAX,ESI
        MOV     EDI,ECX
        MOV     ESI,ECX
        AND     EDI,EDX
        OR      ESI,EDX
        AND     ESI,EBP
        OR      ESI,EDI
        ROL     ECX,30
        LEA     EAX,[RAX + RSI + $8F1BBCDC]
        MOV     ESI,EBX
        ROL     ESI,5
        ADD     EAX,ESI
                                                    {60}
//  Tmp:= W[9] xor W[4] xor W[14] xor W[12];
//  W[12]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(E,((A shl 5) or (A shr 27)) + (B xor C xor D) + $CA62C1D6 + W[12]);
//  B:= (B shl 30) or (B shr 2);

        MOV     ESI,[R8 + 36]
        XOR     ESI,[R8 + 16]
        XOR     ESI,[R8 + 56]
        XOR     ESI,[R8 + 48]
        ROL     ESI,1
        MOV     [R8 + 48],ESI
        ADD     EBP,ESI
        MOV     ESI,EBX
        XOR     ESI,ECX
        XOR     ESI,EDX
        ROL     EBX,30
        LEA     EBP,[RBP + RSI + $CA62C1D6]
        MOV     ESI,EAX
        ROL     ESI,5
        ADD     EBP,ESI
                                                    {61}
//  Tmp:= W[10] xor W[5] xor W[15] xor W[13];
//  W[13]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(D,((E shl 5) or (E shr 27)) + (A xor B xor C) + $CA62C1D6 + W[13]);
//  A:= (A shl 30) or (A shr 2);

        MOV     ESI,[R8 + 40]
        XOR     ESI,[R8 + 20]
        XOR     ESI,[R8 + 60]
        XOR     ESI,[R8 + 52]
        ROL     ESI,1
        MOV     [R8 + 52],ESI
        ADD     EDX,ESI
        MOV     ESI,EAX
        XOR     ESI,EBX
        XOR     ESI,ECX
        ROL     EAX,30
        LEA     EDX,[RDX + RSI + $CA62C1D6]
        MOV     ESI,EBP
        ROL     ESI,5
        ADD     EDX,ESI
                                                    {62}
//  Tmp:= W[11] xor W[6] xor W[0] xor W[14];
//  W[14]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(C,((D shl 5) or (D shr 27)) + (E xor A xor B) + $CA62C1D6 + W[14]);
//  E:= (E shl 30) or (E shr 2);

        MOV     ESI,[R8 + 44]
        XOR     ESI,[R8 + 24]
        XOR     ESI,[R8]
        XOR     ESI,[R8 + 56]
        ROL     ESI,1
        MOV     [R8 + 56],ESI
        ADD     ECX,ESI
        MOV     ESI,EBP
        XOR     ESI,EAX
        XOR     ESI,EBX
        ROL     EBP,30
        LEA     ECX,[RCX + RSI + $CA62C1D6]
        MOV     ESI,EDX
        ROL     ESI,5
        ADD     ECX,ESI
                                                    {63}
//  Tmp:= W[12] xor W[7] xor W[1] xor W[15];
//  W[15]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(B,((C shl 5) or (C shr 27)) + (D xor E xor A) + $CA62C1D6 + W[15]);
//  D:= (D shl 30) or (D shr 2);

        MOV     ESI,[R8 + 48]
        XOR     ESI,[R8 + 28]
        XOR     ESI,[R8 + 4]
        XOR     ESI,[R8 + 60]
        ROL     ESI,1
        MOV     [R8 + 60],ESI
        ADD     EBX,ESI
        MOV     ESI,EDX
        XOR     ESI,EBP
        XOR     ESI,EAX
        ROL     EDX,30
        LEA     EBX,[RBX + RSI + $CA62C1D6]
        MOV     ESI,ECX
        ROL     ESI,5
        ADD     EBX,ESI
                                                    {64}
//  Tmp:= W[13] xor W[8] xor W[2] xor W[0];
//  W[0]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(A,((B shl 5) or (B shr 27)) + (C xor D xor E) + $CA62C1D6 + W[0]);
//  C:= (C shl 30) or (C shr 2);

        MOV     ESI,[R8 + 52]
        XOR     ESI,[R8 + 32]
        XOR     ESI,[R8 + 8]
        XOR     ESI,[R8]
        ROL     ESI,1
        MOV     [R8],ESI
        ADD     EAX,ESI
        MOV     ESI,ECX
        XOR     ESI,EDX
        XOR     ESI,EBP
        ROL     ECX,30
        LEA     EAX,[RAX + RSI + $CA62C1D6]
        MOV     ESI,EBX
        ROL     ESI,5
        ADD     EAX,ESI
                                                    {65}
//  Tmp:= W[14] xor W[9] xor W[3] xor W[1];
//  W[1]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(E,((A shl 5) or (A shr 27)) + (B xor C xor D) + $CA62C1D6 + W[1]);
//  B:= (B shl 30) or (B shr 2);

        MOV     ESI,[R8 + 56]
        XOR     ESI,[R8 + 36]
        XOR     ESI,[R8 + 12]
        XOR     ESI,[R8 + 4]
        ROL     ESI,1
        MOV     [R8 + 4],ESI
        ADD     EBP,ESI
        MOV     ESI,EBX
        XOR     ESI,ECX
        XOR     ESI,EDX
        ROL     EBX,30
        LEA     EBP,[RBP + RSI + $CA62C1D6]
        MOV     ESI,EAX
        ROL     ESI,5
        ADD     EBP,ESI
                                                    {66}
//  Tmp:= W[15] xor W[10] xor W[4] xor W[2];
//  W[2]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(D,((E shl 5) or (E shr 27)) + (A xor B xor C) + $CA62C1D6 + W[2]);
//  A:= (A shl 30) or (A shr 2);

        MOV     ESI,[R8 + 60]
        XOR     ESI,[R8 + 40]
        XOR     ESI,[R8 + 16]
        XOR     ESI,[R8 + 8]
        ROL     ESI,1
        MOV     [R8 + 8],ESI
        ADD     EDX,ESI
        MOV     ESI,EAX
        XOR     ESI,EBX
        XOR     ESI,ECX
        ROL     EAX,30
        LEA     EDX,[RDX + RSI + $CA62C1D6]
        MOV     ESI,EBP
        ROL     ESI,5
        ADD     EDX,ESI
                                                    {67}
//  Tmp:= W[0] xor W[11] xor W[5] xor W[3];
//  W[3]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(C,((D shl 5) or (D shr 27)) + (E xor A xor B) + $CA62C1D6 + W[3]);
//  E:= (E shl 30) or (E shr 2);

        MOV     ESI,[R8]
        XOR     ESI,[R8 + 44]
        XOR     ESI,[R8 + 20]
        XOR     ESI,[R8 + 12]
        ROL     ESI,1
        MOV     [R8 + 12],ESI
        ADD     ECX,ESI
        MOV     ESI,EBP
        XOR     ESI,EAX
        XOR     ESI,EBX
        ROL     EBP,30
        LEA     ECX,[RCX + RSI + $CA62C1D6]
        MOV     ESI,EDX
        ROL     ESI,5
        ADD     ECX,ESI
                                                    {68}
//  Tmp:= W[1] xor W[12] xor W[6] xor W[4];
//  W[4]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(B,((C shl 5) or (C shr 27)) + (D xor E xor A) + $CA62C1D6 + W[4]);
//  D:= (D shl 30) or (D shr 2);

        MOV     ESI,[R8 + 4]
        XOR     ESI,[R8 + 48]
        XOR     ESI,[R8 + 24]
        XOR     ESI,[R8 + 16]
        ROL     ESI,1
        MOV     [R8 + 16],ESI
        ADD     EBX,ESI
        MOV     ESI,EDX
        XOR     ESI,EBP
        XOR     ESI,EAX
        ROL     EDX,30
        LEA     EBX,[RBX + RSI + $CA62C1D6]
        MOV     ESI,ECX
        ROL     ESI,5
        ADD     EBX,ESI
                                                    {69}
//  Tmp:= W[2] xor W[13] xor W[7] xor W[5];
//  W[5]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(A,((B shl 5) or (B shr 27)) + (C xor D xor E) + $CA62C1D6 + W[5]);
//  C:= (C shl 30) or (C shr 2);

        MOV     ESI,[R8 + 8]
        XOR     ESI,[R8 + 52]
        XOR     ESI,[R8 + 28]
        XOR     ESI,[R8 + 20]
        ROL     ESI,1
        MOV     [R8 + 20],ESI
        ADD     EAX,ESI
        MOV     ESI,ECX
        XOR     ESI,EDX
        XOR     ESI,EBP
        ROL     ECX,30
        LEA     EAX,[RAX + RSI + $CA62C1D6]
        MOV     ESI,EBX
        ROL     ESI,5
        ADD     EAX,ESI
                                                    {70}
//  Tmp:= W[3] xor W[14] xor W[8] xor W[6];
//  W[6]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(E,((A shl 5) or (A shr 27)) + (B xor C xor D) + $CA62C1D6 + W[6]);
//  B:= (B shl 30) or (B shr 2);

        MOV     ESI,[R8 + 12]
        XOR     ESI,[R8 + 56]
        XOR     ESI,[R8 + 32]
        XOR     ESI,[R8 + 24]
        ROL     ESI,1
        MOV     [R8 + 24],ESI
        ADD     EBP,ESI
        MOV     ESI,EBX
        XOR     ESI,ECX
        XOR     ESI,EDX
        ROL     EBX,30
        LEA     EBP,[RBP + RSI + $CA62C1D6]
        MOV     ESI,EAX
        ROL     ESI,5
        ADD     EBP,ESI
                                                    {71}
//  Tmp:= W[4] xor W[15] xor W[9] xor W[7];
//  W[7]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(D,((E shl 5) or (E shr 27)) + (A xor B xor C) + $CA62C1D6 + W[7]);
//  A:= (A shl 30) or (A shr 2);

        MOV     ESI,[R8 + 16]
        XOR     ESI,[R8 + 60]
        XOR     ESI,[R8 + 36]
        XOR     ESI,[R8 + 28]
        ROL     ESI,1
        MOV     [R8 + 28],ESI
        ADD     EDX,ESI
        MOV     ESI,EAX
        XOR     ESI,EBX
        XOR     ESI,ECX
        ROL     EAX,30
        LEA     EDX,[RDX + RSI + $CA62C1D6]
        MOV     ESI,EBP
        ROL     ESI,5
        ADD     EDX,ESI
                                                    {72}
//  Tmp:= W[5] xor W[0] xor W[10] xor W[8];
//  W[8]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(C,((D shl 5) or (D shr 27)) + (E xor A xor B) + $CA62C1D6 + W[8]);
//  E:= (E shl 30) or (E shr 2);

        MOV     ESI,[R8 + 20]
        XOR     ESI,[R8]
        XOR     ESI,[R8 + 40]
        XOR     ESI,[R8 + 32]
        ROL     ESI,1
        MOV     [R8 + 32],ESI
        ADD     ECX,ESI
        MOV     ESI,EBP
        XOR     ESI,EAX
        XOR     ESI,EBX
        ROL     EBP,30
        LEA     ECX,[RCX + RSI + $CA62C1D6]
        MOV     ESI,EDX
        ROL     ESI,5
        ADD     ECX,ESI
                                                    {73}
//  Tmp:= W[6] xor W[1] xor W[11] xor W[9];
//  W[9]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(B,((C shl 5) or (C shr 27)) + (D xor E xor A) + $CA62C1D6 + W[9]);
//  D:= (D shl 30) or (D shr 2);

        MOV     ESI,[R8 + 24]
        XOR     ESI,[R8 + 4]
        XOR     ESI,[R8 + 44]
        XOR     ESI,[R8 + 36]
        ROL     ESI,1
        MOV     [R8 + 36],ESI
        ADD     EBX,ESI
        MOV     ESI,EDX
        XOR     ESI,EBP
        XOR     ESI,EAX
        ROL     EDX,30
        LEA     EBX,[RBX + RSI + $CA62C1D6]
        MOV     ESI,ECX
        ROL     ESI,5
        ADD     EBX,ESI
                                                    {74}
//  Tmp:= W[7] xor W[2] xor W[12] xor W[10];
//  W[10]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(A,((B shl 5) or (B shr 27)) + (C xor D xor E) + $CA62C1D6 + W[10]);
//  C:= (C shl 30) or (C shr 2);

        MOV     ESI,[R8 + 28]
        XOR     ESI,[R8 + 8]
        XOR     ESI,[R8 + 48]
        XOR     ESI,[R8 + 40]
        ROL     ESI,1
        MOV     [R8 + 40],ESI
        ADD     EAX,ESI
        MOV     ESI,ECX
        XOR     ESI,EDX
        XOR     ESI,EBP
        ROL     ECX,30
        LEA     EAX,[RAX + RSI + $CA62C1D6]
        MOV     ESI,EBX
        ROL     ESI,5
        ADD     EAX,ESI
                                                    {75}
//  Tmp:= W[8] xor W[3] xor W[13] xor W[11];
//  W[11]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(E,((A shl 5) or (A shr 27)) + (B xor C xor D) + $CA62C1D6 + W[11]);
//  B:= (B shl 30) or (B shr 2);

        MOV     ESI,[R8 + 32]
        XOR     ESI,[R8 + 12]
        XOR     ESI,[R8 + 52]
        XOR     ESI,[R8 + 44]
        ROL     ESI,1
        MOV     [R8 + 44],ESI
        ADD     EBP,ESI
        MOV     ESI,EBX
        XOR     ESI,ECX
        XOR     ESI,EDX
        ROL     EBX,30
        LEA     EBP,[RBP + RSI + $CA62C1D6]
        MOV     ESI,EAX
        ROL     ESI,5
        ADD     EBP,ESI
                                                    {76}
//  Tmp:= W[9] xor W[4] xor W[14] xor W[12];
//  W[12]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(D,((E shl 5) or (E shr 27)) + (A xor B xor C) + $CA62C1D6 + W[12]);
//  A:= (A shl 30) or (A shr 2);

        MOV     ESI,[R8 + 36]
        XOR     ESI,[R8 + 16]
        XOR     ESI,[R8 + 56]
        XOR     ESI,[R8 + 48]
        ROL     ESI,1
        MOV     [R8 + 48],ESI
        ADD     EDX,ESI
        MOV     ESI,EAX
        XOR     ESI,EBX
        XOR     ESI,ECX
        ROL     EAX,30
        LEA     EDX,[RDX + RSI + $CA62C1D6]
        MOV     ESI,EBP
        ROL     ESI,5
        ADD     EDX,ESI
                                                    {77}
//  Tmp:= W[10] xor W[5] xor W[15] xor W[13];
//  W[13]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(C,((D shl 5) or (D shr 27)) + (E xor A xor B) + $CA62C1D6 + W[13]);
//  E:= (E shl 30) or (E shr 2);

        MOV     ESI,[R8 + 40]
        XOR     ESI,[R8 + 20]
        XOR     ESI,[R8 + 60]
        XOR     ESI,[R8 + 52]
        ROL     ESI,1
//        MOV     [R8 + 52],ESI
        ADD     ECX,ESI
        MOV     ESI,EBP
        XOR     ESI,EAX
        XOR     ESI,EBX
        ROL     EBP,30
        LEA     ECX,[RCX + RSI + $CA62C1D6]
        MOV     ESI,EDX
        ROL     ESI,5
        ADD     ECX,ESI
                                                    {78}
//  Tmp:= W[11] xor W[6] xor W[0] xor W[14];
//  W[14]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(B,((C shl 5) or (C shr 27)) + (D xor E xor A) + $CA62C1D6 + W[14]);
//  D:= (D shl 30) or (D shr 2);

        MOV     ESI,[R8 + 44]
        XOR     ESI,[R8 + 24]
        XOR     ESI,[R8]
        XOR     ESI,[R8 + 56]
        ROL     ESI,1
//        MOV     [R8 + 56],ESI
        ADD     EBX,ESI
        MOV     ESI,EDX
        XOR     ESI,EBP
        XOR     ESI,EAX
        ROL     EDX,30
        LEA     EBX,[RBX + RSI + $CA62C1D6]
        MOV     ESI,ECX
        ROL     ESI,5
        ADD     EBX,ESI
                                                    {79}
//  Tmp:= W[12] xor W[7] xor W[1] xor W[15];
//  W[15]:= (Tmp shl 1) or (Tmp shr 31);
//  Inc(A,((B shl 5) or (B shr 27)) + (C xor D xor E) + $CA62C1D6 + W[15]);
//  C:= (C shl 30) or (C shr 2);

        MOV     ESI,[R8 + 48]
        XOR     ESI,[R8 + 28]
        XOR     ESI,[R8 + 4]
        XOR     ESI,[R8 + 60]
        ROL     ESI,1
//        MOV     [R8 + 60],ESI
        ADD     EAX,ESI
        MOV     ESI,ECX
        XOR     ESI,EDX
        XOR     ESI,EBP
        ROL     ECX,30
        LEA     EAX,[RAX + RSI + $CA62C1D6]
        MOV     ESI,EBX
        ROL     ESI,5
        ADD     EAX,ESI


        ADD     [R8 - 20],EAX      // Inc(FData.Digest[0], A);
        ADD     [R8 - 16],EBX      // Inc(FData.Digest[1], B);
        ADD     [R8 - 12],ECX      // Inc(FData.Digest[2], C);
        ADD     [R8 - 8],EDX       // Inc(FData.Digest[3], D);
        ADD     [R8 - 4],EBP       // Inc(FData.Digest[4], E);

                                  //  FillChar(Block, SizeOf(Block), 0);
        XOR     RAX,RAX
        MOV     [R8],RAX
        MOV     [R8 + 8],RAX
        MOV     [R8 + 16],RAX
        MOV     [R8 + 24],RAX
        MOV     [R8 + 32],RAX
        MOV     [R8 + 40],RAX
        MOV     [R8 + 48],RAX
        MOV     [R8 + 56],RAX

        ADD     RSP,8
        POP     RBP
        POP     RBX
        POP     RDI
        POP     RSI
end;
{$ELSE}
procedure TSHA1Alg.Compress;
type
  PLongArray = ^TLongArray;
  TLongArray = array[0..15] of UInt32;

var
  W: PLongArray;
  A, B, C, D, E: UInt32;
  Tmp: UInt32;

begin
  W:= @FData.Block;

  A:= FData.Digest[0];
  B:= FData.Digest[1];
  C:= FData.Digest[2];
  D:= FData.Digest[3];
  E:= FData.Digest[4];
                                                    { 0}
  W[0]:= Swap32(W[0]);
  Inc(E,((A shl 5) or (A shr 27)) + (D xor (B and (C xor D))) + $5A827999 + W[0]);
  B:= (B shl 30) or (B shr 2);
                                                    { 1}
  W[1]:= Swap32(W[1]);
  Inc(D,((E shl 5) or (E shr 27)) + (C xor (A and (B xor C))) + $5A827999 + W[1]);
  A:= (A shl 30) or (A shr 2);
                                                    { 2}
  W[2]:= Swap32(W[2]);
  Inc(C,((D shl 5) or (D shr 27)) + (B xor (E and (A xor B))) + $5A827999 + W[2]);
  E:= (E shl 30) or (E shr 2);
                                                    { 3}
  W[3]:= Swap32(W[3]);
  Inc(B,((C shl 5) or (C shr 27)) + (A xor (D and (E xor A))) + $5A827999 + W[3]);
  D:= (D shl 30) or (D shr 2);
                                                    { 4}
  W[4]:= Swap32(W[4]);
  Inc(A,((B shl 5) or (B shr 27)) + (E xor (C and (D xor E))) + $5A827999 + W[4]);
  C:= (C shl 30) or (C shr 2);
                                                    { 5}
  W[5]:= Swap32(W[5]);
  Inc(E,((A shl 5) or (A shr 27)) + (D xor (B and (C xor D))) + $5A827999 + W[5]);
  B:= (B shl 30) or (B shr 2);
                                                    { 6}
  W[6]:= Swap32(W[6]);
  Inc(D,((E shl 5) or (E shr 27)) + (C xor (A and (B xor C))) + $5A827999 + W[6]);
  A:= (A shl 30) or (A shr 2);
                                                    { 7}
  W[7]:= Swap32(W[7]);
  Inc(C,((D shl 5) or (D shr 27)) + (B xor (E and (A xor B))) + $5A827999 + W[7]);
  E:= (E shl 30) or (E shr 2);
                                                    { 8}
  W[8]:= Swap32(W[8]);
  Inc(B,((C shl 5) or (C shr 27)) + (A xor (D and (E xor A))) + $5A827999 + W[8]);
  D:= (D shl 30) or (D shr 2);
                                                    { 9}
  W[9]:= Swap32(W[9]);
  Inc(A,((B shl 5) or (B shr 27)) + (E xor (C and (D xor E))) + $5A827999 + W[9]);
  C:= (C shl 30) or (C shr 2);
                                                    {10}
  W[10]:= Swap32(W[10]);
  Inc(E,((A shl 5) or (A shr 27)) + (D xor (B and (C xor D))) + $5A827999 + W[10]);
  B:= (B shl 30) or (B shr 2);
                                                    {11}
  W[11]:= Swap32(W[11]);
  Inc(D,((E shl 5) or (E shr 27)) + (C xor (A and (B xor C))) + $5A827999 + W[11]);
  A:= (A shl 30) or (A shr 2);
                                                    {12}
  W[12]:= Swap32(W[12]);
  Inc(C,((D shl 5) or (D shr 27)) + (B xor (E and (A xor B))) + $5A827999 + W[12]);
  E:= (E shl 30) or (E shr 2);
                                                    {13}
  W[13]:= Swap32(W[13]);
  Inc(B,((C shl 5) or (C shr 27)) + (A xor (D and (E xor A))) + $5A827999 + W[13]);
  D:= (D shl 30) or (D shr 2);
                                                    {14}
  W[14]:= Swap32(W[14]);
  Inc(A,((B shl 5) or (B shr 27)) + (E xor (C and (D xor E))) + $5A827999 + W[14]);
  C:= (C shl 30) or (C shr 2);
                                                    {15}
  W[15]:= Swap32(W[15]);
  Inc(E,((A shl 5) or (A shr 27)) + (D xor (B and (C xor D))) + $5A827999 + W[15]);
  B:= (B shl 30) or (B shr 2);
                                                    {16}
  Tmp:= W[13] xor W[8] xor W[2] xor W[0];
  W[0]:= (Tmp shl 1) or (Tmp shr 31);
  Inc(D,((E shl 5) or (E shr 27)) + (C xor (A and (B xor C))) + $5A827999 + W[0]);
  A:= (A shl 30) or (A shr 2);
                                                    {17}
  Tmp:= W[14] xor W[9] xor W[3] xor W[1];
  W[1]:= (Tmp shl 1) or (Tmp shr 31);
  Inc(C,((D shl 5) or (D shr 27)) + (B xor (E and (A xor B))) + $5A827999 + W[1]);
  E:= (E shl 30) or (E shr 2);
                                                    {18}
  Tmp:= W[15] xor W[10] xor W[4] xor W[2];
  W[2]:= (Tmp shl 1) or (Tmp shr 31);
  Inc(B,((C shl 5) or (C shr 27)) + (A xor (D and (E xor A))) + $5A827999 + W[2]);
  D:= (D shl 30) or (D shr 2);
                                                    {19}
  Tmp:= W[0] xor W[11] xor W[5] xor W[3];
  W[3]:= (Tmp shl 1) or (Tmp shr 31);
  Inc(A,((B shl 5) or (B shr 27)) + (E xor (C and (D xor E))) + $5A827999 + W[3]);
  C:= (C shl 30) or (C shr 2);

                                                    {20}
  Tmp:= W[1] xor W[12] xor W[6] xor W[4];
  W[4]:= (Tmp shl 1) or (Tmp shr 31);
  Inc(E,((A shl 5) or (A shr 27)) + (B xor C xor D) + $6ED9EBA1 + W[4]);
  B:= (B shl 30) or (B shr 2);
                                                    {21}
  Tmp:= W[2] xor W[13] xor W[7] xor W[5];
  W[5]:= (Tmp shl 1) or (Tmp shr 31);
  Inc(D,((E shl 5) or (E shr 27)) + (A xor B xor C) + $6ED9EBA1 + W[5]);
  A:= (A shl 30) or (A shr 2);
                                                    {22}
  Tmp:= W[3] xor W[14] xor W[8] xor W[6];
  W[6]:= (Tmp shl 1) or (Tmp shr 31);
  Inc(C,((D shl 5) or (D shr 27)) + (E xor A xor B) + $6ED9EBA1 + W[6]);
  E:= (E shl 30) or (E shr 2);
                                                    {23}
  Tmp:= W[4] xor W[15] xor W[9] xor W[7];
  W[7]:= (Tmp shl 1) or (Tmp shr 31);
  Inc(B,((C shl 5) or (C shr 27)) + (D xor E xor A) + $6ED9EBA1 + W[7]);
  D:= (D shl 30) or (D shr 2);
                                                    {24}
  Tmp:= W[5] xor W[0] xor W[10] xor W[8];
  W[8]:= (Tmp shl 1) or (Tmp shr 31);
  Inc(A,((B shl 5) or (B shr 27)) + (C xor D xor E) + $6ED9EBA1 + W[8]);
  C:= (C shl 30) or (C shr 2);
                                                    {25}
  Tmp:= W[6] xor W[1] xor W[11] xor W[9];
  W[9]:= (Tmp shl 1) or (Tmp shr 31);
  Inc(E,((A shl 5) or (A shr 27)) + (B xor C xor D) + $6ED9EBA1 + W[9]);
  B:= (B shl 30) or (B shr 2);
                                                    {26}
  Tmp:= W[7] xor W[2] xor W[12] xor W[10];
  W[10]:= (Tmp shl 1) or (Tmp shr 31);
  Inc(D,((E shl 5) or (E shr 27)) + (A xor B xor C) + $6ED9EBA1 + W[10]);
  A:= (A shl 30) or (A shr 2);
                                                    {27}
  Tmp:= W[8] xor W[3] xor W[13] xor W[11];
  W[11]:= (Tmp shl 1) or (Tmp shr 31);
  Inc(C,((D shl 5) or (D shr 27)) + (E xor A xor B) + $6ED9EBA1 + W[11]);
  E:= (E shl 30) or (E shr 2);
                                                    {28}
  Tmp:= W[9] xor W[4] xor W[14] xor W[12];
  W[12]:= (Tmp shl 1) or (Tmp shr 31);
  Inc(B,((C shl 5) or (C shr 27)) + (D xor E xor A) + $6ED9EBA1 + W[12]);
  D:= (D shl 30) or (D shr 2);
                                                    {29}
  Tmp:= W[10] xor W[5] xor W[15] xor W[13];
  W[13]:= (Tmp shl 1) or (Tmp shr 31);
  Inc(A,((B shl 5) or (B shr 27)) + (C xor D xor E) + $6ED9EBA1 + W[13]);
  C:= (C shl 30) or (C shr 2);
                                                    {30}
  Tmp:= W[11] xor W[6] xor W[0] xor W[14];
  W[14]:= (Tmp shl 1) or (Tmp shr 31);
  Inc(E,((A shl 5) or (A shr 27)) + (B xor C xor D) + $6ED9EBA1 + W[14]);
  B:= (B shl 30) or (B shr 2);
                                                    {31}
  Tmp:= W[12] xor W[7] xor W[1] xor W[15];
  W[15]:= (Tmp shl 1) or (Tmp shr 31);
  Inc(D,((E shl 5) or (E shr 27)) + (A xor B xor C) + $6ED9EBA1 + W[15]);
  A:= (A shl 30) or (A shr 2);
                                                    {32}
  Tmp:= W[13] xor W[8] xor W[2] xor W[0];
  W[0]:= (Tmp shl 1) or (Tmp shr 31);
  Inc(C,((D shl 5) or (D shr 27)) + (E xor A xor B) + $6ED9EBA1 + W[0]);
  E:= (E shl 30) or (E shr 2);
                                                    {33}
  Tmp:= W[14] xor W[9] xor W[3] xor W[1];
  W[1]:= (Tmp shl 1) or (Tmp shr 31);
  Inc(B,((C shl 5) or (C shr 27)) + (D xor E xor A) + $6ED9EBA1 + W[1]);
  D:= (D shl 30) or (D shr 2);
                                                    {34}
  Tmp:= W[15] xor W[10] xor W[4] xor W[2];
  W[2]:= (Tmp shl 1) or (Tmp shr 31);
  Inc(A,((B shl 5) or (B shr 27)) + (C xor D xor E) + $6ED9EBA1 + W[2]);
  C:= (C shl 30) or (C shr 2);
                                                    {35}
  Tmp:= W[0] xor W[11] xor W[5] xor W[3];
  W[3]:= (Tmp shl 1) or (Tmp shr 31);
  Inc(E,((A shl 5) or (A shr 27)) + (B xor C xor D) + $6ED9EBA1 + W[3]);
  B:= (B shl 30) or (B shr 2);
                                                    {36}
  Tmp:= W[1] xor W[12] xor W[6] xor W[4];
  W[4]:= (Tmp shl 1) or (Tmp shr 31);
  Inc(D,((E shl 5) or (E shr 27)) + (A xor B xor C) + $6ED9EBA1 + W[4]);
  A:= (A shl 30) or (A shr 2);
                                                    {37}
  Tmp:= W[2] xor W[13] xor W[7] xor W[5];
  W[5]:= (Tmp shl 1) or (Tmp shr 31);
  Inc(C,((D shl 5) or (D shr 27)) + (E xor A xor B) + $6ED9EBA1 + W[5]);
  E:= (E shl 30) or (E shr 2);
                                                    {38}
  Tmp:= W[3] xor W[14] xor W[8] xor W[6];
  W[6]:= (Tmp shl 1) or (Tmp shr 31);
  Inc(B,((C shl 5) or (C shr 27)) + (D xor E xor A) + $6ED9EBA1 + W[6]);
  D:= (D shl 30) or (D shr 2);
                                                    {39}
  Tmp:= W[4] xor W[15] xor W[9] xor W[7];
  W[7]:= (Tmp shl 1) or (Tmp shr 31);
  Inc(A,((B shl 5) or (B shr 27)) + (C xor D xor E) + $6ED9EBA1 + W[7]);
  C:= (C shl 30) or (C shr 2);

                                                    {40}
  Tmp:= W[5] xor W[0] xor W[10] xor W[8];
  W[8]:= (Tmp shl 1) or (Tmp shr 31);
  Inc(E,((A shl 5) or (A shr 27)) + ((B and C) or (D and (B or C))) + $8F1BBCDC + W[8]);
  B:= (B shl 30) or (B shr 2);
                                                    {41}
  Tmp:= W[6] xor W[1] xor W[11] xor W[9];
  W[9]:= (Tmp shl 1) or (Tmp shr 31);
  Inc(D,((E shl 5) or (E shr 27)) + ((A and B) or (C and (A or B))) + $8F1BBCDC + W[9]);
  A:= (A shl 30) or (A shr 2);
                                                    {42}
  Tmp:= W[7] xor W[2] xor W[12] xor W[10];
  W[10]:= (Tmp shl 1) or (Tmp shr 31);
  Inc(C,((D shl 5) or (D shr 27)) + ((E and A) or (B and (E or A))) + $8F1BBCDC + W[10]);
  E:= (E shl 30) or (E shr 2);
                                                    {43}
  Tmp:= W[8] xor W[3] xor W[13] xor W[11];
  W[11]:= (Tmp shl 1) or (Tmp shr 31);
  Inc(B,((C shl 5) or (C shr 27)) + ((D and E) or (A and (D or E))) + $8F1BBCDC + W[11]);
  D:= (D shl 30) or (D shr 2);
                                                    {44}
  Tmp:= W[9] xor W[4] xor W[14] xor W[12];
  W[12]:= (Tmp shl 1) or (Tmp shr 31);
  Inc(A,((B shl 5) or (B shr 27)) + ((C and D) or (E and (C or D))) + $8F1BBCDC + W[12]);
  C:= (C shl 30) or (C shr 2);
                                                    {45}
  Tmp:= W[10] xor W[5] xor W[15] xor W[13];
  W[13]:= (Tmp shl 1) or (Tmp shr 31);
  Inc(E,((A shl 5) or (A shr 27)) + ((B and C) or (D and (B or C))) + $8F1BBCDC + W[13]);
  B:= (B shl 30) or (B shr 2);
                                                    {46}
  Tmp:= W[11] xor W[6] xor W[0] xor W[14];
  W[14]:= (Tmp shl 1) or (Tmp shr 31);
  Inc(D,((E shl 5) or (E shr 27)) + ((A and B) or (C and (A or B))) + $8F1BBCDC + W[14]);
  A:= (A shl 30) or (A shr 2);
                                                    {47}
  Tmp:= W[12] xor W[7] xor W[1] xor W[15];
  W[15]:= (Tmp shl 1) or (Tmp shr 31);
  Inc(C,((D shl 5) or (D shr 27)) + ((E and A) or (B and (E or A))) + $8F1BBCDC + W[15]);
  E:= (E shl 30) or (E shr 2);
                                                    {48}
  Tmp:= W[13] xor W[8] xor W[2] xor W[0];
  W[0]:= (Tmp shl 1) or (Tmp shr 31);
  Inc(B,((C shl 5) or (C shr 27)) + ((D and E) or (A and (D or E))) + $8F1BBCDC + W[0]);
  D:= (D shl 30) or (D shr 2);
                                                    {49}
  Tmp:= W[14] xor W[9] xor W[3] xor W[1];
  W[1]:= (Tmp shl 1) or (Tmp shr 31);
  Inc(A,((B shl 5) or (B shr 27)) + ((C and D) or (E and (C or D))) + $8F1BBCDC + W[1]);
  C:= (C shl 30) or (C shr 2);
                                                    {50}
  Tmp:= W[15] xor W[10] xor W[4] xor W[2];
  W[2]:= (Tmp shl 1) or (Tmp shr 31);
  Inc(E,((A shl 5) or (A shr 27)) + ((B and C) or (D and (B or C))) + $8F1BBCDC + W[2]);
  B:= (B shl 30) or (B shr 2);
                                                    {51}
  Tmp:= W[0] xor W[11] xor W[5] xor W[3];
  W[3]:= (Tmp shl 1) or (Tmp shr 31);
  Inc(D,((E shl 5) or (E shr 27)) + ((A and B) or (C and (A or B))) + $8F1BBCDC + W[3]);
  A:= (A shl 30) or (A shr 2);
                                                    {52}
  Tmp:= W[1] xor W[12] xor W[6] xor W[4];
  W[4]:= (Tmp shl 1) or (Tmp shr 31);
  Inc(C,((D shl 5) or (D shr 27)) + ((E and A) or (B and (E or A))) + $8F1BBCDC + W[4]);
  E:= (E shl 30) or (E shr 2);
                                                    {53}
  Tmp:= W[2] xor W[13] xor W[7] xor W[5];
  W[5]:= (Tmp shl 1) or (Tmp shr 31);
  Inc(B,((C shl 5) or (C shr 27)) + ((D and E) or (A and (D or E))) + $8F1BBCDC + W[5]);
  D:= (D shl 30) or (D shr 2);
                                                    {54}
  Tmp:= W[3] xor W[14] xor W[8] xor W[6];
  W[6]:= (Tmp shl 1) or (Tmp shr 31);
  Inc(A,((B shl 5) or (B shr 27)) + ((C and D) or (E and (C or D))) + $8F1BBCDC + W[6]);
  C:= (C shl 30) or (C shr 2);
                                                    {55}
  Tmp:= W[4] xor W[15] xor W[9] xor W[7];
  W[7]:= (Tmp shl 1) or (Tmp shr 31);
  Inc(E,((A shl 5) or (A shr 27)) + ((B and C) or (D and (B or C))) + $8F1BBCDC + W[7]);
  B:= (B shl 30) or (B shr 2);
                                                    {56}
  Tmp:= W[5] xor W[0] xor W[10] xor W[8];
  W[8]:= (Tmp shl 1) or (Tmp shr 31);
  Inc(D,((E shl 5) or (E shr 27)) + ((A and B) or (C and (A or B))) + $8F1BBCDC + W[8]);
  A:= (A shl 30) or (A shr 2);
                                                    {57}
  Tmp:= W[6] xor W[1] xor W[11] xor W[9];
  W[9]:= (Tmp shl 1) or (Tmp shr 31);
  Inc(C,((D shl 5) or (D shr 27)) + ((E and A) or (B and (E or A))) + $8F1BBCDC + W[9]);
  E:= (E shl 30) or (E shr 2);
                                                    {58}
  Tmp:= W[7] xor W[2] xor W[12] xor W[10];
  W[10]:= (Tmp shl 1) or (Tmp shr 31);
  Inc(B,((C shl 5) or (C shr 27)) + ((D and E) or (A and (D or E))) + $8F1BBCDC + W[10]);
  D:= (D shl 30) or (D shr 2);
                                                    {59}
  Tmp:= W[8] xor W[3] xor W[13] xor W[11];
  W[11]:= (Tmp shl 1) or (Tmp shr 31);
  Inc(A,((B shl 5) or (B shr 27)) + ((C and D) or (E and (C or D))) + $8F1BBCDC + W[11]);
  C:= (C shl 30) or (C shr 2);
                                                    {60}
  Tmp:= W[9] xor W[4] xor W[14] xor W[12];
  W[12]:= (Tmp shl 1) or (Tmp shr 31);
  Inc(E,((A shl 5) or (A shr 27)) + (B xor C xor D) + $CA62C1D6 + W[12]);
  B:= (B shl 30) or (B shr 2);
                                                    {61}
  Tmp:= W[10] xor W[5] xor W[15] xor W[13];
  W[13]:= (Tmp shl 1) or (Tmp shr 31);
  Inc(D,((E shl 5) or (E shr 27)) + (A xor B xor C) + $CA62C1D6 + W[13]);
  A:= (A shl 30) or (A shr 2);
                                                    {62}
  Tmp:= W[11] xor W[6] xor W[0] xor W[14];
  W[14]:= (Tmp shl 1) or (Tmp shr 31);
  Inc(C,((D shl 5) or (D shr 27)) + (E xor A xor B) + $CA62C1D6 + W[14]);
  E:= (E shl 30) or (E shr 2);
                                                    {63}
  Tmp:= W[12] xor W[7] xor W[1] xor W[15];
  W[15]:= (Tmp shl 1) or (Tmp shr 31);
  Inc(B,((C shl 5) or (C shr 27)) + (D xor E xor A) + $CA62C1D6 + W[15]);
  D:= (D shl 30) or (D shr 2);
                                                    {64}
  Tmp:= W[13] xor W[8] xor W[2] xor W[0];
  W[0]:= (Tmp shl 1) or (Tmp shr 31);
  Inc(A,((B shl 5) or (B shr 27)) + (C xor D xor E) + $CA62C1D6 + W[0]);
  C:= (C shl 30) or (C shr 2);
                                                    {65}
  Tmp:= W[14] xor W[9] xor W[3] xor W[1];
  W[1]:= (Tmp shl 1) or (Tmp shr 31);
  Inc(E,((A shl 5) or (A shr 27)) + (B xor C xor D) + $CA62C1D6 + W[1]);
  B:= (B shl 30) or (B shr 2);
                                                    {66}
  Tmp:= W[15] xor W[10] xor W[4] xor W[2];
  W[2]:= (Tmp shl 1) or (Tmp shr 31);
  Inc(D,((E shl 5) or (E shr 27)) + (A xor B xor C) + $CA62C1D6 + W[2]);
  A:= (A shl 30) or (A shr 2);
                                                    {67}
  Tmp:= W[0] xor W[11] xor W[5] xor W[3];
  W[3]:= (Tmp shl 1) or (Tmp shr 31);
  Inc(C,((D shl 5) or (D shr 27)) + (E xor A xor B) + $CA62C1D6 + W[3]);
  E:= (E shl 30) or (E shr 2);
                                                    {68}
  Tmp:= W[1] xor W[12] xor W[6] xor W[4];
  W[4]:= (Tmp shl 1) or (Tmp shr 31);
  Inc(B,((C shl 5) or (C shr 27)) + (D xor E xor A) + $CA62C1D6 + W[4]);
  D:= (D shl 30) or (D shr 2);
                                                    {69}
  Tmp:= W[2] xor W[13] xor W[7] xor W[5];
  W[5]:= (Tmp shl 1) or (Tmp shr 31);
  Inc(A,((B shl 5) or (B shr 27)) + (C xor D xor E) + $CA62C1D6 + W[5]);
  C:= (C shl 30) or (C shr 2);
                                                    {70}
  Tmp:= W[3] xor W[14] xor W[8] xor W[6];
  W[6]:= (Tmp shl 1) or (Tmp shr 31);
  Inc(E,((A shl 5) or (A shr 27)) + (B xor C xor D) + $CA62C1D6 + W[6]);
  B:= (B shl 30) or (B shr 2);
                                                    {71}
  Tmp:= W[4] xor W[15] xor W[9] xor W[7];
  W[7]:= (Tmp shl 1) or (Tmp shr 31);
  Inc(D,((E shl 5) or (E shr 27)) + (A xor B xor C) + $CA62C1D6 + W[7]);
  A:= (A shl 30) or (A shr 2);
                                                    {72}
  Tmp:= W[5] xor W[0] xor W[10] xor W[8];
  W[8]:= (Tmp shl 1) or (Tmp shr 31);
  Inc(C,((D shl 5) or (D shr 27)) + (E xor A xor B) + $CA62C1D6 + W[8]);
  E:= (E shl 30) or (E shr 2);
                                                    {73}
  Tmp:= W[6] xor W[1] xor W[11] xor W[9];
  W[9]:= (Tmp shl 1) or (Tmp shr 31);
  Inc(B,((C shl 5) or (C shr 27)) + (D xor E xor A) + $CA62C1D6 + W[9]);
  D:= (D shl 30) or (D shr 2);
                                                    {74}
  Tmp:= W[7] xor W[2] xor W[12] xor W[10];
  W[10]:= (Tmp shl 1) or (Tmp shr 31);
  Inc(A,((B shl 5) or (B shr 27)) + (C xor D xor E) + $CA62C1D6 + W[10]);
  C:= (C shl 30) or (C shr 2);
                                                    {75}
  Tmp:= W[8] xor W[3] xor W[13] xor W[11];
  W[11]:= (Tmp shl 1) or (Tmp shr 31);
  Inc(E,((A shl 5) or (A shr 27)) + (B xor C xor D) + $CA62C1D6 + W[11]);
  B:= (B shl 30) or (B shr 2);
                                                    {76}
  Tmp:= W[9] xor W[4] xor W[14] xor W[12];
  W[12]:= (Tmp shl 1) or (Tmp shr 31);
  Inc(D,((E shl 5) or (E shr 27)) + (A xor B xor C) + $CA62C1D6 + W[12]);
  A:= (A shl 30) or (A shr 2);
                                                    {77}
  Tmp:= W[10] xor W[5] xor W[15] xor W[13];
  W[13]:= (Tmp shl 1) or (Tmp shr 31);
  Inc(C,((D shl 5) or (D shr 27)) + (E xor A xor B) + $CA62C1D6 + W[13]);
  E:= (E shl 30) or (E shr 2);
                                                    {78}
  Tmp:= W[11] xor W[6] xor W[0] xor W[14];
  W[14]:= (Tmp shl 1) or (Tmp shr 31);
  Inc(B,((C shl 5) or (C shr 27)) + (D xor E xor A) + $CA62C1D6 + W[14]);
  D:= (D shl 30) or (D shr 2);
                                                    {79}
  Tmp:= W[12] xor W[7] xor W[1] xor W[15];
  W[15]:= (Tmp shl 1) or (Tmp shr 31);
  Inc(A,((B shl 5) or (B shr 27)) + (C xor D xor E) + $CA62C1D6 + W[15]);
  C:= (C shl 30) or (C shr 2);

  FData.Digest[0]:= FData.Digest[0] + A;
  FData.Digest[1]:= FData.Digest[1] + B;
  FData.Digest[2]:= FData.Digest[2] + C;
  FData.Digest[3]:= FData.Digest[3] + D;
  FData.Digest[4]:= FData.Digest[4] + E;
//  FillChar(W, SizeOf(W), 0);
  FillChar(FData.Block, SizeOf(FData.Block), 0);
end;

{$ENDIF}
{$ENDIF}

class procedure TSHA1Alg.Init(Inst: PSHA1Alg);
begin
  Inst.FData.Digest[0]:= $67452301;
  Inst.FData.Digest[1]:= $EFCDAB89;
  Inst.FData.Digest[2]:= $98BADCFE;
  Inst.FData.Digest[3]:= $10325476;
  Inst.FData.Digest[4]:= $C3D2E1F0;

  FillChar(Inst.FData.Block, SizeOf(Inst.FData.Block), 0);
  Inst.FData.Count:= 0;
end;

class procedure TSHA1Alg.Update(Inst: PSHA1Alg; Data: PByte;
                                DataSize: Cardinal);
var
  Cnt, Ofs: Cardinal;

begin
  while DataSize > 0 do begin
    Ofs:= Cardinal(Inst.FData.Count) and $3F;
    Cnt:= $40 - Ofs;
    if Cnt > DataSize then Cnt:= DataSize;
    Move(Data^, PByte(@Inst.FData.Block)[Ofs], Cnt);
    if (Cnt + Ofs = $40) then Inst.Compress;
    Inc(Inst.FData.Count, Cnt);
    Dec(DataSize, Cnt);
    Inc(Data, Cnt);
  end;
end;

class procedure TSHA1Alg.Done(Inst: PSHA1Alg; PDigest: PSHA1Digest);
var
  Ofs: Cardinal;

begin
  Ofs:= Cardinal(Inst.FData.Count) and $3F;
  Inst.FData.Block[Ofs]:= $80;
  if Ofs >= 56 then
    Inst.Compress;

  Inst.FData.Count:= Inst.FData.Count shl 3;
  PUInt32(@Inst.FData.Block[56])^:= Swap32(UInt32(Inst.FData.Count shr 32));
  PUInt32(@Inst.FData.Block[60])^:= Swap32(UInt32(Inst.FData.Count));
  Inst.Compress;

  Inst.FData.Digest[0]:= Swap32(Inst.FData.Digest[0]);
  Inst.FData.Digest[1]:= Swap32(Inst.FData.Digest[1]);
  Inst.FData.Digest[2]:= Swap32(Inst.FData.Digest[2]);
  Inst.FData.Digest[3]:= Swap32(Inst.FData.Digest[3]);
  Inst.FData.Digest[4]:= Swap32(Inst.FData.Digest[4]);

  Move(Inst.FData.Digest, PDigest^, SizeOf(TSHA1Digest));

  Init(Inst);
end;

class function TSHA1Alg.Duplicate(Inst: PSHA1Alg;
                                  var DupInst: PSHA1Alg): TF_RESULT;
begin
  Result:= GetSHA1Algorithm(DupInst);
  if Result = TF_S_OK then
    DupInst.FData:= Inst.FData;
end;

class function TSHA1Alg.GetBlockSize(Inst: PSHA1Alg): Integer;
begin
  Result:= 64;
end;

class function TSHA1Alg.GetDigestSize(Inst: PSHA1Alg): Integer;
begin
  Result:= SizeOf(TSHA1Digest);
end;

end.
