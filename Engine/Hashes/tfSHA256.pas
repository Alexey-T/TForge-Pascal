{ *********************************************************** }
{ *                     TForge Library                      * }
{ *       Copyright (c) Sergey Kasandrov 1997, 2016         * }
{ *********************************************************** }

unit tfSHA256;

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
  PSHA256Alg = ^TSHA256Alg;
  TSHA256Alg = record
  private type
    TData = record
      Digest: TSHA256Digest;
      Block: array[0..63] of Byte;
      Count: UInt64;                 // number of bytes processed
    end;
  private
    FVTable: Pointer;
    FRefCount: Integer;
    FData: TData;

    procedure Compress;
  public
    class procedure Init(Inst: PSHA256Alg);
         {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class procedure Update(Inst: PSHA256Alg; Data: PByte; DataSize: Cardinal);
         {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class procedure Done(Inst: PSHA256Alg; PDigest: PSHA256Digest);
         {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function GetDigestSize(Inst: PSHA256Alg): Integer;
         {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function GetBlockSize(Inst: PSHA256Alg): Integer;
         {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function Duplicate(Inst: PSHA256Alg; var DupInst: PSHA256Alg): TF_RESULT;
         {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
end;

type
  PSHA224Alg = ^TSHA224Alg;
  TSHA224Alg = record
  private type
    TData = record
      Digest: TSHA256Digest;         // !! 256 bits
      Block: array[0..63] of Byte;
      Count: UInt64;                 // number of bytes processed
    end;
  private
    FVTable: Pointer;
    FRefCount: Integer;
    FData: TData;

  public
    class procedure Init(Inst: PSHA224Alg);
         {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class procedure Done(Inst: PSHA224Alg; PDigest: PSHA224Digest);
         {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function GetDigestSize(Inst: PSHA256Alg): Integer;
         {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
end;

function GetSHA256Algorithm(var Inst: PSHA256Alg): TF_RESULT;
function GetSHA224Algorithm(var Inst: PSHA224Alg): TF_RESULT;

implementation

uses tfRecords;

const
  SHA256VTable: array[0..9] of Pointer = (
    @TForgeInstance.QueryIntf,
    @TForgeInstance.Addref,
    @HashAlgRelease,

    @TSHA256Alg.Init,
    @TSHA256Alg.Update,
    @TSHA256Alg.Done,
    @TSHA256Alg.Init,
    @TSHA256Alg.GetDigestSize,
    @TSHA256Alg.GetBlockSize,
    @TSHA256Alg.Duplicate
  );

const
  SHA224VTable: array[0..9] of Pointer = (
    @TForgeInstance.QueryIntf,
    @TForgeInstance.Addref,
    @HashAlgRelease,

    @TSHA224Alg.Init,
    @TSHA256Alg.Update,
    @TSHA224Alg.Done,
    @TSHA224Alg.Init,
    @TSHA224Alg.GetDigestSize,
    @TSHA256Alg.GetBlockSize,
    @TSHA256Alg.Duplicate
  );

function GetSHA256Algorithm(var Inst: PSHA256Alg): TF_RESULT;
var
  P: PSHA256Alg;

begin
  try
    New(P);
    P^.FVTable:= @SHA256VTable;
    P^.FRefCount:= 1;
    TSHA256Alg.Init(P);
    if Inst <> nil then HashAlgRelease(Inst);
    Inst:= P;
    Result:= TF_S_OK;
  except
    Result:= TF_E_OUTOFMEMORY;
  end;
end;

function GetSHA224Algorithm(var Inst: PSHA224Alg): TF_RESULT;
var
  P: PSHA224Alg;

begin
  try
    New(P);
    P^.FVTable:= @SHA224VTable;
    P^.FRefCount:= 1;
    TSHA224Alg.Init(P);
    if Inst <> nil then HashAlgRelease(Inst);
    Inst:= P;
    Result:= TF_S_OK;
  except
    Result:= TF_E_OUTOFMEMORY;
  end;
end;

{ TSHA256Algorithm }

function Swap32(Value: UInt32): UInt32;
begin
  Result:= ((Value and $FF) shl 24) or ((Value and $FF00) shl 8) or
           ((Value and $FF0000) shr 8) or ((Value and $FF000000) shr 24);
end;

{$IFNDEF CPUX86_WIN32}
{$IFNDEF CPUX64_WIN64}
procedure TSHA256Alg.Compress;
type
  PLongArray = ^TLongArray;
  TLongArray = array[0..15] of UInt32;

var
  W: PLongArray;
//  W: array[0..63] of UInt32;
  a, b, c, d, e, f, g, h, t1, t2: UInt32;
//  I: UInt32;

begin
  W:= @FData.Block;

  a:= FData.Digest[0];
  b:= FData.Digest[1];
  c:= FData.Digest[2];
  d:= FData.Digest[3];
  e:= FData.Digest[4];
  f:= FData.Digest[5];
  g:= FData.Digest[6];
  h:= FData.Digest[7];
//  Move(FData.Block, W, SizeOf(FData.Block));

{  for I:= 0 to 15 do
    W[I]:= Swap32(W[I]);

  for I:= 16 to 63 do
    W[I]:= (((W[I-2] shr 17) or (W[I-2] shl 15)) xor
            ((W[I-2] shr 19) or (W[I-2] shl 13)) xor (W[I-2] shr 10)) + W[I-7] +
           (((W[I-15] shr 7) or (W[I-15] shl 25)) xor
            ((W[I-15] shr 18) or (W[I-15] shl 14)) xor (W[I-15] shr 3)) + W[I-16];
}
  W[0]:= Swap32(W[0]);
  t1:= h + (((e shr 6) or (e shl 26)) xor ((e shr 11) or (e shl 21)) xor
      ((e shr 25) or (e shl 7))) + ((e and f) xor (not e and g)) + $428a2f98 + W[0];
  t2:= (((a shr 2) or (a shl 30)) xor ((a shr 13) or (a shl 19)) xor
      ((a shr 22) xor (a shl 10))) + ((a and b) xor (a and c) xor (b and c));
  h:= t1 + t2;
  d:= d + t1;

  W[1]:= Swap32(W[1]);
  t1:= g + (((d shr 6) or (d shl 26)) xor ((d shr 11) or (d shl 21)) xor
      ((d shr 25) or (d shl 7))) + ((d and e) xor (not d and f)) + $71374491 + W[1];
  t2:= (((h shr 2) or (h shl 30)) xor ((h shr 13) or (h shl 19)) xor
      ((h shr 22) xor (h shl 10))) + ((h and a) xor (h and b) xor (a and b));
  g:= t1 + t2;
  c:= c + t1;

  W[2]:= Swap32(W[2]);
  t1:= f + (((c shr 6) or (c shl 26)) xor ((c shr 11) or (c shl 21)) xor
      ((c shr 25) or (c shl 7))) + ((c and d) xor (not c and e)) + $b5c0fbcf + W[2];
  t2:= (((g shr 2) or (g shl 30)) xor ((g shr 13) or (g shl 19)) xor
      ((g shr 22) xor (g shl 10))) + ((g and h) xor (g and a) xor (h and a));
  f:= t1 + t2;
  b:= b + t1;

  W[3]:= Swap32(W[3]);
  t1:= e + (((b shr 6) or (b shl 26)) xor ((b shr 11) or (b shl 21)) xor
      ((b shr 25) or (b shl 7))) + ((b and c) xor (not b and d)) + $e9b5dba5 + W[3];
  t2:= (((f shr 2) or (f shl 30)) xor ((f shr 13) or (f shl 19)) xor
      ((f shr 22) xor (f shl 10))) + ((f and g) xor (f and h) xor (g and h));
  e:= t1 + t2;
  a:= a + t1;

  W[4]:= Swap32(W[4]);
  t1:= d + (((a shr 6) or (a shl 26)) xor ((a shr 11) or (a shl 21)) xor
      ((a shr 25) or (a shl 7))) + ((a and b) xor (not a and c)) + $3956c25b + W[4];
  t2:= (((e shr 2) or (e shl 30)) xor ((e shr 13) or (e shl 19)) xor
      ((e shr 22) xor (e shl 10))) + ((e and f) xor (e and g) xor (f and g));
  d:= t1 + t2;
  h:= h + t1;

  W[5]:= Swap32(W[5]);
  t1:= c + (((h shr 6) or (h shl 26)) xor ((h shr 11) or (h shl 21)) xor
      ((h shr 25) or (h shl 7))) + ((h and a) xor (not h and b)) + $59f111f1 + W[5];
  t2:= (((d shr 2) or (d shl 30)) xor ((d shr 13) or (d shl 19)) xor
      ((d shr 22) xor (d shl 10))) + ((d and e) xor (d and f) xor (e and f));
  c:= t1 + t2;
  g:= g + t1;

  W[6]:= Swap32(W[6]);
  t1:= b + (((g shr 6) or (g shl 26)) xor ((g shr 11) or (g shl 21)) xor
      ((g shr 25) or (g shl 7))) + ((g and h) xor (not g and a)) + $923f82a4 + W[6];
  t2:= (((c shr 2) or (c shl 30)) xor ((c shr 13) or (c shl 19)) xor
      ((c shr 22) xor (c shl 10))) + ((c and d) xor (c and e) xor (d and e));
  b:= t1 + t2;
  f:= f + t1;

  W[7]:= Swap32(W[7]);
  t1:= a + (((f shr 6) or (f shl 26)) xor ((f shr 11) or (f shl 21)) xor
      ((f shr 25) or (f shl 7))) + ((f and g) xor (not f and h)) + $ab1c5ed5 + W[7];
  t2:= (((b shr 2) or (b shl 30)) xor ((b shr 13) or (b shl 19)) xor
      ((b shr 22) xor (b shl 10))) + ((b and c) xor (b and d) xor (c and d));
  a:= t1 + t2;
  e:= e + t1;

  W[8]:= Swap32(W[8]);
  t1:= h + (((e shr 6) or (e shl 26)) xor ((e shr 11) or (e shl 21)) xor
      ((e shr 25) or (e shl 7))) + ((e and f) xor (not e and g)) + $d807aa98 + W[8];
  t2:= (((a shr 2) or (a shl 30)) xor ((a shr 13) or (a shl 19)) xor
      ((a shr 22) xor (a shl 10))) + ((a and b) xor (a and c) xor (b and c));
  h:= t1 + t2;
  d:= d + t1;

  W[9]:= Swap32(W[9]);
  t1:= g + (((d shr 6) or (d shl 26)) xor ((d shr 11) or (d shl 21)) xor
      ((d shr 25) or (d shl 7))) + ((d and e) xor (not d and f)) + $12835b01 + W[9];
  t2:= (((h shr 2) or (h shl 30)) xor ((h shr 13) or (h shl 19)) xor
      ((h shr 22) xor (h shl 10))) + ((h and a) xor (h and b) xor (a and b));
  g:= t1 + t2;
  c:= c + t1;

  W[10]:= Swap32(W[10]);
  t1:= f + (((c shr 6) or (c shl 26)) xor ((c shr 11) or (c shl 21)) xor
      ((c shr 25) or (c shl 7))) + ((c and d) xor (not c and e)) + $243185be + W[10];
  t2:= (((g shr 2) or (g shl 30)) xor ((g shr 13) or (g shl 19)) xor
      ((g shr 22) xor (g shl 10))) + ((g and h) xor (g and a) xor (h and a));
  f:= t1 + t2;
  b:= b + t1;

  W[11]:= Swap32(W[11]);
  t1:= e + (((b shr 6) or (b shl 26)) xor ((b shr 11) or (b shl 21)) xor
      ((b shr 25) or (b shl 7))) + ((b and c) xor (not b and d)) + $550c7dc3 + W[11];
  t2:= (((f shr 2) or (f shl 30)) xor ((f shr 13) or (f shl 19)) xor
      ((f shr 22) xor (f shl 10))) + ((f and g) xor (f and h) xor (g and h));
  e:= t1 + t2;
  a:= a + t1;

  W[12]:= Swap32(W[12]);
  t1:= d + (((a shr 6) or (a shl 26)) xor ((a shr 11) or (a shl 21)) xor
      ((a shr 25) or (a shl 7))) + ((a and b) xor (not a and c)) + $72be5d74 + W[12];
  t2:= (((e shr 2) or (e shl 30)) xor ((e shr 13) or (e shl 19)) xor
      ((e shr 22) xor (e shl 10))) + ((e and f) xor (e and g) xor (f and g));
  d:= t1 + t2;
  h:= h + t1;

  W[13]:= Swap32(W[13]);
  t1:= c + (((h shr 6) or (h shl 26)) xor ((h shr 11) or (h shl 21)) xor
      ((h shr 25) or (h shl 7))) + ((h and a) xor (not h and b)) + $80deb1fe + W[13];
  t2:= (((d shr 2) or (d shl 30)) xor ((d shr 13) or (d shl 19)) xor
      ((d shr 22) xor (d shl 10))) + ((d and e) xor (d and f) xor (e and f));
  c:= t1 + t2;
  g:= g + t1;

  W[14]:= Swap32(W[14]);
  t1:= b + (((g shr 6) or (g shl 26)) xor ((g shr 11) or (g shl 21)) xor
      ((g shr 25) or (g shl 7))) + ((g and h) xor (not g and a)) + $9bdc06a7 + W[14];
  t2:= (((c shr 2) or (c shl 30)) xor ((c shr 13) or (c shl 19)) xor
      ((c shr 22) xor (c shl 10))) + ((c and d) xor (c and e) xor (d and e));
  b:= t1 + t2;
  f:= f + t1;

  W[15]:= Swap32(W[15]);
  t1:= a + (((f shr 6) or (f shl 26)) xor ((f shr 11) or (f shl 21)) xor
      ((f shr 25) or (f shl 7))) + ((f and g) xor (not f and h)) + $c19bf174 + W[15];
  t2:= (((b shr 2) or (b shl 30)) xor ((b shr 13) or (b shl 19)) xor
      ((b shr 22) xor (b shl 10))) + ((b and c) xor (b and d) xor (c and d));
  a:= t1 + t2;
  e:= e + t1;


  W[0]:= (((W[14] shr 17) or (W[14] shl 15)) xor
          ((W[14] shr 19) or (W[14] shl 13)) xor (W[14] shr 10)) + W[9] +
         (((W[1] shr 7) or (W[1] shl 25)) xor
          ((W[1] shr 18) or (W[1] shl 14)) xor (W[1] shr 3)) + W[0];
  t1:= h + (((e shr 6) or (e shl 26)) xor ((e shr 11) or (e shl 21)) xor
      ((e shr 25) or (e shl 7))) + ((e and f) xor (not e and g)) + $e49b69c1 + W[0];
  t2:= (((a shr 2) or (a shl 30)) xor ((a shr 13) or (a shl 19)) xor
      ((a shr 22) xor (a shl 10))) + ((a and b) xor (a and c) xor (b and c));
  h:= t1 + t2;
  d:= d + t1;

  W[1]:= (((W[15] shr 17) or (W[15] shl 15)) xor
          ((W[15] shr 19) or (W[15] shl 13)) xor (W[15] shr 10)) + W[10] +
         (((W[2] shr 7) or (W[2] shl 25)) xor
          ((W[2] shr 18) or (W[2] shl 14)) xor (W[2] shr 3)) + W[1];
  t1:= g + (((d shr 6) or (d shl 26)) xor ((d shr 11) or (d shl 21)) xor
      ((d shr 25) or (d shl 7))) + ((d and e) xor (not d and f)) + $efbe4786 + W[1];
  t2:= (((h shr 2) or (h shl 30)) xor ((h shr 13) or (h shl 19)) xor
      ((h shr 22) xor (h shl 10))) + ((h and a) xor (h and b) xor (a and b));
  g:= t1 + t2;
  c:= c + t1;

  W[2]:= (((W[0] shr 17) or (W[0] shl 15)) xor
          ((W[0] shr 19) or (W[0] shl 13)) xor (W[0] shr 10)) + W[11] +
         (((W[3] shr 7) or (W[3] shl 25)) xor
          ((W[3] shr 18) or (W[3] shl 14)) xor (W[3] shr 3)) + W[2];
  t1:= f + (((c shr 6) or (c shl 26)) xor ((c shr 11) or (c shl 21)) xor
      ((c shr 25) or (c shl 7))) + ((c and d) xor (not c and e)) + $0fc19dc6 + W[2];
  t2:= (((g shr 2) or (g shl 30)) xor ((g shr 13) or (g shl 19)) xor
      ((g shr 22) xor (g shl 10))) + ((g and h) xor (g and a) xor (h and a));
  f:= t1 + t2;
  b:= b + t1;

  W[3]:= (((W[1] shr 17) or (W[1] shl 15)) xor
          ((W[1] shr 19) or (W[1] shl 13)) xor (W[1] shr 10)) + W[12] +
         (((W[4] shr 7) or (W[4] shl 25)) xor
          ((W[4] shr 18) or (W[4] shl 14)) xor (W[4] shr 3)) + W[3];
  t1:= e + (((b shr 6) or (b shl 26)) xor ((b shr 11) or (b shl 21)) xor
      ((b shr 25) or (b shl 7))) + ((b and c) xor (not b and d)) + $240ca1cc + W[3];
  t2:= (((f shr 2) or (f shl 30)) xor ((f shr 13) or (f shl 19)) xor
      ((f shr 22) xor (f shl 10))) + ((f and g) xor (f and h) xor (g and h));
  e:= t1 + t2;
  a:= a + t1;

  W[4]:= (((W[2] shr 17) or (W[2] shl 15)) xor
          ((W[2] shr 19) or (W[2] shl 13)) xor (W[2] shr 10)) + W[13] +
         (((W[5] shr 7) or (W[5] shl 25)) xor
          ((W[5] shr 18) or (W[5] shl 14)) xor (W[5] shr 3)) + W[4];
  t1:= d + (((a shr 6) or (a shl 26)) xor ((a shr 11) or (a shl 21)) xor
      ((a shr 25) or (a shl 7))) + ((a and b) xor (not a and c)) + $2de92c6f + W[4];
  t2:= (((e shr 2) or (e shl 30)) xor ((e shr 13) or (e shl 19)) xor
      ((e shr 22) xor (e shl 10))) + ((e and f) xor (e and g) xor (f and g));
  d:= t1 + t2;
  h:= h + t1;

  W[5]:= (((W[3] shr 17) or (W[3] shl 15)) xor
          ((W[3] shr 19) or (W[3] shl 13)) xor (W[3] shr 10)) + W[14] +
         (((W[6] shr 7) or (W[6] shl 25)) xor
          ((W[6] shr 18) or (W[6] shl 14)) xor (W[6] shr 3)) + W[5];
  t1:= c + (((h shr 6) or (h shl 26)) xor ((h shr 11) or (h shl 21)) xor
      ((h shr 25) or (h shl 7))) + ((h and a) xor (not h and b)) + $4a7484aa + W[5];
  t2:= (((d shr 2) or (d shl 30)) xor ((d shr 13) or (d shl 19)) xor
      ((d shr 22) xor (d shl 10))) + ((d and e) xor (d and f) xor (e and f));
  c:= t1 + t2;
  g:= g + t1;

  W[6]:= (((W[4] shr 17) or (W[4] shl 15)) xor
          ((W[4] shr 19) or (W[4] shl 13)) xor (W[4] shr 10)) + W[15] +
         (((W[7] shr 7) or (W[7] shl 25)) xor
          ((W[7] shr 18) or (W[7] shl 14)) xor (W[7] shr 3)) + W[6];
  t1:= b + (((g shr 6) or (g shl 26)) xor ((g shr 11) or (g shl 21)) xor
      ((g shr 25) or (g shl 7))) + ((g and h) xor (not g and a)) + $5cb0a9dc + W[6];
  t2:= (((c shr 2) or (c shl 30)) xor ((c shr 13) or (c shl 19)) xor
      ((c shr 22) xor (c shl 10))) + ((c and d) xor (c and e) xor (d and e));
  b:= t1 + t2;
  f:= f + t1;

  W[7]:= (((W[5] shr 17) or (W[5] shl 15)) xor
          ((W[5] shr 19) or (W[5] shl 13)) xor (W[5] shr 10)) + W[0] +
         (((W[8] shr 7) or (W[8] shl 25)) xor
          ((W[8] shr 18) or (W[8] shl 14)) xor (W[8] shr 3)) + W[7];
  t1:= a + (((f shr 6) or (f shl 26)) xor ((f shr 11) or (f shl 21)) xor
      ((f shr 25) or (f shl 7))) + ((f and g) xor (not f and h)) + $76f988da + W[7];
  t2:= (((b shr 2) or (b shl 30)) xor ((b shr 13) or (b shl 19)) xor
      ((b shr 22) xor (b shl 10))) + ((b and c) xor (b and d) xor (c and d));
  a:= t1 + t2;
  e:= e + t1;

  W[8]:= (((W[6] shr 17) or (W[6] shl 15)) xor
          ((W[6] shr 19) or (W[6] shl 13)) xor (W[6] shr 10)) + W[1] +
         (((W[9] shr 7) or (W[9] shl 25)) xor
          ((W[9] shr 18) or (W[9] shl 14)) xor (W[9] shr 3)) + W[8];
  t1:= h + (((e shr 6) or (e shl 26)) xor ((e shr 11) or (e shl 21)) xor
      ((e shr 25) or (e shl 7))) + ((e and f) xor (not e and g)) + $983e5152 + W[8];
  t2:= (((a shr 2) or (a shl 30)) xor ((a shr 13) or (a shl 19)) xor
      ((a shr 22) xor (a shl 10))) + ((a and b) xor (a and c) xor (b and c));
  h:= t1 + t2;
  d:= d + t1;

  W[9]:= (((W[7] shr 17) or (W[7] shl 15)) xor
          ((W[7] shr 19) or (W[7] shl 13)) xor (W[7] shr 10)) + W[2] +
         (((W[10] shr 7) or (W[10] shl 25)) xor
          ((W[10] shr 18) or (W[10] shl 14)) xor (W[10] shr 3)) + W[9];
  t1:= g + (((d shr 6) or (d shl 26)) xor ((d shr 11) or (d shl 21)) xor
      ((d shr 25) or (d shl 7))) + ((d and e) xor (not d and f)) + $a831c66d + W[9];
  t2:= (((h shr 2) or (h shl 30)) xor ((h shr 13) or (h shl 19)) xor
      ((h shr 22) xor (h shl 10))) + ((h and a) xor (h and b) xor (a and b));
  g:= t1 + t2;
  c:= c + t1;

  W[10]:= (((W[8] shr 17) or (W[8] shl 15)) xor
           ((W[8] shr 19) or (W[8] shl 13)) xor (W[8] shr 10)) + W[3] +
          (((W[11] shr 7) or (W[11] shl 25)) xor
           ((W[11] shr 18) or (W[11] shl 14)) xor (W[11] shr 3)) + W[10];
  t1:= f + (((c shr 6) or (c shl 26)) xor ((c shr 11) or (c shl 21)) xor
      ((c shr 25) or (c shl 7))) + ((c and d) xor (not c and e)) + $b00327c8 + W[10];
  t2:= (((g shr 2) or (g shl 30)) xor ((g shr 13) or (g shl 19)) xor
      ((g shr 22) xor (g shl 10))) + ((g and h) xor (g and a) xor (h and a));
  f:= t1 + t2;
  b:= b + t1;

  W[11]:= (((W[9] shr 17) or (W[9] shl 15)) xor
           ((W[9] shr 19) or (W[9] shl 13)) xor (W[9] shr 10)) + W[4] +
          (((W[12] shr 7) or (W[12] shl 25)) xor
           ((W[12] shr 18) or (W[12] shl 14)) xor (W[12] shr 3)) + W[11];
  t1:= e + (((b shr 6) or (b shl 26)) xor ((b shr 11) or (b shl 21)) xor
      ((b shr 25) or (b shl 7))) + ((b and c) xor (not b and d)) + $bf597fc7 + W[11];
  t2:= (((f shr 2) or (f shl 30)) xor ((f shr 13) or (f shl 19)) xor
      ((f shr 22) xor (f shl 10))) + ((f and g) xor (f and h) xor (g and h));
  e:= t1 + t2;
  a:= a + t1;

  W[12]:= (((W[10] shr 17) or (W[10] shl 15)) xor
           ((W[10] shr 19) or (W[10] shl 13)) xor (W[10] shr 10)) + W[5] +
          (((W[13] shr 7) or (W[13] shl 25)) xor
           ((W[13] shr 18) or (W[13] shl 14)) xor (W[13] shr 3)) + W[12];
  t1:= d + (((a shr 6) or (a shl 26)) xor ((a shr 11) or (a shl 21)) xor
      ((a shr 25) or (a shl 7))) + ((a and b) xor (not a and c)) + $c6e00bf3 + W[12];
  t2:= (((e shr 2) or (e shl 30)) xor ((e shr 13) or (e shl 19)) xor
      ((e shr 22) xor (e shl 10))) + ((e and f) xor (e and g) xor (f and g));
  d:= t1 + t2;
  h:= h + t1;

  W[13]:= (((W[11] shr 17) or (W[11] shl 15)) xor
           ((W[11] shr 19) or (W[11] shl 13)) xor (W[11] shr 10)) + W[6] +
          (((W[14] shr 7) or (W[14] shl 25)) xor
           ((W[14] shr 18) or (W[14] shl 14)) xor (W[14] shr 3)) + W[13];
  t1:= c + (((h shr 6) or (h shl 26)) xor ((h shr 11) or (h shl 21)) xor
      ((h shr 25) or (h shl 7))) + ((h and a) xor (not h and b)) + $d5a79147 + W[13];
  t2:= (((d shr 2) or (d shl 30)) xor ((d shr 13) or (d shl 19)) xor
      ((d shr 22) xor (d shl 10))) + ((d and e) xor (d and f) xor (e and f));
  c:= t1 + t2;
  g:= g + t1;

  W[14]:= (((W[12] shr 17) or (W[12] shl 15)) xor
           ((W[12] shr 19) or (W[12] shl 13)) xor (W[12] shr 10)) + W[7] +
          (((W[15] shr 7) or (W[15] shl 25)) xor
           ((W[15] shr 18) or (W[15] shl 14)) xor (W[15] shr 3)) + W[14];
  t1:= b + (((g shr 6) or (g shl 26)) xor ((g shr 11) or (g shl 21)) xor
      ((g shr 25) or (g shl 7))) + ((g and h) xor (not g and a)) + $06ca6351 + W[14];
  t2:= (((c shr 2) or (c shl 30)) xor ((c shr 13) or (c shl 19)) xor
      ((c shr 22) xor (c shl 10))) + ((c and d) xor (c and e) xor (d and e));
  b:= t1 + t2;
  f:= f + t1;

  W[15]:= (((W[13] shr 17) or (W[13] shl 15)) xor
           ((W[13] shr 19) or (W[13] shl 13)) xor (W[13] shr 10)) + W[8] +
          (((W[0] shr 7) or (W[0] shl 25)) xor
           ((W[0] shr 18) or (W[0] shl 14)) xor (W[0] shr 3)) + W[15];
  t1:= a + (((f shr 6) or (f shl 26)) xor ((f shr 11) or (f shl 21)) xor
      ((f shr 25) or (f shl 7))) + ((f and g) xor (not f and h)) + $14292967 + W[15];
  t2:= (((b shr 2) or (b shl 30)) xor ((b shr 13) or (b shl 19)) xor
      ((b shr 22) xor (b shl 10))) + ((b and c) xor (b and d) xor (c and d));
  a:= t1 + t2;
  e:= e + t1;

  W[0]:= (((W[14] shr 17) or (W[14] shl 15)) xor
          ((W[14] shr 19) or (W[14] shl 13)) xor (W[14] shr 10)) + W[9] +
         (((W[1] shr 7) or (W[1] shl 25)) xor
          ((W[1] shr 18) or (W[1] shl 14)) xor (W[1] shr 3)) + W[0];
  t1:= h + (((e shr 6) or (e shl 26)) xor ((e shr 11) or (e shl 21)) xor
      ((e shr 25) or (e shl 7))) + ((e and f) xor (not e and g)) + $27b70a85 + W[0];
  t2:= (((a shr 2) or (a shl 30)) xor ((a shr 13) or (a shl 19)) xor
      ((a shr 22) xor (a shl 10))) + ((a and b) xor (a and c) xor (b and c));
  h:= t1 + t2;
  d:= d + t1;

  W[1]:= (((W[15] shr 17) or (W[15] shl 15)) xor
          ((W[15] shr 19) or (W[15] shl 13)) xor (W[15] shr 10)) + W[10] +
         (((W[2] shr 7) or (W[2] shl 25)) xor
          ((W[2] shr 18) or (W[2] shl 14)) xor (W[2] shr 3)) + W[1];
  t1:= g + (((d shr 6) or (d shl 26)) xor ((d shr 11) or (d shl 21)) xor
      ((d shr 25) or (d shl 7))) + ((d and e) xor (not d and f)) + $2e1b2138 + W[1];
  t2:= (((h shr 2) or (h shl 30)) xor ((h shr 13) or (h shl 19)) xor
      ((h shr 22) xor (h shl 10))) + ((h and a) xor (h and b) xor (a and b));
  g:= t1 + t2;
  c:= c + t1;

  W[2]:= (((W[0] shr 17) or (W[0] shl 15)) xor
          ((W[0] shr 19) or (W[0] shl 13)) xor (W[0] shr 10)) + W[11] +
         (((W[3] shr 7) or (W[3] shl 25)) xor
          ((W[3] shr 18) or (W[3] shl 14)) xor (W[3] shr 3)) + W[2];
  t1:= f + (((c shr 6) or (c shl 26)) xor ((c shr 11) or (c shl 21)) xor
      ((c shr 25) or (c shl 7))) + ((c and d) xor (not c and e)) + $4d2c6dfc + W[2];
  t2:= (((g shr 2) or (g shl 30)) xor ((g shr 13) or (g shl 19)) xor
      ((g shr 22) xor (g shl 10))) + ((g and h) xor (g and a) xor (h and a));
  f:= t1 + t2;
  b:= b + t1;

  W[3]:= (((W[1] shr 17) or (W[1] shl 15)) xor
          ((W[1] shr 19) or (W[1] shl 13)) xor (W[1] shr 10)) + W[12] +
         (((W[4] shr 7) or (W[4] shl 25)) xor
          ((W[4] shr 18) or (W[4] shl 14)) xor (W[4] shr 3)) + W[3];
  t1:= e + (((b shr 6) or (b shl 26)) xor ((b shr 11) or (b shl 21)) xor
      ((b shr 25) or (b shl 7))) + ((b and c) xor (not b and d)) + $53380d13 + W[3];
  t2:= (((f shr 2) or (f shl 30)) xor ((f shr 13) or (f shl 19)) xor
      ((f shr 22) xor (f shl 10))) + ((f and g) xor (f and h) xor (g and h));
  e:= t1 + t2;
  a:= a + t1;

  W[4]:= (((W[2] shr 17) or (W[2] shl 15)) xor
          ((W[2] shr 19) or (W[2] shl 13)) xor (W[2] shr 10)) + W[13] +
         (((W[5] shr 7) or (W[5] shl 25)) xor
          ((W[5] shr 18) or (W[5] shl 14)) xor (W[5] shr 3)) + W[4];
  t1:= d + (((a shr 6) or (a shl 26)) xor ((a shr 11) or (a shl 21)) xor
      ((a shr 25) or (a shl 7))) + ((a and b) xor (not a and c)) + $650a7354 + W[4];
  t2:= (((e shr 2) or (e shl 30)) xor ((e shr 13) or (e shl 19)) xor
      ((e shr 22) xor (e shl 10))) + ((e and f) xor (e and g) xor (f and g));
  d:= t1 + t2;
  h:= h + t1;

  W[5]:= (((W[3] shr 17) or (W[3] shl 15)) xor
          ((W[3] shr 19) or (W[3] shl 13)) xor (W[3] shr 10)) + W[14] +
         (((W[6] shr 7) or (W[6] shl 25)) xor
          ((W[6] shr 18) or (W[6] shl 14)) xor (W[6] shr 3)) + W[5];
  t1:= c + (((h shr 6) or (h shl 26)) xor ((h shr 11) or (h shl 21)) xor
      ((h shr 25) or (h shl 7))) + ((h and a) xor (not h and b)) + $766a0abb + W[5];
  t2:= (((d shr 2) or (d shl 30)) xor ((d shr 13) or (d shl 19)) xor
      ((d shr 22) xor (d shl 10))) + ((d and e) xor (d and f) xor (e and f));
  c:= t1 + t2;
  g:= g + t1;

  W[6]:= (((W[4] shr 17) or (W[4] shl 15)) xor
          ((W[4] shr 19) or (W[4] shl 13)) xor (W[4] shr 10)) + W[15] +
         (((W[7] shr 7) or (W[7] shl 25)) xor
          ((W[7] shr 18) or (W[7] shl 14)) xor (W[7] shr 3)) + W[6];
  t1:= b + (((g shr 6) or (g shl 26)) xor ((g shr 11) or (g shl 21)) xor
      ((g shr 25) or (g shl 7))) + ((g and h) xor (not g and a)) + $81c2c92e + W[6];
  t2:= (((c shr 2) or (c shl 30)) xor ((c shr 13) or (c shl 19)) xor
      ((c shr 22) xor (c shl 10))) + ((c and d) xor (c and e) xor (d and e));
  b:= t1 + t2;
  f:= f + t1;

  W[7]:= (((W[5] shr 17) or (W[5] shl 15)) xor
          ((W[5] shr 19) or (W[5] shl 13)) xor (W[5] shr 10)) + W[0] +
         (((W[8] shr 7) or (W[8] shl 25)) xor
          ((W[8] shr 18) or (W[8] shl 14)) xor (W[8] shr 3)) + W[7];
  t1:= a + (((f shr 6) or (f shl 26)) xor ((f shr 11) or (f shl 21)) xor
      ((f shr 25) or (f shl 7))) + ((f and g) xor (not f and h)) + $92722c85 + W[7];
  t2:= (((b shr 2) or (b shl 30)) xor ((b shr 13) or (b shl 19)) xor
      ((b shr 22) xor (b shl 10))) + ((b and c) xor (b and d) xor (c and d));
  a:= t1 + t2;
  e:= e + t1;

  W[8]:= (((W[6] shr 17) or (W[6] shl 15)) xor
          ((W[6] shr 19) or (W[6] shl 13)) xor (W[6] shr 10)) + W[1] +
         (((W[9] shr 7) or (W[9] shl 25)) xor
          ((W[9] shr 18) or (W[9] shl 14)) xor (W[9] shr 3)) + W[8];
  t1:= h + (((e shr 6) or (e shl 26)) xor ((e shr 11) or (e shl 21)) xor
      ((e shr 25) or (e shl 7))) + ((e and f) xor (not e and g)) + $a2bfe8a1 + W[8];
  t2:= (((a shr 2) or (a shl 30)) xor ((a shr 13) or (a shl 19)) xor
      ((a shr 22) xor (a shl 10))) + ((a and b) xor (a and c) xor (b and c));
  h:= t1 + t2;
  d:= d + t1;

  W[9]:= (((W[7] shr 17) or (W[7] shl 15)) xor
          ((W[7] shr 19) or (W[7] shl 13)) xor (W[7] shr 10)) + W[2] +
         (((W[10] shr 7) or (W[10] shl 25)) xor
          ((W[10] shr 18) or (W[10] shl 14)) xor (W[10] shr 3)) + W[9];
  t1:= g + (((d shr 6) or (d shl 26)) xor ((d shr 11) or (d shl 21)) xor
      ((d shr 25) or (d shl 7))) + ((d and e) xor (not d and f)) + $a81a664b + W[9];
  t2:= (((h shr 2) or (h shl 30)) xor ((h shr 13) or (h shl 19)) xor
      ((h shr 22) xor (h shl 10))) + ((h and a) xor (h and b) xor (a and b));
  g:= t1 + t2;
  c:= c + t1;

  W[10]:= (((W[8] shr 17) or (W[8] shl 15)) xor
           ((W[8] shr 19) or (W[8] shl 13)) xor (W[8] shr 10)) + W[3] +
          (((W[11] shr 7) or (W[11] shl 25)) xor
           ((W[11] shr 18) or (W[11] shl 14)) xor (W[11] shr 3)) + W[10];
  t1:= f + (((c shr 6) or (c shl 26)) xor ((c shr 11) or (c shl 21)) xor
      ((c shr 25) or (c shl 7))) + ((c and d) xor (not c and e)) + $c24b8b70 + W[10];
  t2:= (((g shr 2) or (g shl 30)) xor ((g shr 13) or (g shl 19)) xor
      ((g shr 22) xor (g shl 10))) + ((g and h) xor (g and a) xor (h and a));
  f:= t1 + t2;
  b:= b + t1;

  W[11]:= (((W[9] shr 17) or (W[9] shl 15)) xor
           ((W[9] shr 19) or (W[9] shl 13)) xor (W[9] shr 10)) + W[4] +
          (((W[12] shr 7) or (W[12] shl 25)) xor
           ((W[12] shr 18) or (W[12] shl 14)) xor (W[12] shr 3)) + W[11];
  t1:= e + (((b shr 6) or (b shl 26)) xor ((b shr 11) or (b shl 21)) xor
      ((b shr 25) or (b shl 7))) + ((b and c) xor (not b and d)) + $c76c51a3 + W[11];
  t2:= (((f shr 2) or (f shl 30)) xor ((f shr 13) or (f shl 19)) xor
      ((f shr 22) xor (f shl 10))) + ((f and g) xor (f and h) xor (g and h));
  e:= t1 + t2;
  a:= a + t1;

  W[12]:= (((W[10] shr 17) or (W[10] shl 15)) xor
           ((W[10] shr 19) or (W[10] shl 13)) xor (W[10] shr 10)) + W[5] +
          (((W[13] shr 7) or (W[13] shl 25)) xor
           ((W[13] shr 18) or (W[13] shl 14)) xor (W[13] shr 3)) + W[12];
  t1:= d + (((a shr 6) or (a shl 26)) xor ((a shr 11) or (a shl 21)) xor
      ((a shr 25) or (a shl 7))) + ((a and b) xor (not a and c)) + $d192e819 + W[12];
  t2:= (((e shr 2) or (e shl 30)) xor ((e shr 13) or (e shl 19)) xor
      ((e shr 22) xor (e shl 10))) + ((e and f) xor (e and g) xor (f and g));
  d:= t1 + t2;
  h:= h + t1;

  W[13]:= (((W[11] shr 17) or (W[11] shl 15)) xor
           ((W[11] shr 19) or (W[11] shl 13)) xor (W[11] shr 10)) + W[6] +
          (((W[14] shr 7) or (W[14] shl 25)) xor
           ((W[14] shr 18) or (W[14] shl 14)) xor (W[14] shr 3)) + W[13];
  t1:= c + (((h shr 6) or (h shl 26)) xor ((h shr 11) or (h shl 21)) xor
      ((h shr 25) or (h shl 7))) + ((h and a) xor (not h and b)) + $d6990624 + W[13];
  t2:= (((d shr 2) or (d shl 30)) xor ((d shr 13) or (d shl 19)) xor
      ((d shr 22) xor (d shl 10))) + ((d and e) xor (d and f) xor (e and f));
  c:= t1 + t2;
  g:= g + t1;

  W[14]:= (((W[12] shr 17) or (W[12] shl 15)) xor
           ((W[12] shr 19) or (W[12] shl 13)) xor (W[12] shr 10)) + W[7] +
          (((W[15] shr 7) or (W[15] shl 25)) xor
           ((W[15] shr 18) or (W[15] shl 14)) xor (W[15] shr 3)) + W[14];
  t1:= b + (((g shr 6) or (g shl 26)) xor ((g shr 11) or (g shl 21)) xor
      ((g shr 25) or (g shl 7))) + ((g and h) xor (not g and a)) + $f40e3585 + W[14];
  t2:= (((c shr 2) or (c shl 30)) xor ((c shr 13) or (c shl 19)) xor
      ((c shr 22) xor (c shl 10))) + ((c and d) xor (c and e) xor (d and e));
  b:= t1 + t2;
  f:= f + t1;

  W[15]:= (((W[13] shr 17) or (W[13] shl 15)) xor
           ((W[13] shr 19) or (W[13] shl 13)) xor (W[13] shr 10)) + W[8] +
          (((W[0] shr 7) or (W[0] shl 25)) xor
           ((W[0] shr 18) or (W[0] shl 14)) xor (W[0] shr 3)) + W[15];
  t1:= a + (((f shr 6) or (f shl 26)) xor ((f shr 11) or (f shl 21)) xor
      ((f shr 25) or (f shl 7))) + ((f and g) xor (not f and h)) + $106aa070 + W[15];
  t2:= (((b shr 2) or (b shl 30)) xor ((b shr 13) or (b shl 19)) xor
      ((b shr 22) xor (b shl 10))) + ((b and c) xor (b and d) xor (c and d));
  a:= t1 + t2;
  e:= e + t1;

  W[0]:= (((W[14] shr 17) or (W[14] shl 15)) xor
           ((W[14] shr 19) or (W[14] shl 13)) xor (W[14] shr 10)) + W[9] +
         (((W[1] shr 7) or (W[1] shl 25)) xor
          ((W[1] shr 18) or (W[1] shl 14)) xor (W[1] shr 3)) + W[0];
  t1:= h + (((e shr 6) or (e shl 26)) xor ((e shr 11) or (e shl 21)) xor
      ((e shr 25) or (e shl 7))) + ((e and f) xor (not e and g)) + $19a4c116 + W[0];
  t2:= (((a shr 2) or (a shl 30)) xor ((a shr 13) or (a shl 19)) xor
      ((a shr 22) xor (a shl 10))) + ((a and b) xor (a and c) xor (b and c));
  h:= t1 + t2;
  d:= d + t1;

  W[1]:= (((W[15] shr 17) or (W[15] shl 15)) xor
          ((W[15] shr 19) or (W[15] shl 13)) xor (W[15] shr 10)) + W[10] +
         (((W[2] shr 7) or (W[2] shl 25)) xor
          ((W[2] shr 18) or (W[2] shl 14)) xor (W[2] shr 3)) + W[1];
  t1:= g + (((d shr 6) or (d shl 26)) xor ((d shr 11) or (d shl 21)) xor
      ((d shr 25) or (d shl 7))) + ((d and e) xor (not d and f)) + $1e376c08 + W[1];
  t2:= (((h shr 2) or (h shl 30)) xor ((h shr 13) or (h shl 19)) xor
      ((h shr 22) xor (h shl 10))) + ((h and a) xor (h and b) xor (a and b));
  g:= t1 + t2;
  c:= c + t1;

  W[2]:= (((W[0] shr 17) or (W[0] shl 15)) xor
          ((W[0] shr 19) or (W[0] shl 13)) xor (W[0] shr 10)) + W[11] +
         (((W[3] shr 7) or (W[3] shl 25)) xor
          ((W[3] shr 18) or (W[3] shl 14)) xor (W[3] shr 3)) + W[2];
  t1:= f + (((c shr 6) or (c shl 26)) xor ((c shr 11) or (c shl 21)) xor
      ((c shr 25) or (c shl 7))) + ((c and d) xor (not c and e)) + $2748774c + W[2];
  t2:= (((g shr 2) or (g shl 30)) xor ((g shr 13) or (g shl 19)) xor
      ((g shr 22) xor (g shl 10))) + ((g and h) xor (g and a) xor (h and a));
  f:= t1 + t2;
  b:= b + t1;

  W[3]:= (((W[1] shr 17) or (W[1] shl 15)) xor
          ((W[1] shr 19) or (W[1] shl 13)) xor (W[1] shr 10)) + W[12] +
         (((W[4] shr 7) or (W[4] shl 25)) xor
          ((W[4] shr 18) or (W[4] shl 14)) xor (W[4] shr 3)) + W[3];
  t1:= e + (((b shr 6) or (b shl 26)) xor ((b shr 11) or (b shl 21)) xor
      ((b shr 25) or (b shl 7))) + ((b and c) xor (not b and d)) + $34b0bcb5 + W[3];
  t2:= (((f shr 2) or (f shl 30)) xor ((f shr 13) or (f shl 19)) xor
      ((f shr 22) xor (f shl 10))) + ((f and g) xor (f and h) xor (g and h));
  e:= t1 + t2;
  a:= a + t1;

  W[4]:= (((W[2] shr 17) or (W[2] shl 15)) xor
          ((W[2] shr 19) or (W[2] shl 13)) xor (W[2] shr 10)) + W[13] +
         (((W[5] shr 7) or (W[5] shl 25)) xor
          ((W[5] shr 18) or (W[5] shl 14)) xor (W[5] shr 3)) + W[4];
  t1:= d + (((a shr 6) or (a shl 26)) xor ((a shr 11) or (a shl 21)) xor
      ((a shr 25) or (a shl 7))) + ((a and b) xor (not a and c)) + $391c0cb3 + W[4];
  t2:= (((e shr 2) or (e shl 30)) xor ((e shr 13) or (e shl 19)) xor
      ((e shr 22) xor (e shl 10))) + ((e and f) xor (e and g) xor (f and g));
  d:= t1 + t2;
  h:= h + t1;

  W[5]:= (((W[3] shr 17) or (W[3] shl 15)) xor
          ((W[3] shr 19) or (W[3] shl 13)) xor (W[3] shr 10)) + W[14] +
         (((W[6] shr 7) or (W[6] shl 25)) xor
          ((W[6] shr 18) or (W[6] shl 14)) xor (W[6] shr 3)) + W[5];
  t1:= c + (((h shr 6) or (h shl 26)) xor ((h shr 11) or (h shl 21)) xor
      ((h shr 25) or (h shl 7))) + ((h and a) xor (not h and b)) + $4ed8aa4a + W[5];
  t2:= (((d shr 2) or (d shl 30)) xor ((d shr 13) or (d shl 19)) xor
      ((d shr 22) xor (d shl 10))) + ((d and e) xor (d and f) xor (e and f));
  c:= t1 + t2;
  g:= g + t1;

  W[6]:= (((W[4] shr 17) or (W[4] shl 15)) xor
          ((W[4] shr 19) or (W[4] shl 13)) xor (W[4] shr 10)) + W[15] +
         (((W[7] shr 7) or (W[7] shl 25)) xor
          ((W[7] shr 18) or (W[7] shl 14)) xor (W[7] shr 3)) + W[6];
  t1:= b + (((g shr 6) or (g shl 26)) xor ((g shr 11) or (g shl 21)) xor
      ((g shr 25) or (g shl 7))) + ((g and h) xor (not g and a)) + $5b9cca4f + W[6];
  t2:= (((c shr 2) or (c shl 30)) xor ((c shr 13) or (c shl 19)) xor
      ((c shr 22) xor (c shl 10))) + ((c and d) xor (c and e) xor (d and e));
  b:= t1 + t2;
  f:= f + t1;

  W[7]:= (((W[5] shr 17) or (W[5] shl 15)) xor
          ((W[5] shr 19) or (W[5] shl 13)) xor (W[5] shr 10)) + W[0] +
         (((W[8] shr 7) or (W[8] shl 25)) xor
          ((W[8] shr 18) or (W[8] shl 14)) xor (W[8] shr 3)) + W[7];
  t1:= a + (((f shr 6) or (f shl 26)) xor ((f shr 11) or (f shl 21)) xor
      ((f shr 25) or (f shl 7))) + ((f and g) xor (not f and h)) + $682e6ff3 + W[7];
  t2:= (((b shr 2) or (b shl 30)) xor ((b shr 13) or (b shl 19)) xor
      ((b shr 22) xor (b shl 10))) + ((b and c) xor (b and d) xor (c and d));
  a:= t1 + t2;
  e:= e + t1;

  W[8]:= (((W[6] shr 17) or (W[6] shl 15)) xor
          ((W[6] shr 19) or (W[6] shl 13)) xor (W[6] shr 10)) + W[1] +
         (((W[9] shr 7) or (W[9] shl 25)) xor
          ((W[9] shr 18) or (W[9] shl 14)) xor (W[9] shr 3)) + W[8];
  t1:= h + (((e shr 6) or (e shl 26)) xor ((e shr 11) or (e shl 21)) xor
      ((e shr 25) or (e shl 7))) + ((e and f) xor (not e and g)) + $748f82ee + W[8];
  t2:= (((a shr 2) or (a shl 30)) xor ((a shr 13) or (a shl 19)) xor
      ((a shr 22) xor (a shl 10))) + ((a and b) xor (a and c) xor (b and c));
  h:= t1 + t2;
  d:= d + t1;

  W[9]:= (((W[7] shr 17) or (W[7] shl 15)) xor
          ((W[7] shr 19) or (W[7] shl 13)) xor (W[7] shr 10)) + W[2] +
         (((W[10] shr 7) or (W[10] shl 25)) xor
          ((W[10] shr 18) or (W[10] shl 14)) xor (W[10] shr 3)) + W[9];
  t1:= g + (((d shr 6) or (d shl 26)) xor ((d shr 11) or (d shl 21)) xor
      ((d shr 25) or (d shl 7))) + ((d and e) xor (not d and f)) + $78a5636f + W[9];
  t2:= (((h shr 2) or (h shl 30)) xor ((h shr 13) or (h shl 19)) xor
      ((h shr 22) xor (h shl 10))) + ((h and a) xor (h and b) xor (a and b));
  g:= t1 + t2;
  c:= c + t1;

  W[10]:= (((W[8] shr 17) or (W[8] shl 15)) xor
           ((W[8] shr 19) or (W[8] shl 13)) xor (W[8] shr 10)) + W[3] +
          (((W[11] shr 7) or (W[11] shl 25)) xor
           ((W[11] shr 18) or (W[11] shl 14)) xor (W[11] shr 3)) + W[10];
  t1:= f + (((c shr 6) or (c shl 26)) xor ((c shr 11) or (c shl 21)) xor
      ((c shr 25) or (c shl 7))) + ((c and d) xor (not c and e)) + $84c87814 + W[10];
  t2:= (((g shr 2) or (g shl 30)) xor ((g shr 13) or (g shl 19)) xor
      ((g shr 22) xor (g shl 10))) + ((g and h) xor (g and a) xor (h and a));
  f:= t1 + t2;
  b:= b + t1;

  W[11]:= (((W[9] shr 17) or (W[9] shl 15)) xor
           ((W[9] shr 19) or (W[9] shl 13)) xor (W[9] shr 10)) + W[4] +
          (((W[12] shr 7) or (W[12] shl 25)) xor
           ((W[12] shr 18) or (W[12] shl 14)) xor (W[12] shr 3)) + W[11];
  t1:= e + (((b shr 6) or (b shl 26)) xor ((b shr 11) or (b shl 21)) xor
      ((b shr 25) or (b shl 7))) + ((b and c) xor (not b and d)) + $8cc70208 + W[11];
  t2:= (((f shr 2) or (f shl 30)) xor ((f shr 13) or (f shl 19)) xor
      ((f shr 22) xor (f shl 10))) + ((f and g) xor (f and h) xor (g and h));
  e:= t1 + t2;
  a:= a + t1;

  W[12]:= (((W[10] shr 17) or (W[10] shl 15)) xor
           ((W[10] shr 19) or (W[10] shl 13)) xor (W[10] shr 10)) + W[5] +
          (((W[13] shr 7) or (W[13] shl 25)) xor
           ((W[13] shr 18) or (W[13] shl 14)) xor (W[13] shr 3)) + W[12];
  t1:= d + (((a shr 6) or (a shl 26)) xor ((a shr 11) or (a shl 21)) xor
      ((a shr 25) or (a shl 7))) + ((a and b) xor (not a and c)) + $90befffa + W[12];
  t2:= (((e shr 2) or (e shl 30)) xor ((e shr 13) or (e shl 19)) xor
      ((e shr 22) xor (e shl 10))) + ((e and f) xor (e and g) xor (f and g));
  d:= t1 + t2;
  h:= h + t1;

  W[13]:= (((W[11] shr 17) or (W[11] shl 15)) xor
           ((W[11] shr 19) or (W[11] shl 13)) xor (W[11] shr 10)) + W[6] +
          (((W[14] shr 7) or (W[14] shl 25)) xor
           ((W[14] shr 18) or (W[14] shl 14)) xor (W[14] shr 3)) + W[13];
  t1:= c + (((h shr 6) or (h shl 26)) xor ((h shr 11) or (h shl 21)) xor
      ((h shr 25) or (h shl 7))) + ((h and a) xor (not h and b)) + $a4506ceb + W[13];
  t2:= (((d shr 2) or (d shl 30)) xor ((d shr 13) or (d shl 19)) xor
      ((d shr 22) xor (d shl 10))) + ((d and e) xor (d and f) xor (e and f));
  c:= t1 + t2;
  g:= g + t1;

  W[14]:= (((W[12] shr 17) or (W[12] shl 15)) xor
           ((W[12] shr 19) or (W[12] shl 13)) xor (W[12] shr 10)) + W[7] +
          (((W[15] shr 7) or (W[15] shl 25)) xor
           ((W[15] shr 18) or (W[15] shl 14)) xor (W[15] shr 3)) + W[14];
  t1:= b + (((g shr 6) or (g shl 26)) xor ((g shr 11) or (g shl 21)) xor
      ((g shr 25) or (g shl 7))) + ((g and h) xor (not g and a)) + $bef9a3f7 + W[14];
  t2:= (((c shr 2) or (c shl 30)) xor ((c shr 13) or (c shl 19)) xor
      ((c shr 22) xor (c shl 10))) + ((c and d) xor (c and e) xor (d and e));
  b:= t1 + t2;
  f:= f + t1;

  W[15]:= (((W[13] shr 17) or (W[13] shl 15)) xor
           ((W[13] shr 19) or (W[13] shl 13)) xor (W[13] shr 10)) + W[8] +
          (((W[0] shr 7) or (W[0] shl 25)) xor
           ((W[0] shr 18) or (W[0] shl 14)) xor (W[0] shr 3)) + W[15];
  t1:= a + (((f shr 6) or (f shl 26)) xor ((f shr 11) or (f shl 21)) xor
      ((f shr 25) or (f shl 7))) + ((f and g) xor (not f and h)) + $c67178f2 + W[15];
  t2:= (((b shr 2) or (b shl 30)) xor ((b shr 13) or (b shl 19)) xor
      ((b shr 22) xor (b shl 10))) + ((b and c) xor (b and d) xor (c and d));
  a:= t1 + t2;
  e:= e + t1;

  FData.Digest[0]:= FData.Digest[0] + a;
  FData.Digest[1]:= FData.Digest[1] + b;
  FData.Digest[2]:= FData.Digest[2] + c;
  FData.Digest[3]:= FData.Digest[3] + d;
  FData.Digest[4]:= FData.Digest[4] + e;
  FData.Digest[5]:= FData.Digest[5] + f;
  FData.Digest[6]:= FData.Digest[6] + g;
  FData.Digest[7]:= FData.Digest[7] + h;

//  FillChar(W, SizeOf(W), 0);
  FillChar(FData.Block, SizeOf(FData.Block), 0);
end;
{$ENDIF}
{$ENDIF}

{$IFDEF CPUX86_WIN32}
procedure TSHA256Alg.Compress;
const
// SHA256 registers:
  DigestA = -32;  // [EDI - 32]
  DigestB = -28;  // [EDI - 28]
  DigestC = -24;  // [EDI - 24]
  DigestD = -20;  // [EDI - 20]
  DigestE = -16;  // [EDI - 16]
  DigestF = -12;  // [EDI - 12]
  DigestG = -8;   // [EDI - 8]
  DigestH = -4;   // [EDI - 4]

  RegA = 28;      // [ESP + 28]
  RegB = 24;      // [ESP + 24]
  RegC = 20;      // [ESP + 20]
  RegD = 16;      // [ESP + 16]
  RegE = 12;      // [ESP + 12]
  RegF = 8;       // [ESP + 8]
  RegG = 4;       // [ESP + 4]
  RegH = 0;       // [ESP]

  W0  = 0;    W1  = 4;    W2  = 8;    W3  = 12;
  W4  = 16;   W5  = 20;   W6  = 24;   W7  = 28;
  W8  = 32;   W9  = 36;   W10 = 40;   W11 = 44;
  W12 = 48;   W13 = 52;   W14 = 56;   W15 = 60;

asm
        PUSH    ESI
        PUSH    EDI
        PUSH    EBX
        PUSH    EBP

        LEA     EDI,[EAX].TSHA256Alg.FData.Block    // W:= @FData.Block;

        PUSH    [EDI].DigestA
        PUSH    [EDI].DigestB
        PUSH    [EDI].DigestC
        PUSH    [EDI].DigestD
        PUSH    [EDI].DigestE
        PUSH    [EDI].DigestF
        PUSH    [EDI].DigestG
        PUSH    [EDI].DigestH
{
        SUB     ESP,32
        MOV     EAX,[EDI].DigestA
        MOV     [ESP].RegA,EAX
        MOV     EAX,[EDI].DigestB
        MOV     [ESP].RegB,EAX
        MOV     EAX,[EDI].DigestC
        MOV     [ESP].RegC,EAX
        MOV     EAX,[EDI].DigestD
        MOV     [ESP].RegD,EAX
        MOV     EAX,[EDI].DigestE
        MOV     [ESP].RegE,EAX
        MOV     EAX,[EDI].DigestF
        MOV     [ESP].RegF,EAX
        MOV     EAX,[EDI].DigestG
        MOV     [ESP].RegG,EAX
        MOV     EAX,[EDI].DigestH
        MOV     [ESP].RegH,EAX
}
//  W[0]:= Swap32(W[0]);

        MOV     ESI,[EDI].W0
        BSWAP   ESI
        MOV     [EDI].W0,ESI

//  t1:= h + (((e shr 6) or (e shl 26)) xor ((e shr 11) or (e shl 21)) xor
//      ((e shr 25) or (e shl 7))) + ((e and f) xor (not e and g)) + $428a2f98 + W[0];

        MOV     EAX,[ESP].RegE
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,[ESP].RegF
        NOT     EAX
        AND     EAX,[ESP].RegG
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$428a2f98
        ADD     EBX,[ESP].RegH

//  t2:= (((a shr 2) or (a shl 30)) xor ((a shr 13) or (a shl 19)) xor
//      ((a shr 22) xor (a shl 10))) + ((a and b) xor (a and c) xor (b and c));

        MOV     EAX,[ESP].RegA
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,[ESP].RegB
        MOV     EBP,[ESP].RegC
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  h:= t1 + t2;
//  d:= d + t1;

        ADD     [ESP].RegD,EBX
        ADD     EAX,EBX
        MOV     [ESP].RegH,EAX


//  W[1]:= Swap32(W[1]);

        MOV     ESI,[EDI].W1
        BSWAP   ESI
        MOV     [EDI].W1,ESI

//  t1:= g + (((d shr 6) or (d shl 26)) xor ((d shr 11) or (d shl 21)) xor
//      ((d shr 25) or (d shl 7))) + ((d and e) xor (not d and f)) + $71374491 + W[1];

        MOV     EAX,[ESP].RegD
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,[ESP].RegE
        NOT     EAX
        AND     EAX,[ESP].RegF
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$71374491
        ADD     EBX,[ESP].RegG

//  t2:= (((h shr 2) or (h shl 30)) xor ((h shr 13) or (h shl 19)) xor
//      ((h shr 22) xor (h shl 10))) + ((h and a) xor (h and b) xor (a and b));

        MOV     EAX,[ESP].RegH
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,[ESP].RegA
        MOV     EBP,[ESP].RegB
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  g:= t1 + t2;
//  c:= c + t1;

        ADD     [ESP].RegC,EBX
        ADD     EAX,EBX
        MOV     [ESP].RegG,EAX


//  W[2]:= Swap32(W[2]);

        MOV     ESI,[EDI].W2
        BSWAP   ESI
        MOV     [EDI].W2,ESI

//  t1:= f + (((c shr 6) or (c shl 26)) xor ((c shr 11) or (c shl 21)) xor
//      ((c shr 25) or (c shl 7))) + ((c and d) xor (not c and e)) + $b5c0fbcf + W[2];

        MOV     EAX,[ESP].RegC
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,[ESP].RegD
        NOT     EAX
        AND     EAX,[ESP].RegE
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$b5c0fbcf
        ADD     EBX,[ESP].RegF

//  t2:= (((g shr 2) or (g shl 30)) xor ((g shr 13) or (g shl 19)) xor
//      ((g shr 22) xor (g shl 10))) + ((g and h) xor (g and a) xor (h and a));

        MOV     EAX,[ESP].RegG
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,[ESP].RegH
        MOV     EBP,[ESP].RegA
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  f:= t1 + t2;
//  b:= b + t1;

        ADD     [ESP].RegB,EBX
        ADD     EAX,EBX
        MOV     [ESP].RegF,EAX


//  W[3]:= Swap32(W[3]);

        MOV     ESI,[EDI].W3
        BSWAP   ESI
        MOV     [EDI].W3,ESI

//  t1:= e + (((b shr 6) or (b shl 26)) xor ((b shr 11) or (b shl 21)) xor
//      ((b shr 25) or (b shl 7))) + ((b and c) xor (not b and d)) + $e9b5dba5 + W[3];

        MOV     EAX,[ESP].RegB
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,[ESP].RegC
        NOT     EAX
        AND     EAX,[ESP].RegD
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$e9b5dba5
        ADD     EBX,[ESP].RegE

//  t2:= (((f shr 2) or (f shl 30)) xor ((f shr 13) or (f shl 19)) xor
//      ((f shr 22) xor (f shl 10))) + ((f and g) xor (f and h) xor (g and h));

        MOV     EAX,[ESP].RegF
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,[ESP].RegG
        MOV     EBP,[ESP].RegH
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  e:= t1 + t2;
//  a:= a + t1;

        ADD     [ESP].RegA,EBX
        ADD     EAX,EBX
        MOV     [ESP].RegE,EAX

//  W[4]:= Swap32(W[4]);

        MOV     ESI,[EDI].W4
        BSWAP   ESI
        MOV     [EDI].W4,ESI

//  t1:= d + (((a shr 6) or (a shl 26)) xor ((a shr 11) or (a shl 21)) xor
//      ((a shr 25) or (a shl 7))) + ((a and b) xor (not a and c)) + $3956c25b + W[4];

        MOV     EAX,[ESP].RegA
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,[ESP].RegB
        NOT     EAX
        AND     EAX,[ESP].RegC
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$3956c25b
        ADD     EBX,[ESP].RegD

//  t2:= (((e shr 2) or (e shl 30)) xor ((e shr 13) or (e shl 19)) xor
//      ((e shr 22) xor (e shl 10))) + ((e and f) xor (e and g) xor (f and g));

        MOV     EAX,[ESP].RegE
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,[ESP].RegF
        MOV     EBP,[ESP].RegG
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  d:= t1 + t2;
//  h:= h + t1;

        ADD     [ESP].RegH,EBX
        ADD     EAX,EBX
        MOV     [ESP].RegD,EAX

//  W[5]:= Swap32(W[5]);

        MOV     ESI,[EDI].W5
        BSWAP   ESI
        MOV     [EDI].W5,ESI

//  t1:= c + (((h shr 6) or (h shl 26)) xor ((h shr 11) or (h shl 21)) xor
//      ((h shr 25) or (h shl 7))) + ((h and a) xor (not h and b)) + $59f111f1 + W[5];

        MOV     EAX,[ESP].RegH
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,[ESP].RegA
        NOT     EAX
        AND     EAX,[ESP].RegB
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$59f111f1
        ADD     EBX,[ESP].RegC

//  t2:= (((d shr 2) or (d shl 30)) xor ((d shr 13) or (d shl 19)) xor
//      ((d shr 22) xor (d shl 10))) + ((d and e) xor (d and f) xor (e and f));

        MOV     EAX,[ESP].RegD
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,[ESP].RegE
        MOV     EBP,[ESP].RegF
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  c:= t1 + t2;
//  g:= g + t1;

        ADD     [ESP].RegG,EBX
        ADD     EAX,EBX
        MOV     [ESP].RegC,EAX

//  W[6]:= Swap32(W[6]);

        MOV     ESI,[EDI].W6
        BSWAP   ESI
        MOV     [EDI].W6,ESI

//  t1:= b + (((g shr 6) or (g shl 26)) xor ((g shr 11) or (g shl 21)) xor
//      ((g shr 25) or (g shl 7))) + ((g and h) xor (not g and a)) + $923f82a4 + W[6];

        MOV     EAX,[ESP].RegG
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,[ESP].RegH
        NOT     EAX
        AND     EAX,[ESP].RegA
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$923f82a4
        ADD     EBX,[ESP].RegB

//  t2:= (((c shr 2) or (c shl 30)) xor ((c shr 13) or (c shl 19)) xor
//      ((c shr 22) xor (c shl 10))) + ((c and d) xor (c and e) xor (d and e));

        MOV     EAX,[ESP].RegC
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,[ESP].RegD
        MOV     EBP,[ESP].RegE
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  b:= t1 + t2;
//  f:= f + t1;

        ADD     [ESP].RegF,EBX
        ADD     EAX,EBX
        MOV     [ESP].RegB,EAX

//  W[7]:= Swap32(W[7]);

        MOV     ESI,[EDI].W7
        BSWAP   ESI
        MOV     [EDI].W7,ESI

//  t1:= a + (((f shr 6) or (f shl 26)) xor ((f shr 11) or (f shl 21)) xor
//      ((f shr 25) or (f shl 7))) + ((f and g) xor (not f and h)) + $ab1c5ed5 + W[7];

        MOV     EAX,[ESP].RegF
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,[ESP].RegG
        NOT     EAX
        AND     EAX,[ESP].RegH
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$ab1c5ed5
        ADD     EBX,[ESP].RegA

//  t2:= (((b shr 2) or (b shl 30)) xor ((b shr 13) or (b shl 19)) xor
//      ((b shr 22) xor (b shl 10))) + ((b and c) xor (b and d) xor (c and d));

        MOV     EAX,[ESP].RegB
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,[ESP].RegC
        MOV     EBP,[ESP].RegD
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  a:= t1 + t2;
//  e:= e + t1;

        ADD     [ESP].RegE,EBX
        ADD     EAX,EBX
        MOV     [ESP].RegA,EAX

//  W[8]:= Swap32(W[8]);

        MOV     ESI,[EDI].W8
        BSWAP   ESI
        MOV     [EDI].W8,ESI

//  t1:= h + (((e shr 6) or (e shl 26)) xor ((e shr 11) or (e shl 21)) xor
//      ((e shr 25) or (e shl 7))) + ((e and f) xor (not e and g)) + $d807aa98 + W[8];

        MOV     EAX,[ESP].RegE
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,[ESP].RegF
        NOT     EAX
        AND     EAX,[ESP].RegG
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$d807aa98
        ADD     EBX,[ESP].RegH

//  t2:= (((a shr 2) or (a shl 30)) xor ((a shr 13) or (a shl 19)) xor
//      ((a shr 22) xor (a shl 10))) + ((a and b) xor (a and c) xor (b and c));

        MOV     EAX,[ESP].RegA
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,[ESP].RegB
        MOV     EBP,[ESP].RegC
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  h:= t1 + t2;
//  d:= d + t1;

        ADD     [ESP].RegD,EBX
        ADD     EAX,EBX
        MOV     [ESP].RegH,EAX

//  W[9]:= Swap32(W[9]);

        MOV     ESI,[EDI].W9
        BSWAP   ESI
        MOV     [EDI].W9,ESI

//  t1:= g + (((d shr 6) or (d shl 26)) xor ((d shr 11) or (d shl 21)) xor
//      ((d shr 25) or (d shl 7))) + ((d and e) xor (not d and f)) + $12835b01 + W[9];

        MOV     EAX,[ESP].RegD
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,[ESP].RegE
        NOT     EAX
        AND     EAX,[ESP].RegF
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$12835b01
        ADD     EBX,[ESP].RegG

//  t2:= (((h shr 2) or (h shl 30)) xor ((h shr 13) or (h shl 19)) xor
//      ((h shr 22) xor (h shl 10))) + ((h and a) xor (h and b) xor (a and b));

        MOV     EAX,[ESP].RegH
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,[ESP].RegA
        MOV     EBP,[ESP].RegB
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  g:= t1 + t2;
//  c:= c + t1;

        ADD     [ESP].RegC,EBX
        ADD     EAX,EBX
        MOV     [ESP].RegG,EAX

//  W[10]:= Swap32(W[10]);

        MOV     ESI,[EDI].W10
        BSWAP   ESI
        MOV     [EDI].W10,ESI

//  t1:= f + (((c shr 6) or (c shl 26)) xor ((c shr 11) or (c shl 21)) xor
//      ((c shr 25) or (c shl 7))) + ((c and d) xor (not c and e)) + $243185be + W[10];

        MOV     EAX,[ESP].RegC
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,[ESP].RegD
        NOT     EAX
        AND     EAX,[ESP].RegE
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$243185be
        ADD     EBX,[ESP].RegF

//  t2:= (((g shr 2) or (g shl 30)) xor ((g shr 13) or (g shl 19)) xor
//      ((g shr 22) xor (g shl 10))) + ((g and h) xor (g and a) xor (h and a));

        MOV     EAX,[ESP].RegG
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,[ESP].RegH
        MOV     EBP,[ESP].RegA
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  f:= t1 + t2;
//  b:= b + t1;

        ADD     [ESP].RegB,EBX
        ADD     EAX,EBX
        MOV     [ESP].RegF,EAX

//  W[11]:= Swap32(W[11]);

        MOV     ESI,[EDI].W11
        BSWAP   ESI
        MOV     [EDI].W11,ESI

//  t1:= e + (((b shr 6) or (b shl 26)) xor ((b shr 11) or (b shl 21)) xor
//      ((b shr 25) or (b shl 7))) + ((b and c) xor (not b and d)) + $550c7dc3 + W[11];

        MOV     EAX,[ESP].RegB
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,[ESP].RegC
        NOT     EAX
        AND     EAX,[ESP].RegD
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$550c7dc3
        ADD     EBX,[ESP].RegE

//  t2:= (((f shr 2) or (f shl 30)) xor ((f shr 13) or (f shl 19)) xor
//      ((f shr 22) xor (f shl 10))) + ((f and g) xor (f and h) xor (g and h));

        MOV     EAX,[ESP].RegF
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,[ESP].RegG
        MOV     EBP,[ESP].RegH
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  e:= t1 + t2;
//  a:= a + t1;

        ADD     [ESP].RegA,EBX
        ADD     EAX,EBX
        MOV     [ESP].RegE,EAX

//  W[12]:= Swap32(W[12]);

        MOV     ESI,[EDI].W12
        BSWAP   ESI
        MOV     [EDI].W12,ESI

//  t1:= d + (((a shr 6) or (a shl 26)) xor ((a shr 11) or (a shl 21)) xor
//      ((a shr 25) or (a shl 7))) + ((a and b) xor (not a and c)) + $72be5d74 + W[12];

        MOV     EAX,[ESP].RegA
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,[ESP].RegB
        NOT     EAX
        AND     EAX,[ESP].RegC
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$72be5d74
        ADD     EBX,[ESP].RegD

//  t2:= (((e shr 2) or (e shl 30)) xor ((e shr 13) or (e shl 19)) xor
//      ((e shr 22) xor (e shl 10))) + ((e and f) xor (e and g) xor (f and g));

        MOV     EAX,[ESP].RegE
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,[ESP].RegF
        MOV     EBP,[ESP].RegG
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  d:= t1 + t2;
//  h:= h + t1;

        ADD     [ESP].RegH,EBX
        ADD     EAX,EBX
        MOV     [ESP].RegD,EAX

//  W[13]:= Swap32(W[13]);

        MOV     ESI,[EDI].W13
        BSWAP   ESI
        MOV     [EDI].W13,ESI

//  t1:= c + (((h shr 6) or (h shl 26)) xor ((h shr 11) or (h shl 21)) xor
//      ((h shr 25) or (h shl 7))) + ((h and a) xor (not h and b)) + $80deb1fe + W[13];

        MOV     EAX,[ESP].RegH
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,[ESP].RegA
        NOT     EAX
        AND     EAX,[ESP].RegB
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$80deb1fe
        ADD     EBX,[ESP].RegC

//  t2:= (((d shr 2) or (d shl 30)) xor ((d shr 13) or (d shl 19)) xor
//      ((d shr 22) xor (d shl 10))) + ((d and e) xor (d and f) xor (e and f));

        MOV     EAX,[ESP].RegD
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,[ESP].RegE
        MOV     EBP,[ESP].RegF
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  c:= t1 + t2;
//  g:= g + t1;

        ADD     [ESP].RegG,EBX
        ADD     EAX,EBX
        MOV     [ESP].RegC,EAX

//  W[14]:= Swap32(W[14]);

        MOV     ESI,[EDI].W14
        BSWAP   ESI
        MOV     [EDI].W14,ESI

//  t1:= b + (((g shr 6) or (g shl 26)) xor ((g shr 11) or (g shl 21)) xor
//      ((g shr 25) or (g shl 7))) + ((g and h) xor (not g and a)) + $9bdc06a7 + W[14];

        MOV     EAX,[ESP].RegG
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,[ESP].RegH
        NOT     EAX
        AND     EAX,[ESP].RegA
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$9bdc06a7
        ADD     EBX,[ESP].RegB

//  t2:= (((c shr 2) or (c shl 30)) xor ((c shr 13) or (c shl 19)) xor
//      ((c shr 22) xor (c shl 10))) + ((c and d) xor (c and e) xor (d and e));

        MOV     EAX,[ESP].RegC
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,[ESP].RegD
        MOV     EBP,[ESP].RegE
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  b:= t1 + t2;
//  f:= f + t1;

        ADD     [ESP].RegF,EBX
        ADD     EAX,EBX
        MOV     [ESP].RegB,EAX

//  W[15]:= Swap32(W[15]);

        MOV     ESI,[EDI].W15
        BSWAP   ESI
        MOV     [EDI].W15,ESI

//  t1:= a + (((f shr 6) or (f shl 26)) xor ((f shr 11) or (f shl 21)) xor
//      ((f shr 25) or (f shl 7))) + ((f and g) xor (not f and h)) + $c19bf174 + W[15];

        MOV     EAX,[ESP].RegF
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,[ESP].RegG
        NOT     EAX
        AND     EAX,[ESP].RegH
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$c19bf174
        ADD     EBX,[ESP].RegA

//  t2:= (((b shr 2) or (b shl 30)) xor ((b shr 13) or (b shl 19)) xor
//      ((b shr 22) xor (b shl 10))) + ((b and c) xor (b and d) xor (c and d));

        MOV     EAX,[ESP].RegB
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,[ESP].RegC
        MOV     EBP,[ESP].RegD
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  a:= t1 + t2;
//  e:= e + t1;

        ADD     [ESP].RegE,EBX
        ADD     EAX,EBX
        MOV     [ESP].RegA,EAX

//  W[0]:= (((W[14] shr 17) or (W[14] shl 15)) xor
//          ((W[14] shr 19) or (W[14] shl 13)) xor (W[14] shr 10)) + W[9] +
//         (((W[1] shr 7) or (W[1] shl 25)) xor
//          ((W[1] shr 18) or (W[1] shl 14)) xor (W[1] shr 3)) + W[0];

        MOV     ESI,[EDI].W14
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[EDI].W1
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[EDI].W9
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[EDI].W0
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [EDI].W0,ESI

//  t1:= h + (((e shr 6) or (e shl 26)) xor ((e shr 11) or (e shl 21)) xor
//      ((e shr 25) or (e shl 7))) + ((e and f) xor (not e and g)) + $e49b69c1 + W[0];

        MOV     EAX,[ESP].RegE
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,[ESP].RegF
        NOT     EAX
        AND     EAX,[ESP].RegG
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$e49b69c1
        ADD     EBX,[ESP].RegH

//  t2:= (((a shr 2) or (a shl 30)) xor ((a shr 13) or (a shl 19)) xor
//      ((a shr 22) xor (a shl 10))) + ((a and b) xor (a and c) xor (b and c));

        MOV     EAX,[ESP].RegA
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,[ESP].RegB
        MOV     EBP,[ESP].RegC
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  h:= t1 + t2;
//  d:= d + t1;

        ADD     [ESP].RegD,EBX
        ADD     EAX,EBX
        MOV     [ESP].RegH,EAX

//  W[1]:= (((W[15] shr 17) or (W[15] shl 15)) xor
//          ((W[15] shr 19) or (W[15] shl 13)) xor (W[15] shr 10)) + W[10] +
//         (((W[2] shr 7) or (W[2] shl 25)) xor
//          ((W[2] shr 18) or (W[2] shl 14)) xor (W[2] shr 3)) + W[1];

        MOV     ESI,[EDI].W15
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[EDI].W2
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[EDI].W10
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[EDI].W1
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [EDI].W1,ESI

//  t1:= g + (((d shr 6) or (d shl 26)) xor ((d shr 11) or (d shl 21)) xor
//      ((d shr 25) or (d shl 7))) + ((d and e) xor (not d and f)) + $efbe4786 + W[1];

        MOV     EAX,[ESP].RegD
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,[ESP].RegE
        NOT     EAX
        AND     EAX,[ESP].RegF
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$efbe4786
        ADD     EBX,[ESP].RegG

//  t2:= (((h shr 2) or (h shl 30)) xor ((h shr 13) or (h shl 19)) xor
//      ((h shr 22) xor (h shl 10))) + ((h and a) xor (h and b) xor (a and b));

        MOV     EAX,[ESP].RegH
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,[ESP].RegA
        MOV     EBP,[ESP].RegB
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  g:= t1 + t2;
//  c:= c + t1;

        ADD     [ESP].RegC,EBX
        ADD     EAX,EBX
        MOV     [ESP].RegG,EAX

//  W[2]:= (((W[0] shr 17) or (W[0] shl 15)) xor
//          ((W[0] shr 19) or (W[0] shl 13)) xor (W[0] shr 10)) + W[11] +
//         (((W[3] shr 7) or (W[3] shl 25)) xor
//          ((W[3] shr 18) or (W[3] shl 14)) xor (W[3] shr 3)) + W[2];

        MOV     ESI,[EDI].W0
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[EDI].W3
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[EDI].W11
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[EDI].W2
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [EDI].W2,ESI

//  t1:= f + (((c shr 6) or (c shl 26)) xor ((c shr 11) or (c shl 21)) xor
//      ((c shr 25) or (c shl 7))) + ((c and d) xor (not c and e)) + $0fc19dc6 + W[2];

        MOV     EAX,[ESP].RegC
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,[ESP].RegD
        NOT     EAX
        AND     EAX,[ESP].RegE
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$0fc19dc6
        ADD     EBX,[ESP].RegF

//  t2:= (((g shr 2) or (g shl 30)) xor ((g shr 13) or (g shl 19)) xor
//      ((g shr 22) xor (g shl 10))) + ((g and h) xor (g and a) xor (h and a));

        MOV     EAX,[ESP].RegG
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,[ESP].RegH
        MOV     EBP,[ESP].RegA
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  f:= t1 + t2;
//  b:= b + t1;

        ADD     [ESP].RegB,EBX
        ADD     EAX,EBX
        MOV     [ESP].RegF,EAX

//  W[3]:= (((W[1] shr 17) or (W[1] shl 15)) xor
//          ((W[1] shr 19) or (W[1] shl 13)) xor (W[1] shr 10)) + W[12] +
//         (((W[4] shr 7) or (W[4] shl 25)) xor
//          ((W[4] shr 18) or (W[4] shl 14)) xor (W[4] shr 3)) + W[3];

        MOV     ESI,[EDI].W1
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[EDI].W4
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[EDI].W12
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[EDI].W3
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [EDI].W3,ESI

//  t1:= e + (((b shr 6) or (b shl 26)) xor ((b shr 11) or (b shl 21)) xor
//      ((b shr 25) or (b shl 7))) + ((b and c) xor (not b and d)) + $240ca1cc + W[3];

        MOV     EAX,[ESP].RegB
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,[ESP].RegC
        NOT     EAX
        AND     EAX,[ESP].RegD
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$240ca1cc
        ADD     EBX,[ESP].RegE

//  t2:= (((f shr 2) or (f shl 30)) xor ((f shr 13) or (f shl 19)) xor
//      ((f shr 22) xor (f shl 10))) + ((f and g) xor (f and h) xor (g and h));

        MOV     EAX,[ESP].RegF
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,[ESP].RegG
        MOV     EBP,[ESP].RegH
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  e:= t1 + t2;
//  a:= a + t1;

        ADD     [ESP].RegA,EBX
        ADD     EAX,EBX
        MOV     [ESP].RegE,EAX

//  W[4]:= (((W[2] shr 17) or (W[2] shl 15)) xor
//          ((W[2] shr 19) or (W[2] shl 13)) xor (W[2] shr 10)) + W[13] +
//         (((W[5] shr 7) or (W[5] shl 25)) xor
//          ((W[5] shr 18) or (W[5] shl 14)) xor (W[5] shr 3)) + W[4];

        MOV     ESI,[EDI].W2
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[EDI].W5
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[EDI].W13
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[EDI].W4
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [EDI].W4,ESI

//  t1:= d + (((a shr 6) or (a shl 26)) xor ((a shr 11) or (a shl 21)) xor
//      ((a shr 25) or (a shl 7))) + ((a and b) xor (not a and c)) + $2de92c6f + W[4];

        MOV     EAX,[ESP].RegA
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,[ESP].RegB
        NOT     EAX
        AND     EAX,[ESP].RegC
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$2de92c6f
        ADD     EBX,[ESP].RegD

//  t2:= (((e shr 2) or (e shl 30)) xor ((e shr 13) or (e shl 19)) xor
//      ((e shr 22) xor (e shl 10))) + ((e and f) xor (e and g) xor (f and g));

        MOV     EAX,[ESP].RegE
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,[ESP].RegF
        MOV     EBP,[ESP].RegG
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  d:= t1 + t2;
//  h:= h + t1;

        ADD     [ESP].RegH,EBX
        ADD     EAX,EBX
        MOV     [ESP].RegD,EAX

//  W[5]:= (((W[3] shr 17) or (W[3] shl 15)) xor
//          ((W[3] shr 19) or (W[3] shl 13)) xor (W[3] shr 10)) + W[14] +
//         (((W[6] shr 7) or (W[6] shl 25)) xor
//          ((W[6] shr 18) or (W[6] shl 14)) xor (W[6] shr 3)) + W[5];

        MOV     ESI,[EDI].W3
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[EDI].W6
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[EDI].W14
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[EDI].W5
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [EDI].W5,ESI

//  t1:= c + (((h shr 6) or (h shl 26)) xor ((h shr 11) or (h shl 21)) xor
//      ((h shr 25) or (h shl 7))) + ((h and a) xor (not h and b)) + $4a7484aa + W[5];

        MOV     EAX,[ESP].RegH
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,[ESP].RegA
        NOT     EAX
        AND     EAX,[ESP].RegB
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$4a7484aa
        ADD     EBX,[ESP].RegC

//  t2:= (((d shr 2) or (d shl 30)) xor ((d shr 13) or (d shl 19)) xor
//      ((d shr 22) xor (d shl 10))) + ((d and e) xor (d and f) xor (e and f));

        MOV     EAX,[ESP].RegD
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,[ESP].RegE
        MOV     EBP,[ESP].RegF
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  c:= t1 + t2;
//  g:= g + t1;

        ADD     [ESP].RegG,EBX
        ADD     EAX,EBX
        MOV     [ESP].RegC,EAX

//  W[6]:= (((W[4] shr 17) or (W[4] shl 15)) xor
//          ((W[4] shr 19) or (W[4] shl 13)) xor (W[4] shr 10)) + W[15] +
//         (((W[7] shr 7) or (W[7] shl 25)) xor
//          ((W[7] shr 18) or (W[7] shl 14)) xor (W[7] shr 3)) + W[6];

        MOV     ESI,[EDI].W4
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[EDI].W7
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[EDI].W15
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[EDI].W6
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [EDI].W6,ESI

//  t1:= b + (((g shr 6) or (g shl 26)) xor ((g shr 11) or (g shl 21)) xor
//      ((g shr 25) or (g shl 7))) + ((g and h) xor (not g and a)) + $5cb0a9dc + W[6];

        MOV     EAX,[ESP].RegG
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,[ESP].RegH
        NOT     EAX
        AND     EAX,[ESP].RegA
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$5cb0a9dc
        ADD     EBX,[ESP].RegB

//  t2:= (((c shr 2) or (c shl 30)) xor ((c shr 13) or (c shl 19)) xor
//      ((c shr 22) xor (c shl 10))) + ((c and d) xor (c and e) xor (d and e));

        MOV     EAX,[ESP].RegC
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,[ESP].RegD
        MOV     EBP,[ESP].RegE
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  b:= t1 + t2;
//  f:= f + t1;

        ADD     [ESP].RegF,EBX
        ADD     EAX,EBX
        MOV     [ESP].RegB,EAX

//  W[7]:= (((W[5] shr 17) or (W[5] shl 15)) xor
//          ((W[5] shr 19) or (W[5] shl 13)) xor (W[5] shr 10)) + W[0] +
//         (((W[8] shr 7) or (W[8] shl 25)) xor
//          ((W[8] shr 18) or (W[8] shl 14)) xor (W[8] shr 3)) + W[7];

        MOV     ESI,[EDI].W5
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[EDI].W8
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[EDI].W0
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[EDI].W7
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [EDI].W7,ESI

//  t1:= a + (((f shr 6) or (f shl 26)) xor ((f shr 11) or (f shl 21)) xor
//      ((f shr 25) or (f shl 7))) + ((f and g) xor (not f and h)) + $76f988da + W[7];

        MOV     EAX,[ESP].RegF
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,[ESP].RegG
        NOT     EAX
        AND     EAX,[ESP].RegH
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$76f988da
        ADD     EBX,[ESP].RegA

//  t2:= (((b shr 2) or (b shl 30)) xor ((b shr 13) or (b shl 19)) xor
//      ((b shr 22) xor (b shl 10))) + ((b and c) xor (b and d) xor (c and d));

        MOV     EAX,[ESP].RegB
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,[ESP].RegC
        MOV     EBP,[ESP].RegD
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  a:= t1 + t2;
//  e:= e + t1;

        ADD     [ESP].RegE,EBX
        ADD     EAX,EBX
        MOV     [ESP].RegA,EAX

//  W[8]:= (((W[6] shr 17) or (W[6] shl 15)) xor
//          ((W[6] shr 19) or (W[6] shl 13)) xor (W[6] shr 10)) + W[1] +
//         (((W[9] shr 7) or (W[9] shl 25)) xor
//          ((W[9] shr 18) or (W[9] shl 14)) xor (W[9] shr 3)) + W[8];

        MOV     ESI,[EDI].W6
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[EDI].W9
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[EDI].W1
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[EDI].W8
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [EDI].W8,ESI

//  t1:= h + (((e shr 6) or (e shl 26)) xor ((e shr 11) or (e shl 21)) xor
//      ((e shr 25) or (e shl 7))) + ((e and f) xor (not e and g)) + $983e5152 + W[8];

        MOV     EAX,[ESP].RegE
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,[ESP].RegF
        NOT     EAX
        AND     EAX,[ESP].RegG
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$983e5152
        ADD     EBX,[ESP].RegH

//  t2:= (((a shr 2) or (a shl 30)) xor ((a shr 13) or (a shl 19)) xor
//      ((a shr 22) xor (a shl 10))) + ((a and b) xor (a and c) xor (b and c));

        MOV     EAX,[ESP].RegA
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,[ESP].RegB
        MOV     EBP,[ESP].RegC
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  h:= t1 + t2;
//  d:= d + t1;

        ADD     [ESP].RegD,EBX
        ADD     EAX,EBX
        MOV     [ESP].RegH,EAX

//  W[9]:= (((W[7] shr 17) or (W[7] shl 15)) xor
//          ((W[7] shr 19) or (W[7] shl 13)) xor (W[7] shr 10)) + W[2] +
//         (((W[10] shr 7) or (W[10] shl 25)) xor
//          ((W[10] shr 18) or (W[10] shl 14)) xor (W[10] shr 3)) + W[9];

        MOV     ESI,[EDI].W7
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[EDI].W10
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[EDI].W2
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[EDI].W9
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [EDI].W9,ESI

//  t1:= g + (((d shr 6) or (d shl 26)) xor ((d shr 11) or (d shl 21)) xor
//      ((d shr 25) or (d shl 7))) + ((d and e) xor (not d and f)) + $a831c66d + W[9];

        MOV     EAX,[ESP].RegD
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,[ESP].RegE
        NOT     EAX
        AND     EAX,[ESP].RegF
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$a831c66d
        ADD     EBX,[ESP].RegG

//  t2:= (((h shr 2) or (h shl 30)) xor ((h shr 13) or (h shl 19)) xor
//      ((h shr 22) xor (h shl 10))) + ((h and a) xor (h and b) xor (a and b));

        MOV     EAX,[ESP].RegH
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,[ESP].RegA
        MOV     EBP,[ESP].RegB
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  g:= t1 + t2;
//  c:= c + t1;

        ADD     [ESP].RegC,EBX
        ADD     EAX,EBX
        MOV     [ESP].RegG,EAX

//  W[10]:= (((W[8] shr 17) or (W[8] shl 15)) xor
//           ((W[8] shr 19) or (W[8] shl 13)) xor (W[8] shr 10)) + W[3] +
//          (((W[11] shr 7) or (W[11] shl 25)) xor
//           ((W[11] shr 18) or (W[11] shl 14)) xor (W[11] shr 3)) + W[10];

        MOV     ESI,[EDI].W8
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[EDI].W11
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[EDI].W3
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[EDI].W10
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [EDI].W10,ESI

//  t1:= f + (((c shr 6) or (c shl 26)) xor ((c shr 11) or (c shl 21)) xor
//      ((c shr 25) or (c shl 7))) + ((c and d) xor (not c and e)) + $b00327c8 + W[10];

        MOV     EAX,[ESP].RegC
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,[ESP].RegD
        NOT     EAX
        AND     EAX,[ESP].RegE
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$b00327c8
        ADD     EBX,[ESP].RegF

//  t2:= (((g shr 2) or (g shl 30)) xor ((g shr 13) or (g shl 19)) xor
//      ((g shr 22) xor (g shl 10))) + ((g and h) xor (g and a) xor (h and a));

        MOV     EAX,[ESP].RegG
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,[ESP].RegH
        MOV     EBP,[ESP].RegA
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  f:= t1 + t2;
//  b:= b + t1;

        ADD     [ESP].RegB,EBX
        ADD     EAX,EBX
        MOV     [ESP].RegF,EAX

//  W[11]:= (((W[9] shr 17) or (W[9] shl 15)) xor
//           ((W[9] shr 19) or (W[9] shl 13)) xor (W[9] shr 10)) + W[4] +
//          (((W[12] shr 7) or (W[12] shl 25)) xor
//           ((W[12] shr 18) or (W[12] shl 14)) xor (W[12] shr 3)) + W[11];

        MOV     ESI,[EDI].W9
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[EDI].W12
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[EDI].W4
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[EDI].W11
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [EDI].W11,ESI

//  t1:= e + (((b shr 6) or (b shl 26)) xor ((b shr 11) or (b shl 21)) xor
//      ((b shr 25) or (b shl 7))) + ((b and c) xor (not b and d)) + $bf597fc7 + W[11];

        MOV     EAX,[ESP].RegB
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,[ESP].RegC
        NOT     EAX
        AND     EAX,[ESP].RegD
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$bf597fc7
        ADD     EBX,[ESP].RegE

//  t2:= (((f shr 2) or (f shl 30)) xor ((f shr 13) or (f shl 19)) xor
//      ((f shr 22) xor (f shl 10))) + ((f and g) xor (f and h) xor (g and h));

        MOV     EAX,[ESP].RegF
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,[ESP].RegG
        MOV     EBP,[ESP].RegH
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  e:= t1 + t2;
//  a:= a + t1;

        ADD     [ESP].RegA,EBX
        ADD     EAX,EBX
        MOV     [ESP].RegE,EAX

//  W[12]:= (((W[10] shr 17) or (W[10] shl 15)) xor
//           ((W[10] shr 19) or (W[10] shl 13)) xor (W[10] shr 10)) + W[5] +
//          (((W[13] shr 7) or (W[13] shl 25)) xor
//           ((W[13] shr 18) or (W[13] shl 14)) xor (W[13] shr 3)) + W[12];

        MOV     ESI,[EDI].W10
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[EDI].W13
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[EDI].W5
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[EDI].W12
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [EDI].W12,ESI

//  t1:= d + (((a shr 6) or (a shl 26)) xor ((a shr 11) or (a shl 21)) xor
//      ((a shr 25) or (a shl 7))) + ((a and b) xor (not a and c)) + $c6e00bf3 + W[12];

        MOV     EAX,[ESP].RegA
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,[ESP].RegB
        NOT     EAX
        AND     EAX,[ESP].RegC
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$c6e00bf3
        ADD     EBX,[ESP].RegD

//  t2:= (((e shr 2) or (e shl 30)) xor ((e shr 13) or (e shl 19)) xor
//      ((e shr 22) xor (e shl 10))) + ((e and f) xor (e and g) xor (f and g));

        MOV     EAX,[ESP].RegE
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,[ESP].RegF
        MOV     EBP,[ESP].RegG
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  d:= t1 + t2;
//  h:= h + t1;

        ADD     [ESP].RegH,EBX
        ADD     EAX,EBX
        MOV     [ESP].RegD,EAX

//  W[13]:= (((W[11] shr 17) or (W[11] shl 15)) xor
//           ((W[11] shr 19) or (W[11] shl 13)) xor (W[11] shr 10)) + W[6] +
//          (((W[14] shr 7) or (W[14] shl 25)) xor
//           ((W[14] shr 18) or (W[14] shl 14)) xor (W[14] shr 3)) + W[13];

        MOV     ESI,[EDI].W11
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[EDI].W14
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[EDI].W6
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[EDI].W13
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [EDI].W13,ESI

//  t1:= c + (((h shr 6) or (h shl 26)) xor ((h shr 11) or (h shl 21)) xor
//      ((h shr 25) or (h shl 7))) + ((h and a) xor (not h and b)) + $d5a79147 + W[13];

        MOV     EAX,[ESP].RegH
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,[ESP].RegA
        NOT     EAX
        AND     EAX,[ESP].RegB
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$d5a79147
        ADD     EBX,[ESP].RegC

//  t2:= (((d shr 2) or (d shl 30)) xor ((d shr 13) or (d shl 19)) xor
//      ((d shr 22) xor (d shl 10))) + ((d and e) xor (d and f) xor (e and f));

        MOV     EAX,[ESP].RegD
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,[ESP].RegE
        MOV     EBP,[ESP].RegF
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  c:= t1 + t2;
//  g:= g + t1;

        ADD     [ESP].RegG,EBX
        ADD     EAX,EBX
        MOV     [ESP].RegC,EAX

//  W[14]:= (((W[12] shr 17) or (W[12] shl 15)) xor
//           ((W[12] shr 19) or (W[12] shl 13)) xor (W[12] shr 10)) + W[7] +
//          (((W[15] shr 7) or (W[15] shl 25)) xor
//           ((W[15] shr 18) or (W[15] shl 14)) xor (W[15] shr 3)) + W[14];

        MOV     ESI,[EDI].W12
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[EDI].W15
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[EDI].W7
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[EDI].W14
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [EDI].W14,ESI

//  t1:= b + (((g shr 6) or (g shl 26)) xor ((g shr 11) or (g shl 21)) xor
//      ((g shr 25) or (g shl 7))) + ((g and h) xor (not g and a)) + $06ca6351 + W[14];

        MOV     EAX,[ESP].RegG
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,[ESP].RegH
        NOT     EAX
        AND     EAX,[ESP].RegA
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$06ca6351
        ADD     EBX,[ESP].RegB

//  t2:= (((c shr 2) or (c shl 30)) xor ((c shr 13) or (c shl 19)) xor
//      ((c shr 22) xor (c shl 10))) + ((c and d) xor (c and e) xor (d and e));

        MOV     EAX,[ESP].RegC
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,[ESP].RegD
        MOV     EBP,[ESP].RegE
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  b:= t1 + t2;
//  f:= f + t1;

        ADD     [ESP].RegF,EBX
        ADD     EAX,EBX
        MOV     [ESP].RegB,EAX

//  W[15]:= (((W[13] shr 17) or (W[13] shl 15)) xor
//           ((W[13] shr 19) or (W[13] shl 13)) xor (W[13] shr 10)) + W[8] +
//          (((W[0] shr 7) or (W[0] shl 25)) xor
//           ((W[0] shr 18) or (W[0] shl 14)) xor (W[0] shr 3)) + W[15];

        MOV     ESI,[EDI].W13
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[EDI].W0
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[EDI].W8
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[EDI].W15
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [EDI].W15,ESI

//  t1:= a + (((f shr 6) or (f shl 26)) xor ((f shr 11) or (f shl 21)) xor
//      ((f shr 25) or (f shl 7))) + ((f and g) xor (not f and h)) + $14292967 + W[15];

        MOV     EAX,[ESP].RegF
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,[ESP].RegG
        NOT     EAX
        AND     EAX,[ESP].RegH
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$14292967
        ADD     EBX,[ESP].RegA

//  t2:= (((b shr 2) or (b shl 30)) xor ((b shr 13) or (b shl 19)) xor
//      ((b shr 22) xor (b shl 10))) + ((b and c) xor (b and d) xor (c and d));

        MOV     EAX,[ESP].RegB
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,[ESP].RegC
        MOV     EBP,[ESP].RegD
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  a:= t1 + t2;
//  e:= e + t1;

        ADD     [ESP].RegE,EBX
        ADD     EAX,EBX
        MOV     [ESP].RegA,EAX

//  W[0]:= (((W[14] shr 17) or (W[14] shl 15)) xor
//          ((W[14] shr 19) or (W[14] shl 13)) xor (W[14] shr 10)) + W[9] +
//         (((W[1] shr 7) or (W[1] shl 25)) xor
//          ((W[1] shr 18) or (W[1] shl 14)) xor (W[1] shr 3)) + W[0];

        MOV     ESI,[EDI].W14
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[EDI].W1
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[EDI].W9
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[EDI].W0
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [EDI].W0,ESI

//  t1:= h + (((e shr 6) or (e shl 26)) xor ((e shr 11) or (e shl 21)) xor
//      ((e shr 25) or (e shl 7))) + ((e and f) xor (not e and g)) + $27b70a85 + W[0];

        MOV     EAX,[ESP].RegE
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,[ESP].RegF
        NOT     EAX
        AND     EAX,[ESP].RegG
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$27b70a85
        ADD     EBX,[ESP].RegH

//  t2:= (((a shr 2) or (a shl 30)) xor ((a shr 13) or (a shl 19)) xor
//      ((a shr 22) xor (a shl 10))) + ((a and b) xor (a and c) xor (b and c));

        MOV     EAX,[ESP].RegA
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,[ESP].RegB
        MOV     EBP,[ESP].RegC
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  h:= t1 + t2;
//  d:= d + t1;

        ADD     [ESP].RegD,EBX
        ADD     EAX,EBX
        MOV     [ESP].RegH,EAX

//  W[1]:= (((W[15] shr 17) or (W[15] shl 15)) xor
//          ((W[15] shr 19) or (W[15] shl 13)) xor (W[15] shr 10)) + W[10] +
//         (((W[2] shr 7) or (W[2] shl 25)) xor
//          ((W[2] shr 18) or (W[2] shl 14)) xor (W[2] shr 3)) + W[1];

        MOV     ESI,[EDI].W15
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[EDI].W2
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[EDI].W10
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[EDI].W1
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [EDI].W1,ESI

//  t1:= g + (((d shr 6) or (d shl 26)) xor ((d shr 11) or (d shl 21)) xor
//      ((d shr 25) or (d shl 7))) + ((d and e) xor (not d and f)) + $2e1b2138 + W[1];

        MOV     EAX,[ESP].RegD
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,[ESP].RegE
        NOT     EAX
        AND     EAX,[ESP].RegF
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$2e1b2138
        ADD     EBX,[ESP].RegG

//  t2:= (((h shr 2) or (h shl 30)) xor ((h shr 13) or (h shl 19)) xor
//      ((h shr 22) xor (h shl 10))) + ((h and a) xor (h and b) xor (a and b));

        MOV     EAX,[ESP].RegH
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,[ESP].RegA
        MOV     EBP,[ESP].RegB
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  g:= t1 + t2;
//  c:= c + t1;

        ADD     [ESP].RegC,EBX
        ADD     EAX,EBX
        MOV     [ESP].RegG,EAX

//  W[2]:= (((W[0] shr 17) or (W[0] shl 15)) xor
//          ((W[0] shr 19) or (W[0] shl 13)) xor (W[0] shr 10)) + W[11] +
//         (((W[3] shr 7) or (W[3] shl 25)) xor
//          ((W[3] shr 18) or (W[3] shl 14)) xor (W[3] shr 3)) + W[2];

        MOV     ESI,[EDI].W0
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[EDI].W3
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[EDI].W11
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[EDI].W2
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [EDI].W2,ESI

//  t1:= f + (((c shr 6) or (c shl 26)) xor ((c shr 11) or (c shl 21)) xor
//      ((c shr 25) or (c shl 7))) + ((c and d) xor (not c and e)) + $4d2c6dfc + W[2];

        MOV     EAX,[ESP].RegC
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,[ESP].RegD
        NOT     EAX
        AND     EAX,[ESP].RegE
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$4d2c6dfc
        ADD     EBX,[ESP].RegF

//  t2:= (((g shr 2) or (g shl 30)) xor ((g shr 13) or (g shl 19)) xor
//      ((g shr 22) xor (g shl 10))) + ((g and h) xor (g and a) xor (h and a));

        MOV     EAX,[ESP].RegG
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,[ESP].RegH
        MOV     EBP,[ESP].RegA
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  f:= t1 + t2;
//  b:= b + t1;

        ADD     [ESP].RegB,EBX
        ADD     EAX,EBX
        MOV     [ESP].RegF,EAX

//  W[3]:= (((W[1] shr 17) or (W[1] shl 15)) xor
//          ((W[1] shr 19) or (W[1] shl 13)) xor (W[1] shr 10)) + W[12] +
//         (((W[4] shr 7) or (W[4] shl 25)) xor
//          ((W[4] shr 18) or (W[4] shl 14)) xor (W[4] shr 3)) + W[3];

        MOV     ESI,[EDI].W1
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[EDI].W4
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[EDI].W12
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[EDI].W3
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [EDI].W3,ESI

//  t1:= e + (((b shr 6) or (b shl 26)) xor ((b shr 11) or (b shl 21)) xor
//      ((b shr 25) or (b shl 7))) + ((b and c) xor (not b and d)) + $53380d13 + W[3];

        MOV     EAX,[ESP].RegB
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,[ESP].RegC
        NOT     EAX
        AND     EAX,[ESP].RegD
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$53380d13
        ADD     EBX,[ESP].RegE

//  t2:= (((f shr 2) or (f shl 30)) xor ((f shr 13) or (f shl 19)) xor
//      ((f shr 22) xor (f shl 10))) + ((f and g) xor (f and h) xor (g and h));

        MOV     EAX,[ESP].RegF
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,[ESP].RegG
        MOV     EBP,[ESP].RegH
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  e:= t1 + t2;
//  a:= a + t1;

        ADD     [ESP].RegA,EBX
        ADD     EAX,EBX
        MOV     [ESP].RegE,EAX

//  W[4]:= (((W[2] shr 17) or (W[2] shl 15)) xor
//          ((W[2] shr 19) or (W[2] shl 13)) xor (W[2] shr 10)) + W[13] +
//         (((W[5] shr 7) or (W[5] shl 25)) xor
//          ((W[5] shr 18) or (W[5] shl 14)) xor (W[5] shr 3)) + W[4];

        MOV     ESI,[EDI].W2
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[EDI].W5
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[EDI].W13
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[EDI].W4
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [EDI].W4,ESI

//  t1:= d + (((a shr 6) or (a shl 26)) xor ((a shr 11) or (a shl 21)) xor
//      ((a shr 25) or (a shl 7))) + ((a and b) xor (not a and c)) + $650a7354 + W[4];

        MOV     EAX,[ESP].RegA
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,[ESP].RegB
        NOT     EAX
        AND     EAX,[ESP].RegC
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$650a7354
        ADD     EBX,[ESP].RegD

//  t2:= (((e shr 2) or (e shl 30)) xor ((e shr 13) or (e shl 19)) xor
//      ((e shr 22) xor (e shl 10))) + ((e and f) xor (e and g) xor (f and g));

        MOV     EAX,[ESP].RegE
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,[ESP].RegF
        MOV     EBP,[ESP].RegG
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  d:= t1 + t2;
//  h:= h + t1;

        ADD     [ESP].RegH,EBX
        ADD     EAX,EBX
        MOV     [ESP].RegD,EAX

//  W[5]:= (((W[3] shr 17) or (W[3] shl 15)) xor
//          ((W[3] shr 19) or (W[3] shl 13)) xor (W[3] shr 10)) + W[14] +
//         (((W[6] shr 7) or (W[6] shl 25)) xor
//          ((W[6] shr 18) or (W[6] shl 14)) xor (W[6] shr 3)) + W[5];

        MOV     ESI,[EDI].W3
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[EDI].W6
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[EDI].W14
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[EDI].W5
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [EDI].W5,ESI

//  t1:= c + (((h shr 6) or (h shl 26)) xor ((h shr 11) or (h shl 21)) xor
//      ((h shr 25) or (h shl 7))) + ((h and a) xor (not h and b)) + $766a0abb + W[5];

        MOV     EAX,[ESP].RegH
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,[ESP].RegA
        NOT     EAX
        AND     EAX,[ESP].RegB
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$766a0abb
        ADD     EBX,[ESP].RegC

//  t2:= (((d shr 2) or (d shl 30)) xor ((d shr 13) or (d shl 19)) xor
//      ((d shr 22) xor (d shl 10))) + ((d and e) xor (d and f) xor (e and f));

        MOV     EAX,[ESP].RegD
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,[ESP].RegE
        MOV     EBP,[ESP].RegF
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  c:= t1 + t2;
//  g:= g + t1;

        ADD     [ESP].RegG,EBX
        ADD     EAX,EBX
        MOV     [ESP].RegC,EAX

//  W[6]:= (((W[4] shr 17) or (W[4] shl 15)) xor
//          ((W[4] shr 19) or (W[4] shl 13)) xor (W[4] shr 10)) + W[15] +
//         (((W[7] shr 7) or (W[7] shl 25)) xor
//          ((W[7] shr 18) or (W[7] shl 14)) xor (W[7] shr 3)) + W[6];

        MOV     ESI,[EDI].W4
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[EDI].W7
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[EDI].W15
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[EDI].W6
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [EDI].W6,ESI

//  t1:= b + (((g shr 6) or (g shl 26)) xor ((g shr 11) or (g shl 21)) xor
//      ((g shr 25) or (g shl 7))) + ((g and h) xor (not g and a)) + $81c2c92e + W[6];

        MOV     EAX,[ESP].RegG
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,[ESP].RegH
        NOT     EAX
        AND     EAX,[ESP].RegA
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$81c2c92e
        ADD     EBX,[ESP].RegB

//  t2:= (((c shr 2) or (c shl 30)) xor ((c shr 13) or (c shl 19)) xor
//      ((c shr 22) xor (c shl 10))) + ((c and d) xor (c and e) xor (d and e));

        MOV     EAX,[ESP].RegC
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,[ESP].RegD
        MOV     EBP,[ESP].RegE
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  b:= t1 + t2;
//  f:= f + t1;

        ADD     [ESP].RegF,EBX
        ADD     EAX,EBX
        MOV     [ESP].RegB,EAX

//  W[7]:= (((W[5] shr 17) or (W[5] shl 15)) xor
//          ((W[5] shr 19) or (W[5] shl 13)) xor (W[5] shr 10)) + W[0] +
//         (((W[8] shr 7) or (W[8] shl 25)) xor
//          ((W[8] shr 18) or (W[8] shl 14)) xor (W[8] shr 3)) + W[7];

        MOV     ESI,[EDI].W5
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[EDI].W8
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[EDI].W0
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[EDI].W7
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [EDI].W7,ESI

//  t1:= a + (((f shr 6) or (f shl 26)) xor ((f shr 11) or (f shl 21)) xor
//      ((f shr 25) or (f shl 7))) + ((f and g) xor (not f and h)) + $92722c85 + W[7];

        MOV     EAX,[ESP].RegF
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,[ESP].RegG
        NOT     EAX
        AND     EAX,[ESP].RegH
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$92722c85
        ADD     EBX,[ESP].RegA

//  t2:= (((b shr 2) or (b shl 30)) xor ((b shr 13) or (b shl 19)) xor
//      ((b shr 22) xor (b shl 10))) + ((b and c) xor (b and d) xor (c and d));

        MOV     EAX,[ESP].RegB
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,[ESP].RegC
        MOV     EBP,[ESP].RegD
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  a:= t1 + t2;
//  e:= e + t1;

        ADD     [ESP].RegE,EBX
        ADD     EAX,EBX
        MOV     [ESP].RegA,EAX

//  W[8]:= (((W[6] shr 17) or (W[6] shl 15)) xor
//          ((W[6] shr 19) or (W[6] shl 13)) xor (W[6] shr 10)) + W[1] +
//         (((W[9] shr 7) or (W[9] shl 25)) xor
//          ((W[9] shr 18) or (W[9] shl 14)) xor (W[9] shr 3)) + W[8];

        MOV     ESI,[EDI].W6
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[EDI].W9
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[EDI].W1
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[EDI].W8
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [EDI].W8,ESI

//  t1:= h + (((e shr 6) or (e shl 26)) xor ((e shr 11) or (e shl 21)) xor
//      ((e shr 25) or (e shl 7))) + ((e and f) xor (not e and g)) + $a2bfe8a1 + W[8];

        MOV     EAX,[ESP].RegE
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,[ESP].RegF
        NOT     EAX
        AND     EAX,[ESP].RegG
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$a2bfe8a1
        ADD     EBX,[ESP].RegH

//  t2:= (((a shr 2) or (a shl 30)) xor ((a shr 13) or (a shl 19)) xor
//      ((a shr 22) xor (a shl 10))) + ((a and b) xor (a and c) xor (b and c));

        MOV     EAX,[ESP].RegA
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,[ESP].RegB
        MOV     EBP,[ESP].RegC
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  h:= t1 + t2;
//  d:= d + t1;

        ADD     [ESP].RegD,EBX
        ADD     EAX,EBX
        MOV     [ESP].RegH,EAX

//  W[9]:= (((W[7] shr 17) or (W[7] shl 15)) xor
//          ((W[7] shr 19) or (W[7] shl 13)) xor (W[7] shr 10)) + W[2] +
//         (((W[10] shr 7) or (W[10] shl 25)) xor
//          ((W[10] shr 18) or (W[10] shl 14)) xor (W[10] shr 3)) + W[9];

        MOV     ESI,[EDI].W7
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[EDI].W10
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[EDI].W2
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[EDI].W9
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [EDI].W9,ESI

//  t1:= g + (((d shr 6) or (d shl 26)) xor ((d shr 11) or (d shl 21)) xor
//      ((d shr 25) or (d shl 7))) + ((d and e) xor (not d and f)) + $a81a664b + W[9];

        MOV     EAX,[ESP].RegD
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,[ESP].RegE
        NOT     EAX
        AND     EAX,[ESP].RegF
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$a81a664b
        ADD     EBX,[ESP].RegG

//  t2:= (((h shr 2) or (h shl 30)) xor ((h shr 13) or (h shl 19)) xor
//      ((h shr 22) xor (h shl 10))) + ((h and a) xor (h and b) xor (a and b));

        MOV     EAX,[ESP].RegH
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,[ESP].RegA
        MOV     EBP,[ESP].RegB
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  g:= t1 + t2;
//  c:= c + t1;

        ADD     [ESP].RegC,EBX
        ADD     EAX,EBX
        MOV     [ESP].RegG,EAX

//  W[10]:= (((W[8] shr 17) or (W[8] shl 15)) xor
//           ((W[8] shr 19) or (W[8] shl 13)) xor (W[8] shr 10)) + W[3] +
//          (((W[11] shr 7) or (W[11] shl 25)) xor
//           ((W[11] shr 18) or (W[11] shl 14)) xor (W[11] shr 3)) + W[10];

        MOV     ESI,[EDI].W8
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[EDI].W11
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[EDI].W3
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[EDI].W10
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [EDI].W10,ESI

//  t1:= f + (((c shr 6) or (c shl 26)) xor ((c shr 11) or (c shl 21)) xor
//      ((c shr 25) or (c shl 7))) + ((c and d) xor (not c and e)) + $c24b8b70 + W[10];

        MOV     EAX,[ESP].RegC
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,[ESP].RegD
        NOT     EAX
        AND     EAX,[ESP].RegE
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$c24b8b70
        ADD     EBX,[ESP].RegF

//  t2:= (((g shr 2) or (g shl 30)) xor ((g shr 13) or (g shl 19)) xor
//      ((g shr 22) xor (g shl 10))) + ((g and h) xor (g and a) xor (h and a));

        MOV     EAX,[ESP].RegG
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,[ESP].RegH
        MOV     EBP,[ESP].RegA
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  f:= t1 + t2;
//  b:= b + t1;

        ADD     [ESP].RegB,EBX
        ADD     EAX,EBX
        MOV     [ESP].RegF,EAX

//  W[11]:= (((W[9] shr 17) or (W[9] shl 15)) xor
//           ((W[9] shr 19) or (W[9] shl 13)) xor (W[9] shr 10)) + W[4] +
//          (((W[12] shr 7) or (W[12] shl 25)) xor
//           ((W[12] shr 18) or (W[12] shl 14)) xor (W[12] shr 3)) + W[11];

        MOV     ESI,[EDI].W9
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[EDI].W12
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[EDI].W4
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[EDI].W11
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [EDI].W11,ESI

//  t1:= e + (((b shr 6) or (b shl 26)) xor ((b shr 11) or (b shl 21)) xor
//      ((b shr 25) or (b shl 7))) + ((b and c) xor (not b and d)) + $c76c51a3 + W[11];

        MOV     EAX,[ESP].RegB
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,[ESP].RegC
        NOT     EAX
        AND     EAX,[ESP].RegD
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$c76c51a3
        ADD     EBX,[ESP].RegE

//  t2:= (((f shr 2) or (f shl 30)) xor ((f shr 13) or (f shl 19)) xor
//      ((f shr 22) xor (f shl 10))) + ((f and g) xor (f and h) xor (g and h));

        MOV     EAX,[ESP].RegF
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,[ESP].RegG
        MOV     EBP,[ESP].RegH
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  e:= t1 + t2;
//  a:= a + t1;

        ADD     [ESP].RegA,EBX
        ADD     EAX,EBX
        MOV     [ESP].RegE,EAX

//  W[12]:= (((W[10] shr 17) or (W[10] shl 15)) xor
//           ((W[10] shr 19) or (W[10] shl 13)) xor (W[10] shr 10)) + W[5] +
//          (((W[13] shr 7) or (W[13] shl 25)) xor
//           ((W[13] shr 18) or (W[13] shl 14)) xor (W[13] shr 3)) + W[12];

        MOV     ESI,[EDI].W10
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[EDI].W13
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[EDI].W5
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[EDI].W12
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [EDI].W12,ESI

//  t1:= d + (((a shr 6) or (a shl 26)) xor ((a shr 11) or (a shl 21)) xor
//      ((a shr 25) or (a shl 7))) + ((a and b) xor (not a and c)) + $d192e819 + W[12];

        MOV     EAX,[ESP].RegA
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,[ESP].RegB
        NOT     EAX
        AND     EAX,[ESP].RegC
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$d192e819
        ADD     EBX,[ESP].RegD

//  t2:= (((e shr 2) or (e shl 30)) xor ((e shr 13) or (e shl 19)) xor
//      ((e shr 22) xor (e shl 10))) + ((e and f) xor (e and g) xor (f and g));

        MOV     EAX,[ESP].RegE
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,[ESP].RegF
        MOV     EBP,[ESP].RegG
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  d:= t1 + t2;
//  h:= h + t1;

        ADD     [ESP].RegH,EBX
        ADD     EAX,EBX
        MOV     [ESP].RegD,EAX

//  W[13]:= (((W[11] shr 17) or (W[11] shl 15)) xor
//           ((W[11] shr 19) or (W[11] shl 13)) xor (W[11] shr 10)) + W[6] +
//          (((W[14] shr 7) or (W[14] shl 25)) xor
//           ((W[14] shr 18) or (W[14] shl 14)) xor (W[14] shr 3)) + W[13];

        MOV     ESI,[EDI].W11
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[EDI].W14
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[EDI].W6
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[EDI].W13
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [EDI].W13,ESI

//  t1:= c + (((h shr 6) or (h shl 26)) xor ((h shr 11) or (h shl 21)) xor
//      ((h shr 25) or (h shl 7))) + ((h and a) xor (not h and b)) + $d6990624 + W[13];

        MOV     EAX,[ESP].RegH
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,[ESP].RegA
        NOT     EAX
        AND     EAX,[ESP].RegB
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$d6990624
        ADD     EBX,[ESP].RegC

//  t2:= (((d shr 2) or (d shl 30)) xor ((d shr 13) or (d shl 19)) xor
//      ((d shr 22) xor (d shl 10))) + ((d and e) xor (d and f) xor (e and f));

        MOV     EAX,[ESP].RegD
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,[ESP].RegE
        MOV     EBP,[ESP].RegF
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  c:= t1 + t2;
//  g:= g + t1;

        ADD     [ESP].RegG,EBX
        ADD     EAX,EBX
        MOV     [ESP].RegC,EAX

//  W[14]:= (((W[12] shr 17) or (W[12] shl 15)) xor
//           ((W[12] shr 19) or (W[12] shl 13)) xor (W[12] shr 10)) + W[7] +
//          (((W[15] shr 7) or (W[15] shl 25)) xor
//           ((W[15] shr 18) or (W[15] shl 14)) xor (W[15] shr 3)) + W[14];

        MOV     ESI,[EDI].W12
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[EDI].W15
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[EDI].W7
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[EDI].W14
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [EDI].W14,ESI

//  t1:= b + (((g shr 6) or (g shl 26)) xor ((g shr 11) or (g shl 21)) xor
//      ((g shr 25) or (g shl 7))) + ((g and h) xor (not g and a)) + $f40e3585 + W[14];

        MOV     EAX,[ESP].RegG
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,[ESP].RegH
        NOT     EAX
        AND     EAX,[ESP].RegA
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$f40e3585
        ADD     EBX,[ESP].RegB

//  t2:= (((c shr 2) or (c shl 30)) xor ((c shr 13) or (c shl 19)) xor
//      ((c shr 22) xor (c shl 10))) + ((c and d) xor (c and e) xor (d and e));

        MOV     EAX,[ESP].RegC
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,[ESP].RegD
        MOV     EBP,[ESP].RegE
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  b:= t1 + t2;
//  f:= f + t1;

        ADD     [ESP].RegF,EBX
        ADD     EAX,EBX
        MOV     [ESP].RegB,EAX

//  W[15]:= (((W[13] shr 17) or (W[13] shl 15)) xor
//           ((W[13] shr 19) or (W[13] shl 13)) xor (W[13] shr 10)) + W[8] +
//          (((W[0] shr 7) or (W[0] shl 25)) xor
//           ((W[0] shr 18) or (W[0] shl 14)) xor (W[0] shr 3)) + W[15];

        MOV     ESI,[EDI].W13
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[EDI].W0
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[EDI].W8
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[EDI].W15
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [EDI].W15,ESI

//  t1:= a + (((f shr 6) or (f shl 26)) xor ((f shr 11) or (f shl 21)) xor
//      ((f shr 25) or (f shl 7))) + ((f and g) xor (not f and h)) + $106aa070 + W[15];

        MOV     EAX,[ESP].RegF
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,[ESP].RegG
        NOT     EAX
        AND     EAX,[ESP].RegH
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$106aa070
        ADD     EBX,[ESP].RegA

//  t2:= (((b shr 2) or (b shl 30)) xor ((b shr 13) or (b shl 19)) xor
//      ((b shr 22) xor (b shl 10))) + ((b and c) xor (b and d) xor (c and d));

        MOV     EAX,[ESP].RegB
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,[ESP].RegC
        MOV     EBP,[ESP].RegD
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  a:= t1 + t2;
//  e:= e + t1;

        ADD     [ESP].RegE,EBX
        ADD     EAX,EBX
        MOV     [ESP].RegA,EAX

//  W[0]:= (((W[14] shr 17) or (W[14] shl 15)) xor
//           ((W[14] shr 19) or (W[14] shl 13)) xor (W[14] shr 10)) + W[9] +
//         (((W[1] shr 7) or (W[1] shl 25)) xor
//          ((W[1] shr 18) or (W[1] shl 14)) xor (W[1] shr 3)) + W[0];

        MOV     ESI,[EDI].W14
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[EDI].W1
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[EDI].W9
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[EDI].W0
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [EDI].W0,ESI

//  t1:= h + (((e shr 6) or (e shl 26)) xor ((e shr 11) or (e shl 21)) xor
//      ((e shr 25) or (e shl 7))) + ((e and f) xor (not e and g)) + $19a4c116 + W[0];

        MOV     EAX,[ESP].RegE
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,[ESP].RegF
        NOT     EAX
        AND     EAX,[ESP].RegG
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$19a4c116
        ADD     EBX,[ESP].RegH

//  t2:= (((a shr 2) or (a shl 30)) xor ((a shr 13) or (a shl 19)) xor
//      ((a shr 22) xor (a shl 10))) + ((a and b) xor (a and c) xor (b and c));

        MOV     EAX,[ESP].RegA
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,[ESP].RegB
        MOV     EBP,[ESP].RegC
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  h:= t1 + t2;
//  d:= d + t1;

        ADD     [ESP].RegD,EBX
        ADD     EAX,EBX
        MOV     [ESP].RegH,EAX

//  W[1]:= (((W[15] shr 17) or (W[15] shl 15)) xor
//          ((W[15] shr 19) or (W[15] shl 13)) xor (W[15] shr 10)) + W[10] +
//         (((W[2] shr 7) or (W[2] shl 25)) xor
//          ((W[2] shr 18) or (W[2] shl 14)) xor (W[2] shr 3)) + W[1];

        MOV     ESI,[EDI].W15
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[EDI].W2
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[EDI].W10
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[EDI].W1
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [EDI].W1,ESI

//  t1:= g + (((d shr 6) or (d shl 26)) xor ((d shr 11) or (d shl 21)) xor
//      ((d shr 25) or (d shl 7))) + ((d and e) xor (not d and f)) + $1e376c08 + W[1];

        MOV     EAX,[ESP].RegD
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,[ESP].RegE
        NOT     EAX
        AND     EAX,[ESP].RegF
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$1e376c08
        ADD     EBX,[ESP].RegG

//  t2:= (((h shr 2) or (h shl 30)) xor ((h shr 13) or (h shl 19)) xor
//      ((h shr 22) xor (h shl 10))) + ((h and a) xor (h and b) xor (a and b));

        MOV     EAX,[ESP].RegH
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,[ESP].RegA
        MOV     EBP,[ESP].RegB
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  g:= t1 + t2;
//  c:= c + t1;

        ADD     [ESP].RegC,EBX
        ADD     EAX,EBX
        MOV     [ESP].RegG,EAX

//  W[2]:= (((W[0] shr 17) or (W[0] shl 15)) xor
//          ((W[0] shr 19) or (W[0] shl 13)) xor (W[0] shr 10)) + W[11] +
//         (((W[3] shr 7) or (W[3] shl 25)) xor
//          ((W[3] shr 18) or (W[3] shl 14)) xor (W[3] shr 3)) + W[2];

        MOV     ESI,[EDI].W0
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[EDI].W3
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[EDI].W11
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[EDI].W2
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [EDI].W2,ESI

//  t1:= f + (((c shr 6) or (c shl 26)) xor ((c shr 11) or (c shl 21)) xor
//      ((c shr 25) or (c shl 7))) + ((c and d) xor (not c and e)) + $2748774c + W[2];

        MOV     EAX,[ESP].RegC
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,[ESP].RegD
        NOT     EAX
        AND     EAX,[ESP].RegE
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$2748774c
        ADD     EBX,[ESP].RegF

//  t2:= (((g shr 2) or (g shl 30)) xor ((g shr 13) or (g shl 19)) xor
//      ((g shr 22) xor (g shl 10))) + ((g and h) xor (g and a) xor (h and a));

        MOV     EAX,[ESP].RegG
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,[ESP].RegH
        MOV     EBP,[ESP].RegA
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  f:= t1 + t2;
//  b:= b + t1;

        ADD     [ESP].RegB,EBX
        ADD     EAX,EBX
        MOV     [ESP].RegF,EAX

//  W[3]:= (((W[1] shr 17) or (W[1] shl 15)) xor
//          ((W[1] shr 19) or (W[1] shl 13)) xor (W[1] shr 10)) + W[12] +
//         (((W[4] shr 7) or (W[4] shl 25)) xor
//          ((W[4] shr 18) or (W[4] shl 14)) xor (W[4] shr 3)) + W[3];

        MOV     ESI,[EDI].W1
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[EDI].W4
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[EDI].W12
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[EDI].W3
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [EDI].W3,ESI

//  t1:= e + (((b shr 6) or (b shl 26)) xor ((b shr 11) or (b shl 21)) xor
//      ((b shr 25) or (b shl 7))) + ((b and c) xor (not b and d)) + $34b0bcb5 + W[3];

        MOV     EAX,[ESP].RegB
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,[ESP].RegC
        NOT     EAX
        AND     EAX,[ESP].RegD
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$34b0bcb5
        ADD     EBX,[ESP].RegE

//  t2:= (((f shr 2) or (f shl 30)) xor ((f shr 13) or (f shl 19)) xor
//      ((f shr 22) xor (f shl 10))) + ((f and g) xor (f and h) xor (g and h));

        MOV     EAX,[ESP].RegF
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,[ESP].RegG
        MOV     EBP,[ESP].RegH
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  e:= t1 + t2;
//  a:= a + t1;

        ADD     [ESP].RegA,EBX
        ADD     EAX,EBX
        MOV     [ESP].RegE,EAX

//  W[4]:= (((W[2] shr 17) or (W[2] shl 15)) xor
//          ((W[2] shr 19) or (W[2] shl 13)) xor (W[2] shr 10)) + W[13] +
//         (((W[5] shr 7) or (W[5] shl 25)) xor
//          ((W[5] shr 18) or (W[5] shl 14)) xor (W[5] shr 3)) + W[4];

        MOV     ESI,[EDI].W2
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[EDI].W5
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[EDI].W13
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[EDI].W4
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [EDI].W4,ESI

//  t1:= d + (((a shr 6) or (a shl 26)) xor ((a shr 11) or (a shl 21)) xor
//      ((a shr 25) or (a shl 7))) + ((a and b) xor (not a and c)) + $391c0cb3 + W[4];

        MOV     EAX,[ESP].RegA
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,[ESP].RegB
        NOT     EAX
        AND     EAX,[ESP].RegC
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$391c0cb3
        ADD     EBX,[ESP].RegD

//  t2:= (((e shr 2) or (e shl 30)) xor ((e shr 13) or (e shl 19)) xor
//      ((e shr 22) xor (e shl 10))) + ((e and f) xor (e and g) xor (f and g));

        MOV     EAX,[ESP].RegE
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,[ESP].RegF
        MOV     EBP,[ESP].RegG
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  d:= t1 + t2;
//  h:= h + t1;

        ADD     [ESP].RegH,EBX
        ADD     EAX,EBX
        MOV     [ESP].RegD,EAX

//  W[5]:= (((W[3] shr 17) or (W[3] shl 15)) xor
//          ((W[3] shr 19) or (W[3] shl 13)) xor (W[3] shr 10)) + W[14] +
//         (((W[6] shr 7) or (W[6] shl 25)) xor
//          ((W[6] shr 18) or (W[6] shl 14)) xor (W[6] shr 3)) + W[5];

        MOV     ESI,[EDI].W3
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[EDI].W6
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[EDI].W14
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[EDI].W5
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [EDI].W5,ESI

//  t1:= c + (((h shr 6) or (h shl 26)) xor ((h shr 11) or (h shl 21)) xor
//      ((h shr 25) or (h shl 7))) + ((h and a) xor (not h and b)) + $4ed8aa4a + W[5];

        MOV     EAX,[ESP].RegH
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,[ESP].RegA
        NOT     EAX
        AND     EAX,[ESP].RegB
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$4ed8aa4a
        ADD     EBX,[ESP].RegC

//  t2:= (((d shr 2) or (d shl 30)) xor ((d shr 13) or (d shl 19)) xor
//      ((d shr 22) xor (d shl 10))) + ((d and e) xor (d and f) xor (e and f));

        MOV     EAX,[ESP].RegD
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,[ESP].RegE
        MOV     EBP,[ESP].RegF
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  c:= t1 + t2;
//  g:= g + t1;

        ADD     [ESP].RegG,EBX
        ADD     EAX,EBX
        MOV     [ESP].RegC,EAX

//  W[6]:= (((W[4] shr 17) or (W[4] shl 15)) xor
//          ((W[4] shr 19) or (W[4] shl 13)) xor (W[4] shr 10)) + W[15] +
//         (((W[7] shr 7) or (W[7] shl 25)) xor
//          ((W[7] shr 18) or (W[7] shl 14)) xor (W[7] shr 3)) + W[6];

        MOV     ESI,[EDI].W4
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[EDI].W7
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[EDI].W15
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[EDI].W6
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [EDI].W6,ESI

//  t1:= b + (((g shr 6) or (g shl 26)) xor ((g shr 11) or (g shl 21)) xor
//      ((g shr 25) or (g shl 7))) + ((g and h) xor (not g and a)) + $5b9cca4f + W[6];

        MOV     EAX,[ESP].RegG
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,[ESP].RegH
        NOT     EAX
        AND     EAX,[ESP].RegA
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$5b9cca4f
        ADD     EBX,[ESP].RegB

//  t2:= (((c shr 2) or (c shl 30)) xor ((c shr 13) or (c shl 19)) xor
//      ((c shr 22) xor (c shl 10))) + ((c and d) xor (c and e) xor (d and e));

        MOV     EAX,[ESP].RegC
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,[ESP].RegD
        MOV     EBP,[ESP].RegE
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  b:= t1 + t2;
//  f:= f + t1;

        ADD     [ESP].RegF,EBX
        ADD     EAX,EBX
        MOV     [ESP].RegB,EAX

//  W[7]:= (((W[5] shr 17) or (W[5] shl 15)) xor
//          ((W[5] shr 19) or (W[5] shl 13)) xor (W[5] shr 10)) + W[0] +
//         (((W[8] shr 7) or (W[8] shl 25)) xor
//          ((W[8] shr 18) or (W[8] shl 14)) xor (W[8] shr 3)) + W[7];

        MOV     ESI,[EDI].W5
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[EDI].W8
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[EDI].W0
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[EDI].W7
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [EDI].W7,ESI

//  t1:= a + (((f shr 6) or (f shl 26)) xor ((f shr 11) or (f shl 21)) xor
//      ((f shr 25) or (f shl 7))) + ((f and g) xor (not f and h)) + $682e6ff3 + W[7];

        MOV     EAX,[ESP].RegF
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,[ESP].RegG
        NOT     EAX
        AND     EAX,[ESP].RegH
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$682e6ff3
        ADD     EBX,[ESP].RegA

//  t2:= (((b shr 2) or (b shl 30)) xor ((b shr 13) or (b shl 19)) xor
//      ((b shr 22) xor (b shl 10))) + ((b and c) xor (b and d) xor (c and d));

        MOV     EAX,[ESP].RegB
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,[ESP].RegC
        MOV     EBP,[ESP].RegD
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  a:= t1 + t2;
//  e:= e + t1;

        ADD     [ESP].RegE,EBX
        ADD     EAX,EBX
        MOV     [ESP].RegA,EAX

//  W[8]:= (((W[6] shr 17) or (W[6] shl 15)) xor
//          ((W[6] shr 19) or (W[6] shl 13)) xor (W[6] shr 10)) + W[1] +
//         (((W[9] shr 7) or (W[9] shl 25)) xor
//          ((W[9] shr 18) or (W[9] shl 14)) xor (W[9] shr 3)) + W[8];

        MOV     ESI,[EDI].W6
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[EDI].W9
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[EDI].W1
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[EDI].W8
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [EDI].W8,ESI

//  t1:= h + (((e shr 6) or (e shl 26)) xor ((e shr 11) or (e shl 21)) xor
//      ((e shr 25) or (e shl 7))) + ((e and f) xor (not e and g)) + $748f82ee + W[8];

        MOV     EAX,[ESP].RegE
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,[ESP].RegF
        NOT     EAX
        AND     EAX,[ESP].RegG
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$748f82ee
        ADD     EBX,[ESP].RegH

//  t2:= (((a shr 2) or (a shl 30)) xor ((a shr 13) or (a shl 19)) xor
//      ((a shr 22) xor (a shl 10))) + ((a and b) xor (a and c) xor (b and c));

        MOV     EAX,[ESP].RegA
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,[ESP].RegB
        MOV     EBP,[ESP].RegC
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  h:= t1 + t2;
//  d:= d + t1;

        ADD     [ESP].RegD,EBX
        ADD     EAX,EBX
        MOV     [ESP].RegH,EAX

//  W[9]:= (((W[7] shr 17) or (W[7] shl 15)) xor
//          ((W[7] shr 19) or (W[7] shl 13)) xor (W[7] shr 10)) + W[2] +
//         (((W[10] shr 7) or (W[10] shl 25)) xor
//          ((W[10] shr 18) or (W[10] shl 14)) xor (W[10] shr 3)) + W[9];

        MOV     ESI,[EDI].W7
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[EDI].W10
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[EDI].W2
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[EDI].W9
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [EDI].W9,ESI

//  t1:= g + (((d shr 6) or (d shl 26)) xor ((d shr 11) or (d shl 21)) xor
//      ((d shr 25) or (d shl 7))) + ((d and e) xor (not d and f)) + $78a5636f + W[9];

        MOV     EAX,[ESP].RegD
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,[ESP].RegE
        NOT     EAX
        AND     EAX,[ESP].RegF
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$78a5636f
        ADD     EBX,[ESP].RegG

//  t2:= (((h shr 2) or (h shl 30)) xor ((h shr 13) or (h shl 19)) xor
//      ((h shr 22) xor (h shl 10))) + ((h and a) xor (h and b) xor (a and b));

        MOV     EAX,[ESP].RegH
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,[ESP].RegA
        MOV     EBP,[ESP].RegB
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  g:= t1 + t2;
//  c:= c + t1;

        ADD     [ESP].RegC,EBX
        ADD     EAX,EBX
        MOV     [ESP].RegG,EAX

//  W[10]:= (((W[8] shr 17) or (W[8] shl 15)) xor
//           ((W[8] shr 19) or (W[8] shl 13)) xor (W[8] shr 10)) + W[3] +
//          (((W[11] shr 7) or (W[11] shl 25)) xor
//           ((W[11] shr 18) or (W[11] shl 14)) xor (W[11] shr 3)) + W[10];

        MOV     ESI,[EDI].W8
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[EDI].W11
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[EDI].W3
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[EDI].W10
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [EDI].W10,ESI

//  t1:= f + (((c shr 6) or (c shl 26)) xor ((c shr 11) or (c shl 21)) xor
//      ((c shr 25) or (c shl 7))) + ((c and d) xor (not c and e)) + $84c87814 + W[10];

        MOV     EAX,[ESP].RegC
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,[ESP].RegD
        NOT     EAX
        AND     EAX,[ESP].RegE
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$84c87814
        ADD     EBX,[ESP].RegF

//  t2:= (((g shr 2) or (g shl 30)) xor ((g shr 13) or (g shl 19)) xor
//      ((g shr 22) xor (g shl 10))) + ((g and h) xor (g and a) xor (h and a));

        MOV     EAX,[ESP].RegG
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,[ESP].RegH
        MOV     EBP,[ESP].RegA
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  f:= t1 + t2;
//  b:= b + t1;

        ADD     [ESP].RegB,EBX
        ADD     EAX,EBX
        MOV     [ESP].RegF,EAX

//  W[11]:= (((W[9] shr 17) or (W[9] shl 15)) xor
//           ((W[9] shr 19) or (W[9] shl 13)) xor (W[9] shr 10)) + W[4] +
//          (((W[12] shr 7) or (W[12] shl 25)) xor
//           ((W[12] shr 18) or (W[12] shl 14)) xor (W[12] shr 3)) + W[11];

        MOV     ESI,[EDI].W9
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[EDI].W12
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[EDI].W4
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[EDI].W11
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [EDI].W11,ESI

//  t1:= e + (((b shr 6) or (b shl 26)) xor ((b shr 11) or (b shl 21)) xor
//      ((b shr 25) or (b shl 7))) + ((b and c) xor (not b and d)) + $8cc70208 + W[11];

        MOV     EAX,[ESP].RegB
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,[ESP].RegC
        NOT     EAX
        AND     EAX,[ESP].RegD
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$8cc70208
        ADD     EBX,[ESP].RegE

//  t2:= (((f shr 2) or (f shl 30)) xor ((f shr 13) or (f shl 19)) xor
//      ((f shr 22) xor (f shl 10))) + ((f and g) xor (f and h) xor (g and h));

        MOV     EAX,[ESP].RegF
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,[ESP].RegG
        MOV     EBP,[ESP].RegH
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  e:= t1 + t2;
//  a:= a + t1;

        ADD     [ESP].RegA,EBX
        ADD     EAX,EBX
        MOV     [ESP].RegE,EAX

//  W[12]:= (((W[10] shr 17) or (W[10] shl 15)) xor
//           ((W[10] shr 19) or (W[10] shl 13)) xor (W[10] shr 10)) + W[5] +
//          (((W[13] shr 7) or (W[13] shl 25)) xor
//           ((W[13] shr 18) or (W[13] shl 14)) xor (W[13] shr 3)) + W[12];

        MOV     ESI,[EDI].W10
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[EDI].W13
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[EDI].W5
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[EDI].W12
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [EDI].W12,ESI

//  t1:= d + (((a shr 6) or (a shl 26)) xor ((a shr 11) or (a shl 21)) xor
//      ((a shr 25) or (a shl 7))) + ((a and b) xor (not a and c)) + $90befffa + W[12];

        MOV     EAX,[ESP].RegA
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,[ESP].RegB
        NOT     EAX
        AND     EAX,[ESP].RegC
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$90befffa
        ADD     EBX,[ESP].RegD

//  t2:= (((e shr 2) or (e shl 30)) xor ((e shr 13) or (e shl 19)) xor
//      ((e shr 22) xor (e shl 10))) + ((e and f) xor (e and g) xor (f and g));

        MOV     EAX,[ESP].RegE
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,[ESP].RegF
        MOV     EBP,[ESP].RegG
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  d:= t1 + t2;
//  h:= h + t1;

        ADD     [ESP].RegH,EBX
        ADD     EAX,EBX
        MOV     [ESP].RegD,EAX

//  W[13]:= (((W[11] shr 17) or (W[11] shl 15)) xor
//           ((W[11] shr 19) or (W[11] shl 13)) xor (W[11] shr 10)) + W[6] +
//          (((W[14] shr 7) or (W[14] shl 25)) xor
//           ((W[14] shr 18) or (W[14] shl 14)) xor (W[14] shr 3)) + W[13];

        MOV     ESI,[EDI].W11
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[EDI].W14
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[EDI].W6
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[EDI].W13
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [EDI].W13,ESI

//  t1:= c + (((h shr 6) or (h shl 26)) xor ((h shr 11) or (h shl 21)) xor
//      ((h shr 25) or (h shl 7))) + ((h and a) xor (not h and b)) + $a4506ceb + W[13];

        MOV     EAX,[ESP].RegH
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,[ESP].RegA
        NOT     EAX
        AND     EAX,[ESP].RegB
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$a4506ceb
        ADD     EBX,[ESP].RegC

//  t2:= (((d shr 2) or (d shl 30)) xor ((d shr 13) or (d shl 19)) xor
//      ((d shr 22) xor (d shl 10))) + ((d and e) xor (d and f) xor (e and f));

        MOV     EAX,[ESP].RegD
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,[ESP].RegE
        MOV     EBP,[ESP].RegF
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  c:= t1 + t2;
//  g:= g + t1;

        ADD     [ESP].RegG,EBX
        ADD     EAX,EBX
        MOV     [ESP].RegC,EAX

//  W[14]:= (((W[12] shr 17) or (W[12] shl 15)) xor
//           ((W[12] shr 19) or (W[12] shl 13)) xor (W[12] shr 10)) + W[7] +
//          (((W[15] shr 7) or (W[15] shl 25)) xor
//           ((W[15] shr 18) or (W[15] shl 14)) xor (W[15] shr 3)) + W[14];

        MOV     ESI,[EDI].W12
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[EDI].W15
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[EDI].W7
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[EDI].W14
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [EDI].W14,ESI

//  t1:= b + (((g shr 6) or (g shl 26)) xor ((g shr 11) or (g shl 21)) xor
//      ((g shr 25) or (g shl 7))) + ((g and h) xor (not g and a)) + $bef9a3f7 + W[14];

        MOV     EAX,[ESP].RegG
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,[ESP].RegH
        NOT     EAX
        AND     EAX,[ESP].RegA
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$bef9a3f7
        ADD     EBX,[ESP].RegB

//  t2:= (((c shr 2) or (c shl 30)) xor ((c shr 13) or (c shl 19)) xor
//      ((c shr 22) xor (c shl 10))) + ((c and d) xor (c and e) xor (d and e));

        MOV     EAX,[ESP].RegC
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,[ESP].RegD
        MOV     EBP,[ESP].RegE
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  b:= t1 + t2;
//  f:= f + t1;

        ADD     [ESP].RegF,EBX
        ADD     EAX,EBX
        MOV     [ESP].RegB,EAX

//  W[15]:= (((W[13] shr 17) or (W[13] shl 15)) xor
//           ((W[13] shr 19) or (W[13] shl 13)) xor (W[13] shr 10)) + W[8] +
//          (((W[0] shr 7) or (W[0] shl 25)) xor
//           ((W[0] shr 18) or (W[0] shl 14)) xor (W[0] shr 3)) + W[15];

        MOV     ESI,[EDI].W13
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[EDI].W0
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[EDI].W8
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[EDI].W15
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [EDI].W15,ESI

//  t1:= a + (((f shr 6) or (f shl 26)) xor ((f shr 11) or (f shl 21)) xor
//      ((f shr 25) or (f shl 7))) + ((f and g) xor (not f and h)) + $c67178f2 + W[15];

        MOV     EAX,[ESP].RegF
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,[ESP].RegG
        NOT     EAX
        AND     EAX,[ESP].RegH
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$c67178f2
        ADD     EBX,[ESP].RegA

//  t2:= (((b shr 2) or (b shl 30)) xor ((b shr 13) or (b shl 19)) xor
//      ((b shr 22) xor (b shl 10))) + ((b and c) xor (b and d) xor (c and d));

        MOV     EAX,[ESP].RegB
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,[ESP].RegC
        MOV     EBP,[ESP].RegD
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  a:= t1 + t2;
//  e:= e + t1;

        ADD     [ESP].RegE,EBX
        ADD     EAX,EBX
        MOV     [ESP].RegA,EAX

        POP     EAX
        ADD     [EDI].DigestH,EAX
        POP     EAX
        ADD     [EDI].DigestG,EAX
        POP     EAX
        ADD     [EDI].DigestF,EAX
        POP     EAX
        ADD     [EDI].DigestE,EAX
        POP     EAX
        ADD     [EDI].DigestD,EAX
        POP     EAX
        ADD     [EDI].DigestC,EAX
        POP     EAX
        ADD     [EDI].DigestB,EAX
        POP     EAX
        ADD     [EDI].DigestA,EAX
{
        MOV     EAX,[ESP].RegA
        MOV     [EDI].DigestA,EAX
        MOV     EAX,[ESP].RegB
        MOV     [EDI].DigestB,EAX
        MOV     EAX,[ESP].RegC
        MOV     [EDI].DigestC,EAX
        MOV     EAX,[ESP].RegD
        MOV     [EDI].DigestD,EAX
        MOV     EAX,[ESP].RegE
        MOV     [EDI].DigestE,EAX
        MOV     EAX,[ESP].RegF
        MOV     [EDI].DigestF,EAX
        MOV     EAX,[ESP].RegG
        MOV     [EDI].DigestG,EAX
        MOV     EAX,[ESP].RegH
        MOV     [EDI].DigestH,EAX

        XOR     EAX,EAX
        MOV     [ESP].RegA,EAX
        MOV     [ESP].RegB,EAX
        MOV     [ESP].RegC,EAX
        MOV     [ESP].RegD,EAX
        MOV     [ESP].RegE,EAX
        MOV     [ESP].RegF,EAX
        MOV     [ESP].RegG,EAX
        MOV     [ESP].RegH,EAX
        ADD     ESP,32
}
        XOR     EAX,EAX
        MOV     [EDI].W0,EAX
        MOV     [EDI].W1,EAX
        MOV     [EDI].W2,EAX
        MOV     [EDI].W3,EAX
        MOV     [EDI].W4,EAX
        MOV     [EDI].W5,EAX
        MOV     [EDI].W6,EAX
        MOV     [EDI].W7,EAX
        MOV     [EDI].W8,EAX
        MOV     [EDI].W9,EAX
        MOV     [EDI].W10,EAX
        MOV     [EDI].W11,EAX
        MOV     [EDI].W12,EAX
        MOV     [EDI].W13,EAX
        MOV     [EDI].W14,EAX
        MOV     [EDI].W15,EAX

        POP     EBP
        POP     EBX
        POP     EDI
        POP     ESI
end;
{$ENDIF}

{$IFDEF CPUX64_WIN64}
{------------
  RegA = R8D
  RegB = R9D
  RegC = R10D
  RegD = R11D
  RegE = R12D
  RegF = R13D
  RegG = R14D
  RegH = R15D
-------------}
procedure TSHA256Alg.Compress;{$IFDEF FPC}assembler; nostackframe;{$ENDIF}
const
// SHA256 registers:
  DigestA = -32;  // [RDI - 32]
  DigestB = -28;  // [RDI - 28]
  DigestC = -24;  // [RDI - 24]
  DigestD = -20;  // [RDI - 20]
  DigestE = -16;  // [RDI - 16]
  DigestF = -12;  // [RDI - 12]
  DigestG = -8;   // [RDI - 8]
  DigestH = -4;   // [RDI - 4]

  W0  = 0;    W1  = 4;    W2  = 8;    W3  = 12;
  W4  = 16;   W5  = 20;   W6  = 24;   W7  = 28;
  W8  = 32;   W9  = 36;   W10 = 40;   W11 = 44;
  W12 = 48;   W13 = 52;   W14 = 56;   W15 = 60;

asm
{$IFNDEF FPC}
        .NOFRAME
{$ENDIF}
        PUSH    RSI
        PUSH    RDI
        PUSH    RBX
        PUSH    RBP
        PUSH    R12
        PUSH    R13
        PUSH    R14
        PUSH    R15
        SUB     RSP,8

        LEA     RDI,[RCX].TSHA256Alg.FData.Block    // W:= @FData.Block;

        MOV     R8D,[RDI].DigestA
        MOV     R9D,[RDI].DigestB
        MOV     R10D,[RDI].DigestC
        MOV     R11D,[RDI].DigestD
        MOV     R12D,[RDI].DigestE
        MOV     R13D,[RDI].DigestF
        MOV     R14D,[RDI].DigestG
        MOV     R15D,[RDI].DigestH

//  W[0]:= Swap32(W[0]);

        MOV     ESI,[RDI].W0
        BSWAP   ESI
        MOV     [RDI].W0,ESI

//  t1:= h + (((e shr 6) or (e shl 26)) xor ((e shr 11) or (e shl 21)) xor
//      ((e shr 25) or (e shl 7))) + ((e and f) xor (not e and g)) + $428a2f98 + W[0];

        MOV     EAX,R12D
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,R13D
        NOT     EAX
        AND     EAX,R14D
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$428a2f98
        ADD     EBX,R15D

//  t2:= (((a shr 2) or (a shl 30)) xor ((a shr 13) or (a shl 19)) xor
//      ((a shr 22) xor (a shl 10))) + ((a and b) xor (a and c) xor (b and c));

        MOV     EAX,R8D
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,R9D
        MOV     EBP,R10D
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  h:= t1 + t2;
//  d:= d + t1;

        ADD     R11D,EBX
        ADD     EAX,EBX
        MOV     R15D,EAX


//  W[1]:= Swap32(W[1]);

        MOV     ESI,[RDI].W1
        BSWAP   ESI
        MOV     [RDI].W1,ESI

//  t1:= g + (((d shr 6) or (d shl 26)) xor ((d shr 11) or (d shl 21)) xor
//      ((d shr 25) or (d shl 7))) + ((d and e) xor (not d and f)) + $71374491 + W[1];

        MOV     EAX,R11D
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,R12D
        NOT     EAX
        AND     EAX,R13D
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$71374491
        ADD     EBX,R14D

//  t2:= (((h shr 2) or (h shl 30)) xor ((h shr 13) or (h shl 19)) xor
//      ((h shr 22) xor (h shl 10))) + ((h and a) xor (h and b) xor (a and b));

        MOV     EAX,R15D
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,R8D
        MOV     EBP,R9D
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  g:= t1 + t2;
//  c:= c + t1;

        ADD     R10D,EBX
        ADD     EAX,EBX
        MOV     R14D,EAX


//  W[2]:= Swap32(W[2]);

        MOV     ESI,[RDI].W2
        BSWAP   ESI
        MOV     [RDI].W2,ESI

//  t1:= f + (((c shr 6) or (c shl 26)) xor ((c shr 11) or (c shl 21)) xor
//      ((c shr 25) or (c shl 7))) + ((c and d) xor (not c and e)) + $b5c0fbcf + W[2];

        MOV     EAX,R10D
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,R11D
        NOT     EAX
        AND     EAX,R12D
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$b5c0fbcf
        ADD     EBX,R13D

//  t2:= (((g shr 2) or (g shl 30)) xor ((g shr 13) or (g shl 19)) xor
//      ((g shr 22) xor (g shl 10))) + ((g and h) xor (g and a) xor (h and a));

        MOV     EAX,R14D
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,R15D
        MOV     EBP,R8D
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  f:= t1 + t2;
//  b:= b + t1;

        ADD     R9D,EBX
        ADD     EAX,EBX
        MOV     R13D,EAX


//  W[3]:= Swap32(W[3]);

        MOV     ESI,[RDI].W3
        BSWAP   ESI
        MOV     [RDI].W3,ESI

//  t1:= e + (((b shr 6) or (b shl 26)) xor ((b shr 11) or (b shl 21)) xor
//      ((b shr 25) or (b shl 7))) + ((b and c) xor (not b and d)) + $e9b5dba5 + W[3];

        MOV     EAX,R9D
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,R10D
        NOT     EAX
        AND     EAX,R11D
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$e9b5dba5
        ADD     EBX,R12D

//  t2:= (((f shr 2) or (f shl 30)) xor ((f shr 13) or (f shl 19)) xor
//      ((f shr 22) xor (f shl 10))) + ((f and g) xor (f and h) xor (g and h));

        MOV     EAX,R13D
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,R14D
        MOV     EBP,R15D
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  e:= t1 + t2;
//  a:= a + t1;

        ADD     R8D,EBX
        ADD     EAX,EBX
        MOV     R12D,EAX

//  W[4]:= Swap32(W[4]);

        MOV     ESI,[RDI].W4
        BSWAP   ESI
        MOV     [RDI].W4,ESI

//  t1:= d + (((a shr 6) or (a shl 26)) xor ((a shr 11) or (a shl 21)) xor
//      ((a shr 25) or (a shl 7))) + ((a and b) xor (not a and c)) + $3956c25b + W[4];

        MOV     EAX,R8D
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,R9D
        NOT     EAX
        AND     EAX,R10D
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$3956c25b
        ADD     EBX,R11D

//  t2:= (((e shr 2) or (e shl 30)) xor ((e shr 13) or (e shl 19)) xor
//      ((e shr 22) xor (e shl 10))) + ((e and f) xor (e and g) xor (f and g));

        MOV     EAX,R12D
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,R13D
        MOV     EBP,R14D
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  d:= t1 + t2;
//  h:= h + t1;

        ADD     R15D,EBX
        ADD     EAX,EBX
        MOV     R11D,EAX

//  W[5]:= Swap32(W[5]);

        MOV     ESI,[RDI].W5
        BSWAP   ESI
        MOV     [RDI].W5,ESI

//  t1:= c + (((h shr 6) or (h shl 26)) xor ((h shr 11) or (h shl 21)) xor
//      ((h shr 25) or (h shl 7))) + ((h and a) xor (not h and b)) + $59f111f1 + W[5];

        MOV     EAX,R15D
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,R8D
        NOT     EAX
        AND     EAX,R9D
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$59f111f1
        ADD     EBX,R10D

//  t2:= (((d shr 2) or (d shl 30)) xor ((d shr 13) or (d shl 19)) xor
//      ((d shr 22) xor (d shl 10))) + ((d and e) xor (d and f) xor (e and f));

        MOV     EAX,R11D
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,R12D
        MOV     EBP,R13D
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  c:= t1 + t2;
//  g:= g + t1;

        ADD     R14D,EBX
        ADD     EAX,EBX
        MOV     R10D,EAX

//  W[6]:= Swap32(W[6]);

        MOV     ESI,[RDI].W6
        BSWAP   ESI
        MOV     [RDI].W6,ESI

//  t1:= b + (((g shr 6) or (g shl 26)) xor ((g shr 11) or (g shl 21)) xor
//      ((g shr 25) or (g shl 7))) + ((g and h) xor (not g and a)) + $923f82a4 + W[6];

        MOV     EAX,R14D
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,R15D
        NOT     EAX
        AND     EAX,R8D
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$923f82a4
        ADD     EBX,R9D

//  t2:= (((c shr 2) or (c shl 30)) xor ((c shr 13) or (c shl 19)) xor
//      ((c shr 22) xor (c shl 10))) + ((c and d) xor (c and e) xor (d and e));

        MOV     EAX,R10D
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,R11D
        MOV     EBP,R12D
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  b:= t1 + t2;
//  f:= f + t1;

        ADD     R13D,EBX
        ADD     EAX,EBX
        MOV     R9D,EAX

//  W[7]:= Swap32(W[7]);

        MOV     ESI,[RDI].W7
        BSWAP   ESI
        MOV     [RDI].W7,ESI

//  t1:= a + (((f shr 6) or (f shl 26)) xor ((f shr 11) or (f shl 21)) xor
//      ((f shr 25) or (f shl 7))) + ((f and g) xor (not f and h)) + $ab1c5ed5 + W[7];

        MOV     EAX,R13D
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,R14D
        NOT     EAX
        AND     EAX,R15D
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$ab1c5ed5
        ADD     EBX,R8D

//  t2:= (((b shr 2) or (b shl 30)) xor ((b shr 13) or (b shl 19)) xor
//      ((b shr 22) xor (b shl 10))) + ((b and c) xor (b and d) xor (c and d));

        MOV     EAX,R9D
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,R10D
        MOV     EBP,R11D
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  a:= t1 + t2;
//  e:= e + t1;

        ADD     R12D,EBX
        ADD     EAX,EBX
        MOV     R8D,EAX

//  W[8]:= Swap32(W[8]);

        MOV     ESI,[RDI].W8
        BSWAP   ESI
        MOV     [RDI].W8,ESI

//  t1:= h + (((e shr 6) or (e shl 26)) xor ((e shr 11) or (e shl 21)) xor
//      ((e shr 25) or (e shl 7))) + ((e and f) xor (not e and g)) + $d807aa98 + W[8];

        MOV     EAX,R12D
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,R13D
        NOT     EAX
        AND     EAX,R14D
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$d807aa98
        ADD     EBX,R15D

//  t2:= (((a shr 2) or (a shl 30)) xor ((a shr 13) or (a shl 19)) xor
//      ((a shr 22) xor (a shl 10))) + ((a and b) xor (a and c) xor (b and c));

        MOV     EAX,R8D
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,R9D
        MOV     EBP,R10D
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  h:= t1 + t2;
//  d:= d + t1;

        ADD     R11D,EBX
        ADD     EAX,EBX
        MOV     R15D,EAX

//  W[9]:= Swap32(W[9]);

        MOV     ESI,[RDI].W9
        BSWAP   ESI
        MOV     [RDI].W9,ESI

//  t1:= g + (((d shr 6) or (d shl 26)) xor ((d shr 11) or (d shl 21)) xor
//      ((d shr 25) or (d shl 7))) + ((d and e) xor (not d and f)) + $12835b01 + W[9];

        MOV     EAX,R11D
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,R12D
        NOT     EAX
        AND     EAX,R13D
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$12835b01
        ADD     EBX,R14D

//  t2:= (((h shr 2) or (h shl 30)) xor ((h shr 13) or (h shl 19)) xor
//      ((h shr 22) xor (h shl 10))) + ((h and a) xor (h and b) xor (a and b));

        MOV     EAX,R15D
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,R8D
        MOV     EBP,R9D
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  g:= t1 + t2;
//  c:= c + t1;

        ADD     R10D,EBX
        ADD     EAX,EBX
        MOV     R14D,EAX

//  W[10]:= Swap32(W[10]);

        MOV     ESI,[RDI].W10
        BSWAP   ESI
        MOV     [RDI].W10,ESI

//  t1:= f + (((c shr 6) or (c shl 26)) xor ((c shr 11) or (c shl 21)) xor
//      ((c shr 25) or (c shl 7))) + ((c and d) xor (not c and e)) + $243185be + W[10];

        MOV     EAX,R10D
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,R11D
        NOT     EAX
        AND     EAX,R12D
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$243185be
        ADD     EBX,R13D

//  t2:= (((g shr 2) or (g shl 30)) xor ((g shr 13) or (g shl 19)) xor
//      ((g shr 22) xor (g shl 10))) + ((g and h) xor (g and a) xor (h and a));

        MOV     EAX,R14D
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,R15D
        MOV     EBP,R8D
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  f:= t1 + t2;
//  b:= b + t1;

        ADD     R9D,EBX
        ADD     EAX,EBX
        MOV     R13D,EAX

//  W[11]:= Swap32(W[11]);

        MOV     ESI,[RDI].W11
        BSWAP   ESI
        MOV     [RDI].W11,ESI

//  t1:= e + (((b shr 6) or (b shl 26)) xor ((b shr 11) or (b shl 21)) xor
//      ((b shr 25) or (b shl 7))) + ((b and c) xor (not b and d)) + $550c7dc3 + W[11];

        MOV     EAX,R9D
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,R10D
        NOT     EAX
        AND     EAX,R11D
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$550c7dc3
        ADD     EBX,R12D

//  t2:= (((f shr 2) or (f shl 30)) xor ((f shr 13) or (f shl 19)) xor
//      ((f shr 22) xor (f shl 10))) + ((f and g) xor (f and h) xor (g and h));

        MOV     EAX,R13D
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,R14D
        MOV     EBP,R15D
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  e:= t1 + t2;
//  a:= a + t1;

        ADD     R8D,EBX
        ADD     EAX,EBX
        MOV     R12D,EAX

//  W[12]:= Swap32(W[12]);

        MOV     ESI,[RDI].W12
        BSWAP   ESI
        MOV     [RDI].W12,ESI

//  t1:= d + (((a shr 6) or (a shl 26)) xor ((a shr 11) or (a shl 21)) xor
//      ((a shr 25) or (a shl 7))) + ((a and b) xor (not a and c)) + $72be5d74 + W[12];

        MOV     EAX,R8D
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,R9D
        NOT     EAX
        AND     EAX,R10D
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$72be5d74
        ADD     EBX,R11D

//  t2:= (((e shr 2) or (e shl 30)) xor ((e shr 13) or (e shl 19)) xor
//      ((e shr 22) xor (e shl 10))) + ((e and f) xor (e and g) xor (f and g));

        MOV     EAX,R12D
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,R13D
        MOV     EBP,R14D
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  d:= t1 + t2;
//  h:= h + t1;

        ADD     R15D,EBX
        ADD     EAX,EBX
        MOV     R11D,EAX

//  W[13]:= Swap32(W[13]);

        MOV     ESI,[RDI].W13
        BSWAP   ESI
        MOV     [RDI].W13,ESI

//  t1:= c + (((h shr 6) or (h shl 26)) xor ((h shr 11) or (h shl 21)) xor
//      ((h shr 25) or (h shl 7))) + ((h and a) xor (not h and b)) + $80deb1fe + W[13];

        MOV     EAX,R15D
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,R8D
        NOT     EAX
        AND     EAX,R9D
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$80deb1fe
        ADD     EBX,R10D

//  t2:= (((d shr 2) or (d shl 30)) xor ((d shr 13) or (d shl 19)) xor
//      ((d shr 22) xor (d shl 10))) + ((d and e) xor (d and f) xor (e and f));

        MOV     EAX,R11D
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,R12D
        MOV     EBP,R13D
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  c:= t1 + t2;
//  g:= g + t1;

        ADD     R14D,EBX
        ADD     EAX,EBX
        MOV     R10D,EAX

//  W[14]:= Swap32(W[14]);

        MOV     ESI,[RDI].W14
        BSWAP   ESI
        MOV     [RDI].W14,ESI

//  t1:= b + (((g shr 6) or (g shl 26)) xor ((g shr 11) or (g shl 21)) xor
//      ((g shr 25) or (g shl 7))) + ((g and h) xor (not g and a)) + $9bdc06a7 + W[14];

        MOV     EAX,R14D
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,R15D
        NOT     EAX
        AND     EAX,R8D
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$9bdc06a7
        ADD     EBX,R9D

//  t2:= (((c shr 2) or (c shl 30)) xor ((c shr 13) or (c shl 19)) xor
//      ((c shr 22) xor (c shl 10))) + ((c and d) xor (c and e) xor (d and e));

        MOV     EAX,R10D
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,R11D
        MOV     EBP,R12D
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  b:= t1 + t2;
//  f:= f + t1;

        ADD     R13D,EBX
        ADD     EAX,EBX
        MOV     R9D,EAX

//  W[15]:= Swap32(W[15]);

        MOV     ESI,[RDI].W15
        BSWAP   ESI
        MOV     [RDI].W15,ESI

//  t1:= a + (((f shr 6) or (f shl 26)) xor ((f shr 11) or (f shl 21)) xor
//      ((f shr 25) or (f shl 7))) + ((f and g) xor (not f and h)) + $c19bf174 + W[15];

        MOV     EAX,R13D
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,R14D
        NOT     EAX
        AND     EAX,R15D
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$c19bf174
        ADD     EBX,R8D

//  t2:= (((b shr 2) or (b shl 30)) xor ((b shr 13) or (b shl 19)) xor
//      ((b shr 22) xor (b shl 10))) + ((b and c) xor (b and d) xor (c and d));

        MOV     EAX,R9D
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,R10D
        MOV     EBP,R11D
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  a:= t1 + t2;
//  e:= e + t1;

        ADD     R12D,EBX
        ADD     EAX,EBX
        MOV     R8D,EAX

//  W[0]:= (((W[14] shr 17) or (W[14] shl 15)) xor
//          ((W[14] shr 19) or (W[14] shl 13)) xor (W[14] shr 10)) + W[9] +
//         (((W[1] shr 7) or (W[1] shl 25)) xor
//          ((W[1] shr 18) or (W[1] shl 14)) xor (W[1] shr 3)) + W[0];

        MOV     ESI,[RDI].W14
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[RDI].W1
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[RDI].W9
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[RDI].W0
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [RDI].W0,ESI

//  t1:= h + (((e shr 6) or (e shl 26)) xor ((e shr 11) or (e shl 21)) xor
//      ((e shr 25) or (e shl 7))) + ((e and f) xor (not e and g)) + $e49b69c1 + W[0];

        MOV     EAX,R12D
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,R13D
        NOT     EAX
        AND     EAX,R14D
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$e49b69c1
        ADD     EBX,R15D

//  t2:= (((a shr 2) or (a shl 30)) xor ((a shr 13) or (a shl 19)) xor
//      ((a shr 22) xor (a shl 10))) + ((a and b) xor (a and c) xor (b and c));

        MOV     EAX,R8D
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,R9D
        MOV     EBP,R10D
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  h:= t1 + t2;
//  d:= d + t1;

        ADD     R11D,EBX
        ADD     EAX,EBX
        MOV     R15D,EAX

//  W[1]:= (((W[15] shr 17) or (W[15] shl 15)) xor
//          ((W[15] shr 19) or (W[15] shl 13)) xor (W[15] shr 10)) + W[10] +
//         (((W[2] shr 7) or (W[2] shl 25)) xor
//          ((W[2] shr 18) or (W[2] shl 14)) xor (W[2] shr 3)) + W[1];

        MOV     ESI,[RDI].W15
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[RDI].W2
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[RDI].W10
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[RDI].W1
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [RDI].W1,ESI

//  t1:= g + (((d shr 6) or (d shl 26)) xor ((d shr 11) or (d shl 21)) xor
//      ((d shr 25) or (d shl 7))) + ((d and e) xor (not d and f)) + $efbe4786 + W[1];

        MOV     EAX,R11D
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,R12D
        NOT     EAX
        AND     EAX,R13D
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$efbe4786
        ADD     EBX,R14D

//  t2:= (((h shr 2) or (h shl 30)) xor ((h shr 13) or (h shl 19)) xor
//      ((h shr 22) xor (h shl 10))) + ((h and a) xor (h and b) xor (a and b));

        MOV     EAX,R15D
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,R8D
        MOV     EBP,R9D
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  g:= t1 + t2;
//  c:= c + t1;

        ADD     R10D,EBX
        ADD     EAX,EBX
        MOV     R14D,EAX

//  W[2]:= (((W[0] shr 17) or (W[0] shl 15)) xor
//          ((W[0] shr 19) or (W[0] shl 13)) xor (W[0] shr 10)) + W[11] +
//         (((W[3] shr 7) or (W[3] shl 25)) xor
//          ((W[3] shr 18) or (W[3] shl 14)) xor (W[3] shr 3)) + W[2];

        MOV     ESI,[RDI].W0
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[RDI].W3
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[RDI].W11
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[RDI].W2
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [RDI].W2,ESI

//  t1:= f + (((c shr 6) or (c shl 26)) xor ((c shr 11) or (c shl 21)) xor
//      ((c shr 25) or (c shl 7))) + ((c and d) xor (not c and e)) + $0fc19dc6 + W[2];

        MOV     EAX,R10D
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,R11D
        NOT     EAX
        AND     EAX,R12D
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$0fc19dc6
        ADD     EBX,R13D

//  t2:= (((g shr 2) or (g shl 30)) xor ((g shr 13) or (g shl 19)) xor
//      ((g shr 22) xor (g shl 10))) + ((g and h) xor (g and a) xor (h and a));

        MOV     EAX,R14D
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,R15D
        MOV     EBP,R8D
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  f:= t1 + t2;
//  b:= b + t1;

        ADD     R9D,EBX
        ADD     EAX,EBX
        MOV     R13D,EAX

//  W[3]:= (((W[1] shr 17) or (W[1] shl 15)) xor
//          ((W[1] shr 19) or (W[1] shl 13)) xor (W[1] shr 10)) + W[12] +
//         (((W[4] shr 7) or (W[4] shl 25)) xor
//          ((W[4] shr 18) or (W[4] shl 14)) xor (W[4] shr 3)) + W[3];

        MOV     ESI,[RDI].W1
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[RDI].W4
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[RDI].W12
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[RDI].W3
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [RDI].W3,ESI

//  t1:= e + (((b shr 6) or (b shl 26)) xor ((b shr 11) or (b shl 21)) xor
//      ((b shr 25) or (b shl 7))) + ((b and c) xor (not b and d)) + $240ca1cc + W[3];

        MOV     EAX,R9D
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,R10D
        NOT     EAX
        AND     EAX,R11D
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$240ca1cc
        ADD     EBX,R12D

//  t2:= (((f shr 2) or (f shl 30)) xor ((f shr 13) or (f shl 19)) xor
//      ((f shr 22) xor (f shl 10))) + ((f and g) xor (f and h) xor (g and h));

        MOV     EAX,R13D
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,R14D
        MOV     EBP,R15D
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  e:= t1 + t2;
//  a:= a + t1;

        ADD     R8D,EBX
        ADD     EAX,EBX
        MOV     R12D,EAX

//  W[4]:= (((W[2] shr 17) or (W[2] shl 15)) xor
//          ((W[2] shr 19) or (W[2] shl 13)) xor (W[2] shr 10)) + W[13] +
//         (((W[5] shr 7) or (W[5] shl 25)) xor
//          ((W[5] shr 18) or (W[5] shl 14)) xor (W[5] shr 3)) + W[4];

        MOV     ESI,[RDI].W2
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[RDI].W5
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[RDI].W13
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[RDI].W4
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [RDI].W4,ESI

//  t1:= d + (((a shr 6) or (a shl 26)) xor ((a shr 11) or (a shl 21)) xor
//      ((a shr 25) or (a shl 7))) + ((a and b) xor (not a and c)) + $2de92c6f + W[4];

        MOV     EAX,R8D
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,R9D
        NOT     EAX
        AND     EAX,R10D
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$2de92c6f
        ADD     EBX,R11D

//  t2:= (((e shr 2) or (e shl 30)) xor ((e shr 13) or (e shl 19)) xor
//      ((e shr 22) xor (e shl 10))) + ((e and f) xor (e and g) xor (f and g));

        MOV     EAX,R12D
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,R13D
        MOV     EBP,R14D
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  d:= t1 + t2;
//  h:= h + t1;

        ADD     R15D,EBX
        ADD     EAX,EBX
        MOV     R11D,EAX

//  W[5]:= (((W[3] shr 17) or (W[3] shl 15)) xor
//          ((W[3] shr 19) or (W[3] shl 13)) xor (W[3] shr 10)) + W[14] +
//         (((W[6] shr 7) or (W[6] shl 25)) xor
//          ((W[6] shr 18) or (W[6] shl 14)) xor (W[6] shr 3)) + W[5];

        MOV     ESI,[RDI].W3
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[RDI].W6
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[RDI].W14
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[RDI].W5
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [RDI].W5,ESI

//  t1:= c + (((h shr 6) or (h shl 26)) xor ((h shr 11) or (h shl 21)) xor
//      ((h shr 25) or (h shl 7))) + ((h and a) xor (not h and b)) + $4a7484aa + W[5];

        MOV     EAX,R15D
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,R8D
        NOT     EAX
        AND     EAX,R9D
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$4a7484aa
        ADD     EBX,R10D

//  t2:= (((d shr 2) or (d shl 30)) xor ((d shr 13) or (d shl 19)) xor
//      ((d shr 22) xor (d shl 10))) + ((d and e) xor (d and f) xor (e and f));

        MOV     EAX,R11D
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,R12D
        MOV     EBP,R13D
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  c:= t1 + t2;
//  g:= g + t1;

        ADD     R14D,EBX
        ADD     EAX,EBX
        MOV     R10D,EAX

//  W[6]:= (((W[4] shr 17) or (W[4] shl 15)) xor
//          ((W[4] shr 19) or (W[4] shl 13)) xor (W[4] shr 10)) + W[15] +
//         (((W[7] shr 7) or (W[7] shl 25)) xor
//          ((W[7] shr 18) or (W[7] shl 14)) xor (W[7] shr 3)) + W[6];

        MOV     ESI,[RDI].W4
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[RDI].W7
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[RDI].W15
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[RDI].W6
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [RDI].W6,ESI

//  t1:= b + (((g shr 6) or (g shl 26)) xor ((g shr 11) or (g shl 21)) xor
//      ((g shr 25) or (g shl 7))) + ((g and h) xor (not g and a)) + $5cb0a9dc + W[6];

        MOV     EAX,R14D
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,R15D
        NOT     EAX
        AND     EAX,R8D
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$5cb0a9dc
        ADD     EBX,R9D

//  t2:= (((c shr 2) or (c shl 30)) xor ((c shr 13) or (c shl 19)) xor
//      ((c shr 22) xor (c shl 10))) + ((c and d) xor (c and e) xor (d and e));

        MOV     EAX,R10D
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,R11D
        MOV     EBP,R12D
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  b:= t1 + t2;
//  f:= f + t1;

        ADD     R13D,EBX
        ADD     EAX,EBX
        MOV     R9D,EAX

//  W[7]:= (((W[5] shr 17) or (W[5] shl 15)) xor
//          ((W[5] shr 19) or (W[5] shl 13)) xor (W[5] shr 10)) + W[0] +
//         (((W[8] shr 7) or (W[8] shl 25)) xor
//          ((W[8] shr 18) or (W[8] shl 14)) xor (W[8] shr 3)) + W[7];

        MOV     ESI,[RDI].W5
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[RDI].W8
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[RDI].W0
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[RDI].W7
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [RDI].W7,ESI

//  t1:= a + (((f shr 6) or (f shl 26)) xor ((f shr 11) or (f shl 21)) xor
//      ((f shr 25) or (f shl 7))) + ((f and g) xor (not f and h)) + $76f988da + W[7];

        MOV     EAX,R13D
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,R14D
        NOT     EAX
        AND     EAX,R15D
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$76f988da
        ADD     EBX,R8D

//  t2:= (((b shr 2) or (b shl 30)) xor ((b shr 13) or (b shl 19)) xor
//      ((b shr 22) xor (b shl 10))) + ((b and c) xor (b and d) xor (c and d));

        MOV     EAX,R9D
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,R10D
        MOV     EBP,R11D
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  a:= t1 + t2;
//  e:= e + t1;

        ADD     R12D,EBX
        ADD     EAX,EBX
        MOV     R8D,EAX

//  W[8]:= (((W[6] shr 17) or (W[6] shl 15)) xor
//          ((W[6] shr 19) or (W[6] shl 13)) xor (W[6] shr 10)) + W[1] +
//         (((W[9] shr 7) or (W[9] shl 25)) xor
//          ((W[9] shr 18) or (W[9] shl 14)) xor (W[9] shr 3)) + W[8];

        MOV     ESI,[RDI].W6
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[RDI].W9
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[RDI].W1
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[RDI].W8
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [RDI].W8,ESI

//  t1:= h + (((e shr 6) or (e shl 26)) xor ((e shr 11) or (e shl 21)) xor
//      ((e shr 25) or (e shl 7))) + ((e and f) xor (not e and g)) + $983e5152 + W[8];

        MOV     EAX,R12D
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,R13D
        NOT     EAX
        AND     EAX,R14D
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$983e5152
        ADD     EBX,R15D

//  t2:= (((a shr 2) or (a shl 30)) xor ((a shr 13) or (a shl 19)) xor
//      ((a shr 22) xor (a shl 10))) + ((a and b) xor (a and c) xor (b and c));

        MOV     EAX,R8D
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,R9D
        MOV     EBP,R10D
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  h:= t1 + t2;
//  d:= d + t1;

        ADD     R11D,EBX
        ADD     EAX,EBX
        MOV     R15D,EAX

//  W[9]:= (((W[7] shr 17) or (W[7] shl 15)) xor
//          ((W[7] shr 19) or (W[7] shl 13)) xor (W[7] shr 10)) + W[2] +
//         (((W[10] shr 7) or (W[10] shl 25)) xor
//          ((W[10] shr 18) or (W[10] shl 14)) xor (W[10] shr 3)) + W[9];

        MOV     ESI,[RDI].W7
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[RDI].W10
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[RDI].W2
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[RDI].W9
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [RDI].W9,ESI

//  t1:= g + (((d shr 6) or (d shl 26)) xor ((d shr 11) or (d shl 21)) xor
//      ((d shr 25) or (d shl 7))) + ((d and e) xor (not d and f)) + $a831c66d + W[9];

        MOV     EAX,R11D
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,R12D
        NOT     EAX
        AND     EAX,R13D
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$a831c66d
        ADD     EBX,R14D

//  t2:= (((h shr 2) or (h shl 30)) xor ((h shr 13) or (h shl 19)) xor
//      ((h shr 22) xor (h shl 10))) + ((h and a) xor (h and b) xor (a and b));

        MOV     EAX,R15D
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,R8D
        MOV     EBP,R9D
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  g:= t1 + t2;
//  c:= c + t1;

        ADD     R10D,EBX
        ADD     EAX,EBX
        MOV     R14D,EAX

//  W[10]:= (((W[8] shr 17) or (W[8] shl 15)) xor
//           ((W[8] shr 19) or (W[8] shl 13)) xor (W[8] shr 10)) + W[3] +
//          (((W[11] shr 7) or (W[11] shl 25)) xor
//           ((W[11] shr 18) or (W[11] shl 14)) xor (W[11] shr 3)) + W[10];

        MOV     ESI,[RDI].W8
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[RDI].W11
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[RDI].W3
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[RDI].W10
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [RDI].W10,ESI

//  t1:= f + (((c shr 6) or (c shl 26)) xor ((c shr 11) or (c shl 21)) xor
//      ((c shr 25) or (c shl 7))) + ((c and d) xor (not c and e)) + $b00327c8 + W[10];

        MOV     EAX,R10D
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,R11D
        NOT     EAX
        AND     EAX,R12D
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$b00327c8
        ADD     EBX,R13D

//  t2:= (((g shr 2) or (g shl 30)) xor ((g shr 13) or (g shl 19)) xor
//      ((g shr 22) xor (g shl 10))) + ((g and h) xor (g and a) xor (h and a));

        MOV     EAX,R14D
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,R15D
        MOV     EBP,R8D
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  f:= t1 + t2;
//  b:= b + t1;

        ADD     R9D,EBX
        ADD     EAX,EBX
        MOV     R13D,EAX

//  W[11]:= (((W[9] shr 17) or (W[9] shl 15)) xor
//           ((W[9] shr 19) or (W[9] shl 13)) xor (W[9] shr 10)) + W[4] +
//          (((W[12] shr 7) or (W[12] shl 25)) xor
//           ((W[12] shr 18) or (W[12] shl 14)) xor (W[12] shr 3)) + W[11];

        MOV     ESI,[RDI].W9
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[RDI].W12
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[RDI].W4
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[RDI].W11
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [RDI].W11,ESI

//  t1:= e + (((b shr 6) or (b shl 26)) xor ((b shr 11) or (b shl 21)) xor
//      ((b shr 25) or (b shl 7))) + ((b and c) xor (not b and d)) + $bf597fc7 + W[11];

        MOV     EAX,R9D
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,R10D
        NOT     EAX
        AND     EAX,R11D
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$bf597fc7
        ADD     EBX,R12D

//  t2:= (((f shr 2) or (f shl 30)) xor ((f shr 13) or (f shl 19)) xor
//      ((f shr 22) xor (f shl 10))) + ((f and g) xor (f and h) xor (g and h));

        MOV     EAX,R13D
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,R14D
        MOV     EBP,R15D
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  e:= t1 + t2;
//  a:= a + t1;

        ADD     R8D,EBX
        ADD     EAX,EBX
        MOV     R12D,EAX

//  W[12]:= (((W[10] shr 17) or (W[10] shl 15)) xor
//           ((W[10] shr 19) or (W[10] shl 13)) xor (W[10] shr 10)) + W[5] +
//          (((W[13] shr 7) or (W[13] shl 25)) xor
//           ((W[13] shr 18) or (W[13] shl 14)) xor (W[13] shr 3)) + W[12];

        MOV     ESI,[RDI].W10
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[RDI].W13
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[RDI].W5
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[RDI].W12
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [RDI].W12,ESI

//  t1:= d + (((a shr 6) or (a shl 26)) xor ((a shr 11) or (a shl 21)) xor
//      ((a shr 25) or (a shl 7))) + ((a and b) xor (not a and c)) + $c6e00bf3 + W[12];

        MOV     EAX,R8D
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,R9D
        NOT     EAX
        AND     EAX,R10D
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$c6e00bf3
        ADD     EBX,R11D

//  t2:= (((e shr 2) or (e shl 30)) xor ((e shr 13) or (e shl 19)) xor
//      ((e shr 22) xor (e shl 10))) + ((e and f) xor (e and g) xor (f and g));

        MOV     EAX,R12D
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,R13D
        MOV     EBP,R14D
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  d:= t1 + t2;
//  h:= h + t1;

        ADD     R15D,EBX
        ADD     EAX,EBX
        MOV     R11D,EAX

//  W[13]:= (((W[11] shr 17) or (W[11] shl 15)) xor
//           ((W[11] shr 19) or (W[11] shl 13)) xor (W[11] shr 10)) + W[6] +
//          (((W[14] shr 7) or (W[14] shl 25)) xor
//           ((W[14] shr 18) or (W[14] shl 14)) xor (W[14] shr 3)) + W[13];

        MOV     ESI,[RDI].W11
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[RDI].W14
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[RDI].W6
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[RDI].W13
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [RDI].W13,ESI

//  t1:= c + (((h shr 6) or (h shl 26)) xor ((h shr 11) or (h shl 21)) xor
//      ((h shr 25) or (h shl 7))) + ((h and a) xor (not h and b)) + $d5a79147 + W[13];

        MOV     EAX,R15D
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,R8D
        NOT     EAX
        AND     EAX,R9D
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$d5a79147
        ADD     EBX,R10D

//  t2:= (((d shr 2) or (d shl 30)) xor ((d shr 13) or (d shl 19)) xor
//      ((d shr 22) xor (d shl 10))) + ((d and e) xor (d and f) xor (e and f));

        MOV     EAX,R11D
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,R12D
        MOV     EBP,R13D
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  c:= t1 + t2;
//  g:= g + t1;

        ADD     R14D,EBX
        ADD     EAX,EBX
        MOV     R10D,EAX

//  W[14]:= (((W[12] shr 17) or (W[12] shl 15)) xor
//           ((W[12] shr 19) or (W[12] shl 13)) xor (W[12] shr 10)) + W[7] +
//          (((W[15] shr 7) or (W[15] shl 25)) xor
//           ((W[15] shr 18) or (W[15] shl 14)) xor (W[15] shr 3)) + W[14];

        MOV     ESI,[RDI].W12
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[RDI].W15
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[RDI].W7
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[RDI].W14
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [RDI].W14,ESI

//  t1:= b + (((g shr 6) or (g shl 26)) xor ((g shr 11) or (g shl 21)) xor
//      ((g shr 25) or (g shl 7))) + ((g and h) xor (not g and a)) + $06ca6351 + W[14];

        MOV     EAX,R14D
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,R15D
        NOT     EAX
        AND     EAX,R8D
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$06ca6351
        ADD     EBX,R9D

//  t2:= (((c shr 2) or (c shl 30)) xor ((c shr 13) or (c shl 19)) xor
//      ((c shr 22) xor (c shl 10))) + ((c and d) xor (c and e) xor (d and e));

        MOV     EAX,R10D
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,R11D
        MOV     EBP,R12D
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  b:= t1 + t2;
//  f:= f + t1;

        ADD     R13D,EBX
        ADD     EAX,EBX
        MOV     R9D,EAX

//  W[15]:= (((W[13] shr 17) or (W[13] shl 15)) xor
//           ((W[13] shr 19) or (W[13] shl 13)) xor (W[13] shr 10)) + W[8] +
//          (((W[0] shr 7) or (W[0] shl 25)) xor
//           ((W[0] shr 18) or (W[0] shl 14)) xor (W[0] shr 3)) + W[15];

        MOV     ESI,[RDI].W13
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[RDI].W0
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[RDI].W8
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[RDI].W15
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [RDI].W15,ESI

//  t1:= a + (((f shr 6) or (f shl 26)) xor ((f shr 11) or (f shl 21)) xor
//      ((f shr 25) or (f shl 7))) + ((f and g) xor (not f and h)) + $14292967 + W[15];

        MOV     EAX,R13D
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,R14D
        NOT     EAX
        AND     EAX,R15D
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$14292967
        ADD     EBX,R8D

//  t2:= (((b shr 2) or (b shl 30)) xor ((b shr 13) or (b shl 19)) xor
//      ((b shr 22) xor (b shl 10))) + ((b and c) xor (b and d) xor (c and d));

        MOV     EAX,R9D
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,R10D
        MOV     EBP,R11D
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  a:= t1 + t2;
//  e:= e + t1;

        ADD     R12D,EBX
        ADD     EAX,EBX
        MOV     R8D,EAX

//  W[0]:= (((W[14] shr 17) or (W[14] shl 15)) xor
//          ((W[14] shr 19) or (W[14] shl 13)) xor (W[14] shr 10)) + W[9] +
//         (((W[1] shr 7) or (W[1] shl 25)) xor
//          ((W[1] shr 18) or (W[1] shl 14)) xor (W[1] shr 3)) + W[0];

        MOV     ESI,[RDI].W14
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[RDI].W1
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[RDI].W9
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[RDI].W0
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [RDI].W0,ESI

//  t1:= h + (((e shr 6) or (e shl 26)) xor ((e shr 11) or (e shl 21)) xor
//      ((e shr 25) or (e shl 7))) + ((e and f) xor (not e and g)) + $27b70a85 + W[0];

        MOV     EAX,R12D
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,R13D
        NOT     EAX
        AND     EAX,R14D
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$27b70a85
        ADD     EBX,R15D

//  t2:= (((a shr 2) or (a shl 30)) xor ((a shr 13) or (a shl 19)) xor
//      ((a shr 22) xor (a shl 10))) + ((a and b) xor (a and c) xor (b and c));

        MOV     EAX,R8D
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,R9D
        MOV     EBP,R10D
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  h:= t1 + t2;
//  d:= d + t1;

        ADD     R11D,EBX
        ADD     EAX,EBX
        MOV     R15D,EAX

//  W[1]:= (((W[15] shr 17) or (W[15] shl 15)) xor
//          ((W[15] shr 19) or (W[15] shl 13)) xor (W[15] shr 10)) + W[10] +
//         (((W[2] shr 7) or (W[2] shl 25)) xor
//          ((W[2] shr 18) or (W[2] shl 14)) xor (W[2] shr 3)) + W[1];

        MOV     ESI,[RDI].W15
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[RDI].W2
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[RDI].W10
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[RDI].W1
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [RDI].W1,ESI

//  t1:= g + (((d shr 6) or (d shl 26)) xor ((d shr 11) or (d shl 21)) xor
//      ((d shr 25) or (d shl 7))) + ((d and e) xor (not d and f)) + $2e1b2138 + W[1];

        MOV     EAX,R11D
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,R12D
        NOT     EAX
        AND     EAX,R13D
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$2e1b2138
        ADD     EBX,R14D

//  t2:= (((h shr 2) or (h shl 30)) xor ((h shr 13) or (h shl 19)) xor
//      ((h shr 22) xor (h shl 10))) + ((h and a) xor (h and b) xor (a and b));

        MOV     EAX,R15D
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,R8D
        MOV     EBP,R9D
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  g:= t1 + t2;
//  c:= c + t1;

        ADD     R10D,EBX
        ADD     EAX,EBX
        MOV     R14D,EAX

//  W[2]:= (((W[0] shr 17) or (W[0] shl 15)) xor
//          ((W[0] shr 19) or (W[0] shl 13)) xor (W[0] shr 10)) + W[11] +
//         (((W[3] shr 7) or (W[3] shl 25)) xor
//          ((W[3] shr 18) or (W[3] shl 14)) xor (W[3] shr 3)) + W[2];

        MOV     ESI,[RDI].W0
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[RDI].W3
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[RDI].W11
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[RDI].W2
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [RDI].W2,ESI

//  t1:= f + (((c shr 6) or (c shl 26)) xor ((c shr 11) or (c shl 21)) xor
//      ((c shr 25) or (c shl 7))) + ((c and d) xor (not c and e)) + $4d2c6dfc + W[2];

        MOV     EAX,R10D
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,R11D
        NOT     EAX
        AND     EAX,R12D
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$4d2c6dfc
        ADD     EBX,R13D

//  t2:= (((g shr 2) or (g shl 30)) xor ((g shr 13) or (g shl 19)) xor
//      ((g shr 22) xor (g shl 10))) + ((g and h) xor (g and a) xor (h and a));

        MOV     EAX,R14D
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,R15D
        MOV     EBP,R8D
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  f:= t1 + t2;
//  b:= b + t1;

        ADD     R9D,EBX
        ADD     EAX,EBX
        MOV     R13D,EAX

//  W[3]:= (((W[1] shr 17) or (W[1] shl 15)) xor
//          ((W[1] shr 19) or (W[1] shl 13)) xor (W[1] shr 10)) + W[12] +
//         (((W[4] shr 7) or (W[4] shl 25)) xor
//          ((W[4] shr 18) or (W[4] shl 14)) xor (W[4] shr 3)) + W[3];

        MOV     ESI,[RDI].W1
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[RDI].W4
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[RDI].W12
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[RDI].W3
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [RDI].W3,ESI

//  t1:= e + (((b shr 6) or (b shl 26)) xor ((b shr 11) or (b shl 21)) xor
//      ((b shr 25) or (b shl 7))) + ((b and c) xor (not b and d)) + $53380d13 + W[3];

        MOV     EAX,R9D
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,R10D
        NOT     EAX
        AND     EAX,R11D
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$53380d13
        ADD     EBX,R12D

//  t2:= (((f shr 2) or (f shl 30)) xor ((f shr 13) or (f shl 19)) xor
//      ((f shr 22) xor (f shl 10))) + ((f and g) xor (f and h) xor (g and h));

        MOV     EAX,R13D
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,R14D
        MOV     EBP,R15D
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  e:= t1 + t2;
//  a:= a + t1;

        ADD     R8D,EBX
        ADD     EAX,EBX
        MOV     R12D,EAX

//  W[4]:= (((W[2] shr 17) or (W[2] shl 15)) xor
//          ((W[2] shr 19) or (W[2] shl 13)) xor (W[2] shr 10)) + W[13] +
//         (((W[5] shr 7) or (W[5] shl 25)) xor
//          ((W[5] shr 18) or (W[5] shl 14)) xor (W[5] shr 3)) + W[4];

        MOV     ESI,[RDI].W2
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[RDI].W5
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[RDI].W13
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[RDI].W4
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [RDI].W4,ESI

//  t1:= d + (((a shr 6) or (a shl 26)) xor ((a shr 11) or (a shl 21)) xor
//      ((a shr 25) or (a shl 7))) + ((a and b) xor (not a and c)) + $650a7354 + W[4];

        MOV     EAX,R8D
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,R9D
        NOT     EAX
        AND     EAX,R10D
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$650a7354
        ADD     EBX,R11D

//  t2:= (((e shr 2) or (e shl 30)) xor ((e shr 13) or (e shl 19)) xor
//      ((e shr 22) xor (e shl 10))) + ((e and f) xor (e and g) xor (f and g));

        MOV     EAX,R12D
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,R13D
        MOV     EBP,R14D
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  d:= t1 + t2;
//  h:= h + t1;

        ADD     R15D,EBX
        ADD     EAX,EBX
        MOV     R11D,EAX

//  W[5]:= (((W[3] shr 17) or (W[3] shl 15)) xor
//          ((W[3] shr 19) or (W[3] shl 13)) xor (W[3] shr 10)) + W[14] +
//         (((W[6] shr 7) or (W[6] shl 25)) xor
//          ((W[6] shr 18) or (W[6] shl 14)) xor (W[6] shr 3)) + W[5];

        MOV     ESI,[RDI].W3
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[RDI].W6
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[RDI].W14
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[RDI].W5
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [RDI].W5,ESI

//  t1:= c + (((h shr 6) or (h shl 26)) xor ((h shr 11) or (h shl 21)) xor
//      ((h shr 25) or (h shl 7))) + ((h and a) xor (not h and b)) + $766a0abb + W[5];

        MOV     EAX,R15D
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,R8D
        NOT     EAX
        AND     EAX,R9D
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$766a0abb
        ADD     EBX,R10D

//  t2:= (((d shr 2) or (d shl 30)) xor ((d shr 13) or (d shl 19)) xor
//      ((d shr 22) xor (d shl 10))) + ((d and e) xor (d and f) xor (e and f));

        MOV     EAX,R11D
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,R12D
        MOV     EBP,R13D
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  c:= t1 + t2;
//  g:= g + t1;

        ADD     R14D,EBX
        ADD     EAX,EBX
        MOV     R10D,EAX

//  W[6]:= (((W[4] shr 17) or (W[4] shl 15)) xor
//          ((W[4] shr 19) or (W[4] shl 13)) xor (W[4] shr 10)) + W[15] +
//         (((W[7] shr 7) or (W[7] shl 25)) xor
//          ((W[7] shr 18) or (W[7] shl 14)) xor (W[7] shr 3)) + W[6];

        MOV     ESI,[RDI].W4
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[RDI].W7
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[RDI].W15
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[RDI].W6
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [RDI].W6,ESI

//  t1:= b + (((g shr 6) or (g shl 26)) xor ((g shr 11) or (g shl 21)) xor
//      ((g shr 25) or (g shl 7))) + ((g and h) xor (not g and a)) + $81c2c92e + W[6];

        MOV     EAX,R14D
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,R15D
        NOT     EAX
        AND     EAX,R8D
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$81c2c92e
        ADD     EBX,R9D

//  t2:= (((c shr 2) or (c shl 30)) xor ((c shr 13) or (c shl 19)) xor
//      ((c shr 22) xor (c shl 10))) + ((c and d) xor (c and e) xor (d and e));

        MOV     EAX,R10D
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,R11D
        MOV     EBP,R12D
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  b:= t1 + t2;
//  f:= f + t1;

        ADD     R13D,EBX
        ADD     EAX,EBX
        MOV     R9D,EAX

//  W[7]:= (((W[5] shr 17) or (W[5] shl 15)) xor
//          ((W[5] shr 19) or (W[5] shl 13)) xor (W[5] shr 10)) + W[0] +
//         (((W[8] shr 7) or (W[8] shl 25)) xor
//          ((W[8] shr 18) or (W[8] shl 14)) xor (W[8] shr 3)) + W[7];

        MOV     ESI,[RDI].W5
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[RDI].W8
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[RDI].W0
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[RDI].W7
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [RDI].W7,ESI

//  t1:= a + (((f shr 6) or (f shl 26)) xor ((f shr 11) or (f shl 21)) xor
//      ((f shr 25) or (f shl 7))) + ((f and g) xor (not f and h)) + $92722c85 + W[7];

        MOV     EAX,R13D
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,R14D
        NOT     EAX
        AND     EAX,R15D
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$92722c85
        ADD     EBX,R8D

//  t2:= (((b shr 2) or (b shl 30)) xor ((b shr 13) or (b shl 19)) xor
//      ((b shr 22) xor (b shl 10))) + ((b and c) xor (b and d) xor (c and d));

        MOV     EAX,R9D
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,R10D
        MOV     EBP,R11D
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  a:= t1 + t2;
//  e:= e + t1;

        ADD     R12D,EBX
        ADD     EAX,EBX
        MOV     R8D,EAX

//  W[8]:= (((W[6] shr 17) or (W[6] shl 15)) xor
//          ((W[6] shr 19) or (W[6] shl 13)) xor (W[6] shr 10)) + W[1] +
//         (((W[9] shr 7) or (W[9] shl 25)) xor
//          ((W[9] shr 18) or (W[9] shl 14)) xor (W[9] shr 3)) + W[8];

        MOV     ESI,[RDI].W6
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[RDI].W9
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[RDI].W1
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[RDI].W8
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [RDI].W8,ESI

//  t1:= h + (((e shr 6) or (e shl 26)) xor ((e shr 11) or (e shl 21)) xor
//      ((e shr 25) or (e shl 7))) + ((e and f) xor (not e and g)) + $a2bfe8a1 + W[8];

        MOV     EAX,R12D
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,R13D
        NOT     EAX
        AND     EAX,R14D
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$a2bfe8a1
        ADD     EBX,R15D

//  t2:= (((a shr 2) or (a shl 30)) xor ((a shr 13) or (a shl 19)) xor
//      ((a shr 22) xor (a shl 10))) + ((a and b) xor (a and c) xor (b and c));

        MOV     EAX,R8D
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,R9D
        MOV     EBP,R10D
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  h:= t1 + t2;
//  d:= d + t1;

        ADD     R11D,EBX
        ADD     EAX,EBX
        MOV     R15D,EAX

//  W[9]:= (((W[7] shr 17) or (W[7] shl 15)) xor
//          ((W[7] shr 19) or (W[7] shl 13)) xor (W[7] shr 10)) + W[2] +
//         (((W[10] shr 7) or (W[10] shl 25)) xor
//          ((W[10] shr 18) or (W[10] shl 14)) xor (W[10] shr 3)) + W[9];

        MOV     ESI,[RDI].W7
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[RDI].W10
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[RDI].W2
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[RDI].W9
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [RDI].W9,ESI

//  t1:= g + (((d shr 6) or (d shl 26)) xor ((d shr 11) or (d shl 21)) xor
//      ((d shr 25) or (d shl 7))) + ((d and e) xor (not d and f)) + $a81a664b + W[9];

        MOV     EAX,R11D
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,R12D
        NOT     EAX
        AND     EAX,R13D
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$a81a664b
        ADD     EBX,R14D

//  t2:= (((h shr 2) or (h shl 30)) xor ((h shr 13) or (h shl 19)) xor
//      ((h shr 22) xor (h shl 10))) + ((h and a) xor (h and b) xor (a and b));

        MOV     EAX,R15D
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,R8D
        MOV     EBP,R9D
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  g:= t1 + t2;
//  c:= c + t1;

        ADD     R10D,EBX
        ADD     EAX,EBX
        MOV     R14D,EAX

//  W[10]:= (((W[8] shr 17) or (W[8] shl 15)) xor
//           ((W[8] shr 19) or (W[8] shl 13)) xor (W[8] shr 10)) + W[3] +
//          (((W[11] shr 7) or (W[11] shl 25)) xor
//           ((W[11] shr 18) or (W[11] shl 14)) xor (W[11] shr 3)) + W[10];

        MOV     ESI,[RDI].W8
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[RDI].W11
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[RDI].W3
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[RDI].W10
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [RDI].W10,ESI

//  t1:= f + (((c shr 6) or (c shl 26)) xor ((c shr 11) or (c shl 21)) xor
//      ((c shr 25) or (c shl 7))) + ((c and d) xor (not c and e)) + $c24b8b70 + W[10];

        MOV     EAX,R10D
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,R11D
        NOT     EAX
        AND     EAX,R12D
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$c24b8b70
        ADD     EBX,R13D

//  t2:= (((g shr 2) or (g shl 30)) xor ((g shr 13) or (g shl 19)) xor
//      ((g shr 22) xor (g shl 10))) + ((g and h) xor (g and a) xor (h and a));

        MOV     EAX,R14D
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,R15D
        MOV     EBP,R8D
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  f:= t1 + t2;
//  b:= b + t1;

        ADD     R9D,EBX
        ADD     EAX,EBX
        MOV     R13D,EAX

//  W[11]:= (((W[9] shr 17) or (W[9] shl 15)) xor
//           ((W[9] shr 19) or (W[9] shl 13)) xor (W[9] shr 10)) + W[4] +
//          (((W[12] shr 7) or (W[12] shl 25)) xor
//           ((W[12] shr 18) or (W[12] shl 14)) xor (W[12] shr 3)) + W[11];

        MOV     ESI,[RDI].W9
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[RDI].W12
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[RDI].W4
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[RDI].W11
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [RDI].W11,ESI

//  t1:= e + (((b shr 6) or (b shl 26)) xor ((b shr 11) or (b shl 21)) xor
//      ((b shr 25) or (b shl 7))) + ((b and c) xor (not b and d)) + $c76c51a3 + W[11];

        MOV     EAX,R9D
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,R10D
        NOT     EAX
        AND     EAX,R11D
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$c76c51a3
        ADD     EBX,R12D

//  t2:= (((f shr 2) or (f shl 30)) xor ((f shr 13) or (f shl 19)) xor
//      ((f shr 22) xor (f shl 10))) + ((f and g) xor (f and h) xor (g and h));

        MOV     EAX,R13D
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,R14D
        MOV     EBP,R15D
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  e:= t1 + t2;
//  a:= a + t1;

        ADD     R8D,EBX
        ADD     EAX,EBX
        MOV     R12D,EAX

//  W[12]:= (((W[10] shr 17) or (W[10] shl 15)) xor
//           ((W[10] shr 19) or (W[10] shl 13)) xor (W[10] shr 10)) + W[5] +
//          (((W[13] shr 7) or (W[13] shl 25)) xor
//           ((W[13] shr 18) or (W[13] shl 14)) xor (W[13] shr 3)) + W[12];

        MOV     ESI,[RDI].W10
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[RDI].W13
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[RDI].W5
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[RDI].W12
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [RDI].W12,ESI

//  t1:= d + (((a shr 6) or (a shl 26)) xor ((a shr 11) or (a shl 21)) xor
//      ((a shr 25) or (a shl 7))) + ((a and b) xor (not a and c)) + $d192e819 + W[12];

        MOV     EAX,R8D
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,R9D
        NOT     EAX
        AND     EAX,R10D
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$d192e819
        ADD     EBX,R11D

//  t2:= (((e shr 2) or (e shl 30)) xor ((e shr 13) or (e shl 19)) xor
//      ((e shr 22) xor (e shl 10))) + ((e and f) xor (e and g) xor (f and g));

        MOV     EAX,R12D
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,R13D
        MOV     EBP,R14D
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  d:= t1 + t2;
//  h:= h + t1;

        ADD     R15D,EBX
        ADD     EAX,EBX
        MOV     R11D,EAX

//  W[13]:= (((W[11] shr 17) or (W[11] shl 15)) xor
//           ((W[11] shr 19) or (W[11] shl 13)) xor (W[11] shr 10)) + W[6] +
//          (((W[14] shr 7) or (W[14] shl 25)) xor
//           ((W[14] shr 18) or (W[14] shl 14)) xor (W[14] shr 3)) + W[13];

        MOV     ESI,[RDI].W11
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[RDI].W14
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[RDI].W6
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[RDI].W13
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [RDI].W13,ESI

//  t1:= c + (((h shr 6) or (h shl 26)) xor ((h shr 11) or (h shl 21)) xor
//      ((h shr 25) or (h shl 7))) + ((h and a) xor (not h and b)) + $d6990624 + W[13];

        MOV     EAX,R15D
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,R8D
        NOT     EAX
        AND     EAX,R9D
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$d6990624
        ADD     EBX,R10D

//  t2:= (((d shr 2) or (d shl 30)) xor ((d shr 13) or (d shl 19)) xor
//      ((d shr 22) xor (d shl 10))) + ((d and e) xor (d and f) xor (e and f));

        MOV     EAX,R11D
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,R12D
        MOV     EBP,R13D
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  c:= t1 + t2;
//  g:= g + t1;

        ADD     R14D,EBX
        ADD     EAX,EBX
        MOV     R10D,EAX

//  W[14]:= (((W[12] shr 17) or (W[12] shl 15)) xor
//           ((W[12] shr 19) or (W[12] shl 13)) xor (W[12] shr 10)) + W[7] +
//          (((W[15] shr 7) or (W[15] shl 25)) xor
//           ((W[15] shr 18) or (W[15] shl 14)) xor (W[15] shr 3)) + W[14];

        MOV     ESI,[RDI].W12
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[RDI].W15
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[RDI].W7
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[RDI].W14
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [RDI].W14,ESI

//  t1:= b + (((g shr 6) or (g shl 26)) xor ((g shr 11) or (g shl 21)) xor
//      ((g shr 25) or (g shl 7))) + ((g and h) xor (not g and a)) + $f40e3585 + W[14];

        MOV     EAX,R14D
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,R15D
        NOT     EAX
        AND     EAX,R8D
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$f40e3585
        ADD     EBX,R9D

//  t2:= (((c shr 2) or (c shl 30)) xor ((c shr 13) or (c shl 19)) xor
//      ((c shr 22) xor (c shl 10))) + ((c and d) xor (c and e) xor (d and e));

        MOV     EAX,R10D
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,R11D
        MOV     EBP,R12D
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  b:= t1 + t2;
//  f:= f + t1;

        ADD     R13D,EBX
        ADD     EAX,EBX
        MOV     R9D,EAX

//  W[15]:= (((W[13] shr 17) or (W[13] shl 15)) xor
//           ((W[13] shr 19) or (W[13] shl 13)) xor (W[13] shr 10)) + W[8] +
//          (((W[0] shr 7) or (W[0] shl 25)) xor
//           ((W[0] shr 18) or (W[0] shl 14)) xor (W[0] shr 3)) + W[15];

        MOV     ESI,[RDI].W13
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[RDI].W0
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[RDI].W8
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[RDI].W15
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [RDI].W15,ESI

//  t1:= a + (((f shr 6) or (f shl 26)) xor ((f shr 11) or (f shl 21)) xor
//      ((f shr 25) or (f shl 7))) + ((f and g) xor (not f and h)) + $106aa070 + W[15];

        MOV     EAX,R13D
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,R14D
        NOT     EAX
        AND     EAX,R15D
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$106aa070
        ADD     EBX,R8D

//  t2:= (((b shr 2) or (b shl 30)) xor ((b shr 13) or (b shl 19)) xor
//      ((b shr 22) xor (b shl 10))) + ((b and c) xor (b and d) xor (c and d));

        MOV     EAX,R9D
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,R10D
        MOV     EBP,R11D
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  a:= t1 + t2;
//  e:= e + t1;

        ADD     R12D,EBX
        ADD     EAX,EBX
        MOV     R8D,EAX

//  W[0]:= (((W[14] shr 17) or (W[14] shl 15)) xor
//           ((W[14] shr 19) or (W[14] shl 13)) xor (W[14] shr 10)) + W[9] +
//         (((W[1] shr 7) or (W[1] shl 25)) xor
//          ((W[1] shr 18) or (W[1] shl 14)) xor (W[1] shr 3)) + W[0];

        MOV     ESI,[RDI].W14
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[RDI].W1
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[RDI].W9
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[RDI].W0
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [RDI].W0,ESI

//  t1:= h + (((e shr 6) or (e shl 26)) xor ((e shr 11) or (e shl 21)) xor
//      ((e shr 25) or (e shl 7))) + ((e and f) xor (not e and g)) + $19a4c116 + W[0];

        MOV     EAX,R12D
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,R13D
        NOT     EAX
        AND     EAX,R14D
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$19a4c116
        ADD     EBX,R15D

//  t2:= (((a shr 2) or (a shl 30)) xor ((a shr 13) or (a shl 19)) xor
//      ((a shr 22) xor (a shl 10))) + ((a and b) xor (a and c) xor (b and c));

        MOV     EAX,R8D
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,R9D
        MOV     EBP,R10D
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  h:= t1 + t2;
//  d:= d + t1;

        ADD     R11D,EBX
        ADD     EAX,EBX
        MOV     R15D,EAX

//  W[1]:= (((W[15] shr 17) or (W[15] shl 15)) xor
//          ((W[15] shr 19) or (W[15] shl 13)) xor (W[15] shr 10)) + W[10] +
//         (((W[2] shr 7) or (W[2] shl 25)) xor
//          ((W[2] shr 18) or (W[2] shl 14)) xor (W[2] shr 3)) + W[1];

        MOV     ESI,[RDI].W15
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[RDI].W2
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[RDI].W10
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[RDI].W1
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [RDI].W1,ESI

//  t1:= g + (((d shr 6) or (d shl 26)) xor ((d shr 11) or (d shl 21)) xor
//      ((d shr 25) or (d shl 7))) + ((d and e) xor (not d and f)) + $1e376c08 + W[1];

        MOV     EAX,R11D
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,R12D
        NOT     EAX
        AND     EAX,R13D
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$1e376c08
        ADD     EBX,R14D

//  t2:= (((h shr 2) or (h shl 30)) xor ((h shr 13) or (h shl 19)) xor
//      ((h shr 22) xor (h shl 10))) + ((h and a) xor (h and b) xor (a and b));

        MOV     EAX,R15D
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,R8D
        MOV     EBP,R9D
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  g:= t1 + t2;
//  c:= c + t1;

        ADD     R10D,EBX
        ADD     EAX,EBX
        MOV     R14D,EAX

//  W[2]:= (((W[0] shr 17) or (W[0] shl 15)) xor
//          ((W[0] shr 19) or (W[0] shl 13)) xor (W[0] shr 10)) + W[11] +
//         (((W[3] shr 7) or (W[3] shl 25)) xor
//          ((W[3] shr 18) or (W[3] shl 14)) xor (W[3] shr 3)) + W[2];

        MOV     ESI,[RDI].W0
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[RDI].W3
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[RDI].W11
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[RDI].W2
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [RDI].W2,ESI

//  t1:= f + (((c shr 6) or (c shl 26)) xor ((c shr 11) or (c shl 21)) xor
//      ((c shr 25) or (c shl 7))) + ((c and d) xor (not c and e)) + $2748774c + W[2];

        MOV     EAX,R10D
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,R11D
        NOT     EAX
        AND     EAX,R12D
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$2748774c
        ADD     EBX,R13D

//  t2:= (((g shr 2) or (g shl 30)) xor ((g shr 13) or (g shl 19)) xor
//      ((g shr 22) xor (g shl 10))) + ((g and h) xor (g and a) xor (h and a));

        MOV     EAX,R14D
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,R15D
        MOV     EBP,R8D
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  f:= t1 + t2;
//  b:= b + t1;

        ADD     R9D,EBX
        ADD     EAX,EBX
        MOV     R13D,EAX

//  W[3]:= (((W[1] shr 17) or (W[1] shl 15)) xor
//          ((W[1] shr 19) or (W[1] shl 13)) xor (W[1] shr 10)) + W[12] +
//         (((W[4] shr 7) or (W[4] shl 25)) xor
//          ((W[4] shr 18) or (W[4] shl 14)) xor (W[4] shr 3)) + W[3];

        MOV     ESI,[RDI].W1
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[RDI].W4
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[RDI].W12
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[RDI].W3
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [RDI].W3,ESI

//  t1:= e + (((b shr 6) or (b shl 26)) xor ((b shr 11) or (b shl 21)) xor
//      ((b shr 25) or (b shl 7))) + ((b and c) xor (not b and d)) + $34b0bcb5 + W[3];

        MOV     EAX,R9D
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,R10D
        NOT     EAX
        AND     EAX,R11D
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$34b0bcb5
        ADD     EBX,R12D

//  t2:= (((f shr 2) or (f shl 30)) xor ((f shr 13) or (f shl 19)) xor
//      ((f shr 22) xor (f shl 10))) + ((f and g) xor (f and h) xor (g and h));

        MOV     EAX,R13D
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,R14D
        MOV     EBP,R15D
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  e:= t1 + t2;
//  a:= a + t1;

        ADD     R8D,EBX
        ADD     EAX,EBX
        MOV     R12D,EAX

//  W[4]:= (((W[2] shr 17) or (W[2] shl 15)) xor
//          ((W[2] shr 19) or (W[2] shl 13)) xor (W[2] shr 10)) + W[13] +
//         (((W[5] shr 7) or (W[5] shl 25)) xor
//          ((W[5] shr 18) or (W[5] shl 14)) xor (W[5] shr 3)) + W[4];

        MOV     ESI,[RDI].W2
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[RDI].W5
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[RDI].W13
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[RDI].W4
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [RDI].W4,ESI

//  t1:= d + (((a shr 6) or (a shl 26)) xor ((a shr 11) or (a shl 21)) xor
//      ((a shr 25) or (a shl 7))) + ((a and b) xor (not a and c)) + $391c0cb3 + W[4];

        MOV     EAX,R8D
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,R9D
        NOT     EAX
        AND     EAX,R10D
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$391c0cb3
        ADD     EBX,R11D

//  t2:= (((e shr 2) or (e shl 30)) xor ((e shr 13) or (e shl 19)) xor
//      ((e shr 22) xor (e shl 10))) + ((e and f) xor (e and g) xor (f and g));

        MOV     EAX,R12D
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,R13D
        MOV     EBP,R14D
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  d:= t1 + t2;
//  h:= h + t1;

        ADD     R15D,EBX
        ADD     EAX,EBX
        MOV     R11D,EAX

//  W[5]:= (((W[3] shr 17) or (W[3] shl 15)) xor
//          ((W[3] shr 19) or (W[3] shl 13)) xor (W[3] shr 10)) + W[14] +
//         (((W[6] shr 7) or (W[6] shl 25)) xor
//          ((W[6] shr 18) or (W[6] shl 14)) xor (W[6] shr 3)) + W[5];

        MOV     ESI,[RDI].W3
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[RDI].W6
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[RDI].W14
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[RDI].W5
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [RDI].W5,ESI

//  t1:= c + (((h shr 6) or (h shl 26)) xor ((h shr 11) or (h shl 21)) xor
//      ((h shr 25) or (h shl 7))) + ((h and a) xor (not h and b)) + $4ed8aa4a + W[5];

        MOV     EAX,R15D
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,R8D
        NOT     EAX
        AND     EAX,R9D
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$4ed8aa4a
        ADD     EBX,R10D

//  t2:= (((d shr 2) or (d shl 30)) xor ((d shr 13) or (d shl 19)) xor
//      ((d shr 22) xor (d shl 10))) + ((d and e) xor (d and f) xor (e and f));

        MOV     EAX,R11D
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,R12D
        MOV     EBP,R13D
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  c:= t1 + t2;
//  g:= g + t1;

        ADD     R14D,EBX
        ADD     EAX,EBX
        MOV     R10D,EAX

//  W[6]:= (((W[4] shr 17) or (W[4] shl 15)) xor
//          ((W[4] shr 19) or (W[4] shl 13)) xor (W[4] shr 10)) + W[15] +
//         (((W[7] shr 7) or (W[7] shl 25)) xor
//          ((W[7] shr 18) or (W[7] shl 14)) xor (W[7] shr 3)) + W[6];

        MOV     ESI,[RDI].W4
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[RDI].W7
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[RDI].W15
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[RDI].W6
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [RDI].W6,ESI

//  t1:= b + (((g shr 6) or (g shl 26)) xor ((g shr 11) or (g shl 21)) xor
//      ((g shr 25) or (g shl 7))) + ((g and h) xor (not g and a)) + $5b9cca4f + W[6];

        MOV     EAX,R14D
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,R15D
        NOT     EAX
        AND     EAX,R8D
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$5b9cca4f
        ADD     EBX,R9D

//  t2:= (((c shr 2) or (c shl 30)) xor ((c shr 13) or (c shl 19)) xor
//      ((c shr 22) xor (c shl 10))) + ((c and d) xor (c and e) xor (d and e));

        MOV     EAX,R10D
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,R11D
        MOV     EBP,R12D
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  b:= t1 + t2;
//  f:= f + t1;

        ADD     R13D,EBX
        ADD     EAX,EBX
        MOV     R9D,EAX

//  W[7]:= (((W[5] shr 17) or (W[5] shl 15)) xor
//          ((W[5] shr 19) or (W[5] shl 13)) xor (W[5] shr 10)) + W[0] +
//         (((W[8] shr 7) or (W[8] shl 25)) xor
//          ((W[8] shr 18) or (W[8] shl 14)) xor (W[8] shr 3)) + W[7];

        MOV     ESI,[RDI].W5
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[RDI].W8
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[RDI].W0
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[RDI].W7
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [RDI].W7,ESI

//  t1:= a + (((f shr 6) or (f shl 26)) xor ((f shr 11) or (f shl 21)) xor
//      ((f shr 25) or (f shl 7))) + ((f and g) xor (not f and h)) + $682e6ff3 + W[7];

        MOV     EAX,R13D
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,R14D
        NOT     EAX
        AND     EAX,R15D
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$682e6ff3
        ADD     EBX,R8D

//  t2:= (((b shr 2) or (b shl 30)) xor ((b shr 13) or (b shl 19)) xor
//      ((b shr 22) xor (b shl 10))) + ((b and c) xor (b and d) xor (c and d));

        MOV     EAX,R9D
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,R10D
        MOV     EBP,R11D
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  a:= t1 + t2;
//  e:= e + t1;

        ADD     R12D,EBX
        ADD     EAX,EBX
        MOV     R8D,EAX

//  W[8]:= (((W[6] shr 17) or (W[6] shl 15)) xor
//          ((W[6] shr 19) or (W[6] shl 13)) xor (W[6] shr 10)) + W[1] +
//         (((W[9] shr 7) or (W[9] shl 25)) xor
//          ((W[9] shr 18) or (W[9] shl 14)) xor (W[9] shr 3)) + W[8];

        MOV     ESI,[RDI].W6
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[RDI].W9
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[RDI].W1
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[RDI].W8
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [RDI].W8,ESI

//  t1:= h + (((e shr 6) or (e shl 26)) xor ((e shr 11) or (e shl 21)) xor
//      ((e shr 25) or (e shl 7))) + ((e and f) xor (not e and g)) + $748f82ee + W[8];

        MOV     EAX,R12D
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,R13D
        NOT     EAX
        AND     EAX,R14D
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$748f82ee
        ADD     EBX,R15D

//  t2:= (((a shr 2) or (a shl 30)) xor ((a shr 13) or (a shl 19)) xor
//      ((a shr 22) xor (a shl 10))) + ((a and b) xor (a and c) xor (b and c));

        MOV     EAX,R8D
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,R9D
        MOV     EBP,R10D
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  h:= t1 + t2;
//  d:= d + t1;

        ADD     R11D,EBX
        ADD     EAX,EBX
        MOV     R15D,EAX

//  W[9]:= (((W[7] shr 17) or (W[7] shl 15)) xor
//          ((W[7] shr 19) or (W[7] shl 13)) xor (W[7] shr 10)) + W[2] +
//         (((W[10] shr 7) or (W[10] shl 25)) xor
//          ((W[10] shr 18) or (W[10] shl 14)) xor (W[10] shr 3)) + W[9];

        MOV     ESI,[RDI].W7
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[RDI].W10
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[RDI].W2
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[RDI].W9
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [RDI].W9,ESI

//  t1:= g + (((d shr 6) or (d shl 26)) xor ((d shr 11) or (d shl 21)) xor
//      ((d shr 25) or (d shl 7))) + ((d and e) xor (not d and f)) + $78a5636f + W[9];

        MOV     EAX,R11D
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,R12D
        NOT     EAX
        AND     EAX,R13D
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$78a5636f
        ADD     EBX,R14D

//  t2:= (((h shr 2) or (h shl 30)) xor ((h shr 13) or (h shl 19)) xor
//      ((h shr 22) xor (h shl 10))) + ((h and a) xor (h and b) xor (a and b));

        MOV     EAX,R15D
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,R8D
        MOV     EBP,R9D
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  g:= t1 + t2;
//  c:= c + t1;

        ADD     R10D,EBX
        ADD     EAX,EBX
        MOV     R14D,EAX

//  W[10]:= (((W[8] shr 17) or (W[8] shl 15)) xor
//           ((W[8] shr 19) or (W[8] shl 13)) xor (W[8] shr 10)) + W[3] +
//          (((W[11] shr 7) or (W[11] shl 25)) xor
//           ((W[11] shr 18) or (W[11] shl 14)) xor (W[11] shr 3)) + W[10];

        MOV     ESI,[RDI].W8
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[RDI].W11
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[RDI].W3
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[RDI].W10
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [RDI].W10,ESI

//  t1:= f + (((c shr 6) or (c shl 26)) xor ((c shr 11) or (c shl 21)) xor
//      ((c shr 25) or (c shl 7))) + ((c and d) xor (not c and e)) + $84c87814 + W[10];

        MOV     EAX,R10D
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,R11D
        NOT     EAX
        AND     EAX,R12D
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$84c87814
        ADD     EBX,R13D

//  t2:= (((g shr 2) or (g shl 30)) xor ((g shr 13) or (g shl 19)) xor
//      ((g shr 22) xor (g shl 10))) + ((g and h) xor (g and a) xor (h and a));

        MOV     EAX,R14D
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,R15D
        MOV     EBP,R8D
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  f:= t1 + t2;
//  b:= b + t1;

        ADD     R9D,EBX
        ADD     EAX,EBX
        MOV     R13D,EAX

//  W[11]:= (((W[9] shr 17) or (W[9] shl 15)) xor
//           ((W[9] shr 19) or (W[9] shl 13)) xor (W[9] shr 10)) + W[4] +
//          (((W[12] shr 7) or (W[12] shl 25)) xor
//           ((W[12] shr 18) or (W[12] shl 14)) xor (W[12] shr 3)) + W[11];

        MOV     ESI,[RDI].W9
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[RDI].W12
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[RDI].W4
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[RDI].W11
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [RDI].W11,ESI

//  t1:= e + (((b shr 6) or (b shl 26)) xor ((b shr 11) or (b shl 21)) xor
//      ((b shr 25) or (b shl 7))) + ((b and c) xor (not b and d)) + $8cc70208 + W[11];

        MOV     EAX,R9D
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,R10D
        NOT     EAX
        AND     EAX,R11D
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$8cc70208
        ADD     EBX,R12D

//  t2:= (((f shr 2) or (f shl 30)) xor ((f shr 13) or (f shl 19)) xor
//      ((f shr 22) xor (f shl 10))) + ((f and g) xor (f and h) xor (g and h));

        MOV     EAX,R13D
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,R14D
        MOV     EBP,R15D
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  e:= t1 + t2;
//  a:= a + t1;

        ADD     R8D,EBX
        ADD     EAX,EBX
        MOV     R12D,EAX

//  W[12]:= (((W[10] shr 17) or (W[10] shl 15)) xor
//           ((W[10] shr 19) or (W[10] shl 13)) xor (W[10] shr 10)) + W[5] +
//          (((W[13] shr 7) or (W[13] shl 25)) xor
//           ((W[13] shr 18) or (W[13] shl 14)) xor (W[13] shr 3)) + W[12];

        MOV     ESI,[RDI].W10
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[RDI].W13
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[RDI].W5
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[RDI].W12
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [RDI].W12,ESI

//  t1:= d + (((a shr 6) or (a shl 26)) xor ((a shr 11) or (a shl 21)) xor
//      ((a shr 25) or (a shl 7))) + ((a and b) xor (not a and c)) + $90befffa + W[12];

        MOV     EAX,R8D
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,R9D
        NOT     EAX
        AND     EAX,R10D
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$90befffa
        ADD     EBX,R11D

//  t2:= (((e shr 2) or (e shl 30)) xor ((e shr 13) or (e shl 19)) xor
//      ((e shr 22) xor (e shl 10))) + ((e and f) xor (e and g) xor (f and g));

        MOV     EAX,R12D
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,R13D
        MOV     EBP,R14D
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  d:= t1 + t2;
//  h:= h + t1;

        ADD     R15D,EBX
        ADD     EAX,EBX
        MOV     R11D,EAX

//  W[13]:= (((W[11] shr 17) or (W[11] shl 15)) xor
//           ((W[11] shr 19) or (W[11] shl 13)) xor (W[11] shr 10)) + W[6] +
//          (((W[14] shr 7) or (W[14] shl 25)) xor
//           ((W[14] shr 18) or (W[14] shl 14)) xor (W[14] shr 3)) + W[13];

        MOV     ESI,[RDI].W11
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[RDI].W14
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[RDI].W6
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[RDI].W13
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [RDI].W13,ESI

//  t1:= c + (((h shr 6) or (h shl 26)) xor ((h shr 11) or (h shl 21)) xor
//      ((h shr 25) or (h shl 7))) + ((h and a) xor (not h and b)) + $a4506ceb + W[13];

        MOV     EAX,R15D
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,R8D
        NOT     EAX
        AND     EAX,R9D
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$a4506ceb
        ADD     EBX,R10D

//  t2:= (((d shr 2) or (d shl 30)) xor ((d shr 13) or (d shl 19)) xor
//      ((d shr 22) xor (d shl 10))) + ((d and e) xor (d and f) xor (e and f));

        MOV     EAX,R11D
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,R12D
        MOV     EBP,R13D
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  c:= t1 + t2;
//  g:= g + t1;

        ADD     R14D,EBX
        ADD     EAX,EBX
        MOV     R10D,EAX

//  W[14]:= (((W[12] shr 17) or (W[12] shl 15)) xor
//           ((W[12] shr 19) or (W[12] shl 13)) xor (W[12] shr 10)) + W[7] +
//          (((W[15] shr 7) or (W[15] shl 25)) xor
//           ((W[15] shr 18) or (W[15] shl 14)) xor (W[15] shr 3)) + W[14];

        MOV     ESI,[RDI].W12
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[RDI].W15
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[RDI].W7
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[RDI].W14
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [RDI].W14,ESI

//  t1:= b + (((g shr 6) or (g shl 26)) xor ((g shr 11) or (g shl 21)) xor
//      ((g shr 25) or (g shl 7))) + ((g and h) xor (not g and a)) + $bef9a3f7 + W[14];

        MOV     EAX,R14D
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,R15D
        NOT     EAX
        AND     EAX,R8D
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$bef9a3f7
        ADD     EBX,R9D

//  t2:= (((c shr 2) or (c shl 30)) xor ((c shr 13) or (c shl 19)) xor
//      ((c shr 22) xor (c shl 10))) + ((c and d) xor (c and e) xor (d and e));

        MOV     EAX,R10D
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,R11D
        MOV     EBP,R12D
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  b:= t1 + t2;
//  f:= f + t1;

        ADD     R13D,EBX
        ADD     EAX,EBX
        MOV     R9D,EAX

//  W[15]:= (((W[13] shr 17) or (W[13] shl 15)) xor
//           ((W[13] shr 19) or (W[13] shl 13)) xor (W[13] shr 10)) + W[8] +
//          (((W[0] shr 7) or (W[0] shl 25)) xor
//           ((W[0] shr 18) or (W[0] shl 14)) xor (W[0] shr 3)) + W[15];

        MOV     ESI,[RDI].W13
        MOV     EAX,ESI
        MOV     EBX,ESI
        ROL     ESI,15
        ROL     EAX,13
        SHR     EBX,10
        XOR     ESI,EAX
        XOR     ESI,EBX
        MOV     EAX,[RDI].W0
        MOV     EBX,EAX
        MOV     ECX,EAX
        ADD     ESI,[RDI].W8
        ROR     EAX,7
        ROL     EBX,14
        SHR     ECX,3
        ADD     ESI,[RDI].W15
        XOR     EAX,EBX
        XOR     EAX,ECX
        ADD     ESI,EAX
        MOV     [RDI].W15,ESI

//  t1:= a + (((f shr 6) or (f shl 26)) xor ((f shr 11) or (f shl 21)) xor
//      ((f shr 25) or (f shl 7))) + ((f and g) xor (not f and h)) + $c67178f2 + W[15];

        MOV     EAX,R13D
        MOV     EBX,EAX
        MOV     ECX,EAX
        MOV     EDX,EAX
        ROR     EBX,6
        ROR     ECX,11
        ROL     EDX,7
        XOR     EBX,ECX
        XOR     EBX,EDX
        MOV     ECX,EAX
        AND     ECX,R14D
        NOT     EAX
        AND     EAX,R15D
        XOR     EAX,ECX
        ADD     EBX,ESI
        ADD     EBX,EAX
        ADD     EBX,$c67178f2
        ADD     EBX,R8D

//  t2:= (((b shr 2) or (b shl 30)) xor ((b shr 13) or (b shl 19)) xor
//      ((b shr 22) xor (b shl 10))) + ((b and c) xor (b and d) xor (c and d));

        MOV     EAX,R9D
        MOV     ECX,EAX
        MOV     EDX,EAX
        MOV     ESI,EAX
        ROR     ECX,2
        ROR     EDX,13
        ROL     ESI,10
        XOR     ECX,EDX
        XOR     ECX,ESI
        MOV     EDX,EAX
        MOV     ESI,R10D
        MOV     EBP,R11D
        AND     EAX,ESI
        AND     EDX,EBP
        AND     ESI,EBP
        XOR     EAX,EDX
        XOR     EAX,ESI
        ADD     EAX,ECX

//  a:= t1 + t2;
//  e:= e + t1;

        ADD     R12D,EBX
        ADD     EAX,EBX
        MOV     R8D,EAX

        ADD     [RDI].DigestH,R15D
        ADD     [RDI].DigestG,R14D
        ADD     [RDI].DigestF,R13D
        ADD     [RDI].DigestE,R12D
        ADD     [RDI].DigestD,R11D
        ADD     [RDI].DigestC,R10D
        ADD     [RDI].DigestB,R9D
        ADD     [RDI].DigestA,R8D

        XOR     RAX,RAX
        MOV     [RDI].W0,RAX
        MOV     [RDI].W2,RAX
        MOV     [RDI].W4,RAX
        MOV     [RDI].W6,RAX
        MOV     [RDI].W8,RAX
        MOV     [RDI].W10,RAX
        MOV     [RDI].W12,RAX
        MOV     [RDI].W14,RAX

        ADD     RSP,8
        POP     R15
        POP     R14
        POP     R13
        POP     R12
        POP     RBP
        POP     RBX
        POP     RDI
        POP     RSI
end;
{$ENDIF}

class procedure TSHA256Alg.Init(Inst: PSHA256Alg);
begin
  Inst.FData.Digest[0]:= $6a09e667;
  Inst.FData.Digest[1]:= $bb67ae85;
  Inst.FData.Digest[2]:= $3c6ef372;
  Inst.FData.Digest[3]:= $a54ff53a;
  Inst.FData.Digest[4]:= $510e527f;
  Inst.FData.Digest[5]:= $9b05688c;
  Inst.FData.Digest[6]:= $1f83d9ab;
  Inst.FData.Digest[7]:= $5be0cd19;

  FillChar(Inst.FData.Block, SizeOf(Inst.FData.Block), 0);
  Inst.FData.Count:= 0;
end;

class procedure TSHA256Alg.Update(Inst: PSHA256Alg; Data: PByte; DataSize: Cardinal);
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

class procedure TSHA256Alg.Done(Inst: PSHA256Alg; PDigest: PSHA256Digest);
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
  Inst.FData.Digest[5]:= Swap32(Inst.FData.Digest[5]);
  Inst.FData.Digest[6]:= Swap32(Inst.FData.Digest[6]);
  Inst.FData.Digest[7]:= Swap32(Inst.FData.Digest[7]);

  Move(Inst.FData.Digest, PDigest^, SizeOf(TSHA256Digest));

  Init(Inst);
end;

class function TSHA256Alg.GetDigestSize(Inst: PSHA256Alg): Integer;
begin
  Result:= SizeOf(TSHA256Digest);
end;

class function TSHA256Alg.GetBlockSize(Inst: PSHA256Alg): Integer;
begin
  Result:= 64;
end;

class function TSHA256Alg.Duplicate(Inst: PSHA256Alg; var DupInst: PSHA256Alg): TF_RESULT;
begin
  Result:= GetSHA256Algorithm(DupInst);
  if Result = TF_S_OK then
    DupInst.FData:= Inst.FData;
end;

{ TSHA224Alg }

class procedure TSHA224Alg.Init(Inst: PSHA224Alg);
begin
  Inst.FData.Digest[0]:= $c1059ed8;
  Inst.FData.Digest[1]:= $367cd507;
  Inst.FData.Digest[2]:= $3070dd17;
  Inst.FData.Digest[3]:= $f70e5939;
  Inst.FData.Digest[4]:= $ffc00b31;
  Inst.FData.Digest[5]:= $68581511;
  Inst.FData.Digest[6]:= $64f98fa7;
  Inst.FData.Digest[7]:= $befa4fa4;

  FillChar(Inst.FData.Block, SizeOf(Inst.FData.Block), 0);
  Inst.FData.Count:= 0;
end;

class procedure TSHA224Alg.Done(Inst: PSHA224Alg; PDigest: PSHA224Digest);
var
  Ofs: Cardinal;

begin
  Ofs:= Cardinal(Inst.FData.Count) and $3F;
  Inst.FData.Block[Ofs]:= $80;
  if Ofs >= 56 then
    PSHA256Alg(Inst).Compress;

  Inst.FData.Count:= Inst.FData.Count shl 3;
  PUInt32(@Inst.FData.Block[56])^:= Swap32(UInt32(Inst.FData.Count shr 32));
  PUInt32(@Inst.FData.Block[60])^:= Swap32(UInt32(Inst.FData.Count));
  PSHA256Alg(Inst).Compress;

  Inst.FData.Digest[0]:= Swap32(Inst.FData.Digest[0]);
  Inst.FData.Digest[1]:= Swap32(Inst.FData.Digest[1]);
  Inst.FData.Digest[2]:= Swap32(Inst.FData.Digest[2]);
  Inst.FData.Digest[3]:= Swap32(Inst.FData.Digest[3]);
  Inst.FData.Digest[4]:= Swap32(Inst.FData.Digest[4]);
  Inst.FData.Digest[5]:= Swap32(Inst.FData.Digest[5]);
  Inst.FData.Digest[6]:= Swap32(Inst.FData.Digest[6]);

  Move(Inst.FData.Digest, PDigest^, SizeOf(TSHA224Digest));

  Init(Inst);
end;

class function TSHA224Alg.GetDigestSize(Inst: PSHA256Alg): Integer;
begin
  Result:= SizeOf(TSHA224Digest);
end;

end.
