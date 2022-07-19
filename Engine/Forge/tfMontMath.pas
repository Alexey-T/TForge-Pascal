{ *********************************************************** }
{ *                     TForge Library                      * }
{ *       Copyright (c) Sergey Kasandrov 1997, 2016         * }
{ * ------------------------------------------------------- * }
{ *   # Arithmetic in Montgomery form                       * }
{ *   # all numbers should be in range [0..N-1]             * }
{ *   # Reduce converts from Montgomery form                * }
{ *********************************************************** }

unit tfMontMath;

{$I TFL.inc}

interface

uses
  tfLimbs, tfTypes, tfNumbers;

type
  PMontInstance = ^TMontInstance;
  TMontInstance = record
    FVTable: Pointer;
    FRefCount: Integer;
    FShift: Integer;        // number of bits in R; R = 2^FShift; ! don't move !
    FN: PBigNumber;         // modulus
    FRR: PBigNumber;        // R^2 mod N, to convert to montgomery form
    FNi: PBigNumber;        // R*Ri - N*Ni = 1

//    class function Release(Inst: PMontInstance): Integer; stdcall; static;

    class procedure Burn(Inst: PMontInstance);
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF}static;
    class function Reduce(Inst: PMontInstance; A: PBigNumber; var T: PBigNumber): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF}static;
    class function Convert(Inst: PMontInstance; A: PBigNumber; var T: PBigNumber): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF}static;
    class function AddNumbers(Inst: PMontInstance; A, B: PBigNumber; var T: PBigNumber): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF}static;
    class function SubNumbers(Inst: PMontInstance; A, B: PBigNumber; var T: PBigNumber): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF}static;
    class function MulNumbers(Inst: PMontInstance; A, B: PBigNumber; var T: PBigNumber): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF}static;
    class function ModMulNumbers(Inst: PMontInstance; A, B: PBigNumber; var T: PBigNumber): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF}static;
    class function ModPowNumber(Inst: PMontInstance; BaseValue, ExpValue: PBigNumber; var T: PBigNumber): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF}static;
    class function ModPowLimb(Inst: PMontInstance; BaseValue: PBigNumber; ExpValue: TLimb; var T: PBigNumber): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF}static;
    class function GetRModulus(Inst: PMontInstance; var T: PBigNumber): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF}static;
  end;

function GetMontInstance(var P: PMontInstance; Modulus: PBigNumber): TF_RESULT;

implementation

uses
  tfRecords;

const
  MontVTable: array[0..12] of Pointer = (
    @TForgeInstance.QueryIntf,
    @TForgeInstance.Addref,
    @TForgeInstance.SafeRelease,
//    @TMontInstance.Release,

    @TMontInstance.Burn,
    @TMontInstance.Reduce,
    @TMontInstance.Convert,
    @TMontInstance.AddNumbers,
    @TMontInstance.SubNumbers,
    @TMontInstance.MulNumbers,
    @TMontInstance.ModMulNumbers,
    @TMontInstance.ModPowNumber,
    @TMontInstance.ModPowLimb,
    @TMontInstance.GetRModulus
  );


// Ni*N = -1 mod 2^Power
function GetNi(N: PBigNumber; Power: Cardinal; var Ni: PBigNumber): TF_RESULT;
var
  TmpNi, TmpProd, TmpMask, TmpPowerOfTwo: PBigNumber;
  Count: Cardinal;

begin
  if Power <= 1 then begin
    Result:= TF_E_INVALIDARG;
    Exit;
  end;

// TmpNi:= 0(1) is solution for Power = 1;
  Result:= TBigNumber.AllocNumber(TmpNi, 1);
  if Result <> TF_S_OK then Exit;
  if Odd(N.FLimbs[0]) then
    TmpNi.FLimbs[0]:= 1;

// TmpMask:= 1
  Result:= TBigNumber.AllocNumber(TmpMask, 1);
  if Result <> TF_S_OK then begin
    tfFreeInstance(TmpNi);
    Exit;
  end;
  TmpMask.FLimbs[0]:= 1;

  Count:= 1;
  TmpProd:= nil;
  TmpPowerOfTwo:= nil;
  repeat

// TmpMask:= TmpMask shl 1 or 1;
    Result:= TBigNumber.ShlNumber(TmpMask, 1, TmpMask);
    if Result <> TF_S_OK then Break;
    TmpMask.FLimbs[0]:= TmpMask.FLimbs[0] or 1;

// TmpProd:= (N * TmpNi) and TmpMask;
// -- we don't really need all the product, Count + 1 bits are enough;
//    can be optimized
    Result:= TBigNumber.MulNumbersU(N, TmpNi, TmpProd);
    if Result <> TF_S_OK then Break;
    Result:= TBigNumber.AndNumbersU(TmpProd, TmpMask, TmpProd);
    if Result <> TF_S_OK then Break;

// if TmpProd <> 1 then TmpNi:= TmpNi + 2^Count
// -- Or (SetBit) can be used instead of AddNumbersU
    if not ((TmpProd.FUsed = 1) and (TmpProd.FLimbs[0] = 1)) then begin
      Result:= BigNumberPowerOfTwo(TmpPowerOfTwo, Count);
      if Result <> TF_S_OK then Break;
      Result:= TBigNumber.AddNumbersU(TmpNi, TmpPowerOfTwo, TmpNi);
      if Result <> TF_S_OK then Break;
    end;
    Inc(Count);
  until Count = Power;
  if Result = TF_S_OK then begin
    Result:= BigNumberPowerOfTwo(TmpPowerOfTwo, Power);
    if Result = TF_S_OK then
      Result:= TBigNumber.SubNumbersU(TmpPowerOfTwo, TmpNi, TmpNi);
  end;
  if Result = TF_S_OK then begin
    tfFreeInstance(Ni);
    Ni:= TmpNi;
  end
  else tfFreeInstance(TmpNi);

  tfFreeInstance(TmpPowerOfTwo);
  tfFreeInstance(TmpMask);
  tfFreeInstance(TmpProd);
end;

function GetMontInstance(var P: PMontInstance; Modulus: PBigNumber): TF_RESULT;
var
  TmpMont: PMontInstance;
  TmpDividend: PBigNumber;
  Shift: Cardinal;

begin
// Modulus should be odd to be coprime with powers of 2
  if not Odd(Modulus.FLimbs[0]) or (Modulus.FSign < 0) then begin
    Result:= TF_E_INVALIDARG;
    Exit;
  end;

  Shift:= TBigNumber.NumBits(PBigNumber(Modulus));

  Result:= tfTryAllocMem(Pointer(TmpMont), SizeOf(TMontInstance));
  if Result = TF_S_OK then begin
    TmpMont.FVTable:= @MontVTable;
    TmpMont.FRefCount:= 1;

// setup Shift; R = 2^Shift
    TmpMont.FShift:= Shift;

// setup N
    Result:= TBigNumber.DuplicateNumber(Modulus, TmpMont.FN);
    if Result = TF_S_OK then begin

// setup RR = 2^(2*Shift) mod Modulus
      Result:= TBigNumber.AllocPowerOfTwo(TmpMont.FRR, Shift shl 1);
      if Result = TF_S_OK then begin
        TmpDividend:= nil;
        Result:= TBigNumber.DivRemNumbers(TmpMont.FRR, TmpMont.FN,
                                          TmpDividend, TmpMont.FRR);
        if Result = TF_S_OK then begin
          tfFreeInstance(TmpDividend);
// setup Ni
          Result:= GetNi(TmpMont.FN, Shift, TmpMont.FNi);
        end;
      end;
    end;
  end;
  if Result = TF_S_OK then begin
    tfFreeInstance(P);
    P:= TmpMont;
  end
  else
    tfFreeInstance(TmpMont);
{   begin
    tfFreeInstance(TmpMont.FNi);
    tfFreeInstance(TmpMont.FRR);
    tfFreeInstance(TmpMont.FN);
  end;}
end;




(* todo: limbwise implementation of Montgomery multiplication,
{$IFDEF MONT_LIMB}
{$ELSE}
{$ENDIF}
*)

{ TMontEngine }
(*
class function TMontInstance.Release(Inst: PMontInstance): Integer;
begin
  tfFreeInstance(Inst.FNi);
  tfFreeInstance(Inst.FRR);
  tfFreeInstance(Inst.FN);
  Result:= TForgeInstance.Release(Inst);
end;
*)

class procedure TMontInstance.Burn(Inst: PMontInstance);
var
  BurnSize: Integer;

begin
  tfFreeInstance(Inst.FNi);
  tfFreeInstance(Inst.FRR);
  tfFreeInstance(Inst.FN);
  BurnSize:= SizeOf(TMontInstance) - Integer(@PMontInstance(nil)^.FShift);
  FillChar(Inst.FShift, BurnSize, 0);
end;

class function TMontInstance.Reduce(Inst: PMontInstance; A: PBigNumber; var T: PBigNumber): TF_RESULT;
var
  Tmp: PBigNumber;

begin
  Tmp:= nil;

// Tmp:= ((A mod R)*Ni) mod R
  Result:= TBigNumber.DuplicateNumber(A, Tmp);
  if Result <> TF_S_OK then Exit;
  TBigNumber.MaskBits(Tmp, Inst.FShift);

  Result:= TBigNumber.MulNumbers(Tmp, Inst.FNi, Tmp);
  if Result = TF_S_OK then begin
    TBigNumber.MaskBits(Tmp, Inst.FShift);

// Tmp:= (A + Tmp*N) div R
    Result:= TBigNumber.MulNumbers(Tmp, Inst.FN, Tmp);
    if Result = TF_S_OK then begin

      Result:= TBigNumber.AddNumbers(A, Tmp, Tmp);
      if Result = TF_S_OK then begin

        Result:= TBigNumber.ShrNumber(Tmp, Inst.FShift, Tmp);
        if Result = TF_S_OK then begin

// if Tmp >= N then Tmp:= Tmp - N
          if TBigNumber.CompareNumbersU(Tmp, Inst.FN) >= 0 then
            Result:= TBigNumber.SubNumbersU(Tmp, Inst.FN, Tmp);
        end;
      end;
    end;
  end;

  if Result = TF_S_OK then begin
    tfFreeInstance(T);
    T:= Tmp;
  end
  else
    tfFreeInstance(Tmp);
end;

class function TMontInstance.Convert(Inst: PMontInstance; A: PBigNumber; var T: PBigNumber): TF_RESULT;
var
  Tmp: PBigNumber;

begin
  Tmp:= nil;
  Result:= TBigNumber.MulNumbersU(A, Inst.FRR, Tmp);
  if Result = TF_S_OK then begin
    Result:= Reduce(Inst, Tmp, T);
    tfFreeInstance(Tmp);
  end;
end;

// just for testing
class function TMontInstance.GetRModulus(Inst: PMontInstance; var T: PBigNumber): TF_RESULT;
begin
  Result:= BigNumberPowerOfTwo(T, Inst.FShift);
end;

class function TMontInstance.AddNumbers(Inst: PMontInstance; A, B: PBigNumber; var T: PBigNumber): TF_RESULT;
var
  Tmp: PBigNumber;

begin
  Tmp:= nil;
  Result:= TBigNumber.AddNumbersU(A, B, Tmp);
  if Result = TF_S_OK then begin
    if TBigNumber.CompareNumbersU(Tmp, Inst.FN) >= 0 then begin
      Result:= TBigNumber.SubNumbersU(Tmp, Inst.FN, T);
      tfFreeInstance(Tmp);
    end
    else begin
      tfFreeInstance(T);
      T:= Tmp;
    end;
  end;
end;

class function TMontInstance.SubNumbers(Inst: PMontInstance; A, B: PBigNumber; var T: PBigNumber): TF_RESULT;
var
  Tmp: PBigNumber;

begin
  Tmp:= nil;
  Result:= TBigNumber.SubNumbers(A, B, Tmp);
  if Result = TF_S_OK then begin
    if Tmp.FSign < 0 then begin
      Result:= TBigNumber.AddNumbers(Tmp, Inst.FN, T);
      tfFreeInstance(Tmp);
    end
    else begin
      tfFreeInstance(T);
      T:= Tmp;
    end;
  end;
end;

class function TMontInstance.MulNumbers(Inst: PMontInstance; A, B: PBigNumber; var T: PBigNumber): TF_RESULT;
var
  Tmp: PBigNumber;

begin
  Tmp:= nil;
  Result:= TBigNumber.MulNumbersU(A, B, Tmp);
  if Result = TF_S_OK then begin
    Result:= Reduce(Inst, Tmp, T);
    tfFreeInstance(Tmp);
  end;
end;

class function TMontInstance.ModMulNumbers(Inst: PMontInstance;
               A, B: PBigNumber; var T: PBigNumber): TF_RESULT;
var
  Tmp: PBigNumber;

begin
  if A.IsZero or B.IsZero then begin
    SetBigNumberZero(T);
    Result:= TF_S_OK;
    Exit;
  end;

// convert A to Montgomery form
  Tmp:= nil;
  Result:= Convert(Inst, A, Tmp);
  if Result <> TF_S_OK then Exit;

// multiply and convert out of Montgomery form
  Result:= TBigNumber.MulNumbersU(Tmp, B, Tmp);
  if Result = TF_S_OK then
    Result:= Reduce(Inst, Tmp, T);

  tfFreeInstance(Tmp);
end;

class function TMontInstance.ModPowLimb(Inst: PMontInstance; BaseValue: PBigNumber;
  ExpValue: TLimb; var T: PBigNumber): TF_RESULT;
var
  MontX, TmpR: PBigNumber;
  Limb: TLimb;

begin
  if ExpValue = 0 then begin
    SetBigNumberOne(T);
    Result:= TF_S_OK;
    Exit;
  end;

  if BaseValue.IsZero then begin
    SetBigNumberZero(T);
    Result:= TF_S_OK;
    Exit;
  end;

//  convert Base to Montgomery form:
  MontX:= nil;
  Result:= Convert(Inst, BaseValue, MontX);
  if Result <> TF_S_OK then Exit;

  TmpR:= nil;
  Limb:= ExpValue;

  while Limb > 0 do begin
    if Odd(Limb) then begin
      if TmpR = nil then begin
        TmpR:= MontX;
        tfAddrefInstance(TmpR);
      end
      else begin
        Result:= TBigNumber.MulNumbersU(MontX, TmpR, TmpR);
        if Result = TF_S_OK then
          Result:= Reduce(Inst, TmpR, TmpR);
        if Result <> TF_S_OK then begin
          tfFreeInstance(MontX);
          tfFreeInstance(TmpR);
          Exit;
        end;
      end;
      if Limb = 1 then Break;
    end;
    Result:= TBigNumber.SqrNumber(MontX, MontX);
    if Result = TF_S_OK then
      Result:= Reduce(Inst, MontX, MontX);
    if Result <> TF_S_OK then begin
      tfFreeInstance(MontX);
      tfFreeInstance(TmpR);
      Exit;
    end;
    Limb:= Limb shr 1;
  end;
  tfFreeInstance(MontX);

// convert TmpR out of Montgomery form:
  Result:= Reduce(Inst, TmpR, T);
  tfFreeInstance(TmpR);
end;

class function TMontInstance.ModPowNumber(Inst: PMontInstance; BaseValue, ExpValue: PBigNumber;
           var T: PBigNumber): TF_RESULT;
var
  MontX: PBigNumber;
  TmpR: PBigNumber;
  Used, I: Cardinal;
  Limb: TLimb;
  P, Sentinel: PLimb;

begin
  if ExpValue.FSign < 0 then begin
    Result:= TF_E_INVALIDARG;
    Exit;
  end;

  if ExpValue.IsZero then begin
    SetBigNumberOne(T);
    Result:= TF_S_OK;
    Exit;
  end;

  if BaseValue.IsZero then begin
    SetBigNumberZero(T);
    Result:= TF_S_OK;
    Exit;
  end;

//  convert Base to Montgomery form:
  MontX:= nil;
  Result:= Convert(Inst, BaseValue, MontX);
  if Result <> TF_S_OK then Exit;

  TmpR:= nil;
//  SetBigNumberOne(TmpR);

//  Tmp:= BaseValue;
//  tfAddrefInstance(Tmp);
//  Q:= nil;

  Used:= ExpValue.FUsed;
  P:= @ExpValue.FLimbs;
  Sentinel:= P + Used;
  while P <> Sentinel do begin
    I:= 0;
    Limb:= P^;
    while Limb > 0 do begin
      if Odd(Limb) then begin
                                              // TmpR:= Tmp * TmpR
//        Result:= TBigNumber.MulNumbers(Tmp, TmpR, TmpR);
        if TmpR = nil then begin
          TmpR:= MontX;
          tfAddrefInstance(TmpR);
        end
        else begin
          Result:= TBigNumber.MulNumbersU(MontX, TmpR, TmpR);
          if Result = TF_S_OK then
            Result:= Reduce(Inst, TmpR, TmpR);
          if Result <> TF_S_OK then begin
            tfFreeInstance(MontX);
            tfFreeInstance(TmpR);
            Exit;
          end;
        end;
        if Limb = 1 then Break;
      end;
      Result:= TBigNumber.SqrNumber(MontX, MontX);
      if Result = TF_S_OK then
        Result:= Reduce(Inst, MontX, MontX);
      if Result <> TF_S_OK then begin
        tfFreeInstance(MontX);
        tfFreeInstance(TmpR);
        Exit;
      end;
      Limb:= Limb shr 1;
      Inc(I);
    end;
    Inc(P);
    if P = Sentinel then Break;
    while I < TLimbInfo.BitSize do begin
      Result:= TBigNumber.SqrNumber(MontX, MontX);
      if Result = TF_S_OK then
        Result:= Reduce(Inst, MontX, MontX);
      if Result <> TF_S_OK then begin
        tfFreeInstance(MontX);
        tfFreeInstance(TmpR);
        Exit;
      end;
      Inc(I);
    end;
  end;
  tfFreeInstance(MontX);

// convert TmpR out of Montgomery form:
  Result:= Reduce(Inst, TmpR, T);
  tfFreeInstance(TmpR);
end;

end.
