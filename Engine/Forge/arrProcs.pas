{ *********************************************************** }
{ *                     TForge Library                      * }
{ *       Copyright (c) Sergey Kasandrov 1997, 2016         * }
{ * ------------------------------------------------------- * }
{ *   # engine unit                                         * }
{ *********************************************************** }
{ *   De Morgan's laws:                                     * }
{ *   # not(A and B) = (not A) or (not B)                   * }
{ *   # not(A or B) = (not A) and (not B)                   * }
{ *   also used:                                            * }
{ *   # -A = (not A) + 1 = not(A - 1)                       * }
{ *   # not(A xor B) = (not A) xor B = A xor (not B)        * }
{ *   # (not A) xor (not B) = A xor B                       * }
{ *********************************************************** }
{
  Win64 Register Usage
  --------------------
    RAX        Volatile     Return value register
    RCX        Volatile     First integer argument
    RDX        Volatile     Second integer argument
    R8         Volatile     Third integer argument
    R9         Volatile     Fourth integer argument
    R10:R11    Volatile
    R12:R15    Nonvolatile
    RDI        Nonvolatile
    RSI        Nonvolatile
    RBX        Nonvolatile
    RBP        Nonvolatile
    RSP        Nonvolatile
    XMM0       Volatile     First FP argument
    XMM1       Volatile     Second FP argument
    XMM2       Volatile     Third FP argument
    XMM3       Volatile     Fourth FP argument
    XMM4:XMM5  Volatile
    XMM6:XMM15 Nonvolatile
}

unit arrProcs;

{$I TFL.inc}

{$IFDEF TFL_LIMB32_CPU386_WIN32}
  {$DEFINE ASM86}
{$ENDIF}

{$IFDEF TFL_LIMB32_CPUX64_WIN64}
  {$DEFINE ASM64}
{$ENDIF}

interface

uses tfLimbs;

{ Utilities}
function arrGetLimbCount(A: PLimb; L: Cardinal): Cardinal;

{ Addition primitives }
function arrAdd(A, B, Res: PLimb; LA, LB: Cardinal): Boolean;
function arrAddLimb(A: PLimb; Limb: TLimb; Res: PLimb; LA: Cardinal): Boolean;
function arrInc(A: PLimb; Res: PLimb; L: Cardinal): Boolean;
function arrSelfAdd(A, B: PLimb; LA, LB: Cardinal): Boolean;
function arrSelfAddLimb(A: PLimb; Limb: TLimb; L: Cardinal): Boolean;
function arrSelfInc(A: PLimb; L: Cardinal): Boolean;

{ Subtraction primitives }
function arrSub(A, B, Res: PLimb; LA, LB: Cardinal): Boolean;
function arrSelfSub(A, B: PLimb; LA, LB: Cardinal): Boolean;
function arrSubLimb(A: PLimb; Limb: TLimb; Res: PLimb; L: Cardinal): Boolean;
function arrSelfSubLimb(A: PLimb; Limb: TLimb; L: Cardinal): Boolean;
function arrDec(A: PLimb; Res: PLimb; L: Cardinal): Boolean;
function arrSelfDec(A: PLimb; L: Cardinal): Boolean;

{ Multiplication primitives }
function arrMul(A, B, Res: PLimb; LA, LB: Cardinal): Boolean;
function arrMulLimb(A: PLimb; Limb: TLimb; Res: PLimb; L: Cardinal): Boolean;
function arrSelfMulLimb(A: PLimb; Limb: TLimb; L: Cardinal): Boolean;

function arrSqr(A, Res: PLimb; LA: Cardinal): Boolean;

{ Division primitives }

// normalized division (Divisor[DsrLen-1] and $80000000 <> 0)
// in: Dividend: Dividend;
//     Divisor: Divisor;
//     DndLen: Dividend Length
//     DsrLen: Divisor Length
// out: Quotient:= Dividend div Divisor
//      Dividend:= Dividend mod Divisor

procedure arrNormDivMod(Dividend, Divisor, Quotient: PLimb;
                        DndLen, DsrLen: TLimb);
procedure arrNormMod(Dividend, Divisor: PLimb;
                        DndLen, DsrLen: TLimb);

function arrDivModLimb(A, Q: PLimb; L, D: TLimb): TLimb;
function arrSelfDivModLimb(A: PLimb; L: Cardinal; D: TLimb): TLimb;

function arrCmp(A, B: PLimb; L: Cardinal): Integer;

function arrSqrt(A, Root: PLimb; LA: Cardinal): Cardinal;

{ Bitwise shifts }
function arrShlShort(A, Res: PLimb; LA, Shift: Cardinal): Cardinal;
function arrShrShort(A, Res: PLimb; LA, Shift: Cardinal): Cardinal;

function arrShlOne(A, Res: PLimb; LA: Cardinal): Cardinal;
function arrShrOne(A, Res: PLimb; LA: Cardinal): Cardinal;
function arrSelfShrOne(A: PLimb; LA: Cardinal): Cardinal;

{ Bitwise boolean }
procedure arrAnd(A, B, Res: PLimb; L: Cardinal);
procedure arrAndTwoCompl(A, B, Res: PLimb; LA, LB: Cardinal);
function arrAndTwoCompl2(A, B, Res: PLimb; LA, LB: Cardinal): Boolean;

procedure arrOr(A, B, Res: PLimb; LA, LB: Cardinal);
procedure arrOrTwoCompl(A, B, Res: PLimb; LA, LB: Cardinal);
procedure arrOrTwoCompl2(A, B, Res: PLimb; LA, LB: Cardinal);

procedure arrXor(A, B, Res: PLimb; LA, LB: Cardinal);
procedure arrXorTwoCompl(A, B, Res: PLimb; LA, LB: Cardinal);
procedure arrXorTwoCompl2(A, B, Res: PLimb; LA, LB: Cardinal);

implementation

{$IFDEF TFL_POINTERMATH}
{$POINTERMATH ON}
{$ELSE}
function GetLimb(P: PLimb; Offset: Cardinal): TLimb;
begin
  Inc(P, Offset);
  Result:= P^;
end;
{$ENDIF}

function arrGetLimbCount(A: PLimb; L: Cardinal): Cardinal;
begin
  Assert(L > 0);
  Inc(A, L - 1);
  while (A^ = 0) and (L > 1) do begin
    Dec(A);
    Dec(L);
  end;
  Result:= L;
end;

{$IFDEF ASM86}
function arrAdd(A, B, Res: PLimb; LA, LB: Cardinal): Boolean;
asm
        PUSH  ESI
        PUSH  EDI
        MOV   EDI,ECX     // EDI <-- Res
        MOV   ESI,EAX     // ESI <-- A
        MOV   ECX,LA
        SUB   ECX,LB
        PUSH  ECX
        MOV   ECX,LB
        CLC
@@Loop:
//        MOV   EAX,[ESI]
//        LEA   ESI,[ESI+4]
        LODSD             // EAX <-- [ESI], ESI <-- ESI + 4
        ADC   EAX,[EDX]
//        MOV   [EDI],EAX
//        LEA   EDI,[EDI+4]
        STOSD             // [EDI] <-- EAX, EDI <-- EDI + 4
        LEA   EDX,[EDX+4]
        LOOP  @@Loop

        POP   ECX         // POP to keep carry
        JECXZ @@Done
@@Loop2:
        LODSD
        ADC   EAX, 0
        STOSD
        LOOP  @@Loop2
@@Done:
        SETC  AL
        MOVZX EAX,AL
        MOV   [EDI],EAX
        POP   EDI
        POP   ESI
end;

{$ELSE}
{$IFDEF ASM64}
function arrAdd(A, B, Res: PLimb; LA, LB: Cardinal): Boolean;
asm
        MOV   R10,RCX       // R10 <-- A
        MOV   ECX,LB        // ECX <-- LB
        SUB   R9,RCX        // R9D <-- LA - LB
        CLC
@@Loop:
        MOV   EAX,[R10]
        LEA   R10,[R10+4]
        ADC   EAX,[RDX]
        MOV   [R8],EAX
        LEA   R8,[R8+4]
        LEA   RDX,[RDX+4]
//        LOOP  @@Loop
        DEC   ECX
        JNZ   @@Loop

        MOV   ECX,R9D       // ECX <-- LA - LB
        JECXZ @@Done
@@Loop2:
        MOV   EAX,[R10]
        LEA   R10,[R10+4]
        ADC   EAX, 0
        MOV   [R8],EAX
        LEA   R8,[R8+4]
//        LOOP  @@Loop2
        DEC   ECX
        JNZ   @@Loop2
@@Done:
        SETC  AL
        MOVZX EAX,AL
        MOV   [R8],EAX
end;

{$ELSE}
function arrAdd(A, B, Res: PLimb; LA, LB: Cardinal): Boolean;
var
  CarryOut, CarryIn: Boolean;
  Tmp: TLimb;

begin
  Dec(LA, LB);
  CarryIn:= False;
  while LB > 0 do begin
    Tmp:= A^ + B^;
    CarryOut:= Tmp < A^;
    Inc(A);
    Inc(B);
    if CarryIn then begin
      Inc(Tmp);
      CarryOut:= CarryOut or (Tmp = 0);
    end;
    CarryIn:= CarryOut;
    Res^:= Tmp;
    Inc(Res);
    Dec(LB);
  end;
  while (LA > 0) and CarryIn do begin
    Tmp:= A^ + 1;
    CarryIn:= Tmp = 0;
    Inc(A);
    Res^:= Tmp;
    Inc(Res);
    Dec(LA);
  end;
  while (LA > 0) do begin
    Res^:= A^;
    Inc(A);
    Inc(Res);
    Dec(LA);
  end;
  Res^:= Ord(CarryIn);
  Result:= CarryIn;
end;
{$ENDIF}
{$ENDIF}

{
  Description:
    Res:= A + Limb
  Asserts:
    L >= 1
    Res must have enough space for L + 1 limbs
  Remarks:
    function returns True if carry is propagated out of A[L-1];
    if function returns True the Res senior limb is set: Res[L] = 1
}

{$IFDEF ASM86}
function arrAddLimb(A: PLimb; Limb: TLimb; Res: PLimb; LA: Cardinal): Boolean;
asm
        ADD   EDX,[EAX]     // Limb:= Limb + A[0]
        MOV   [ECX],EDX
        MOV   EDX,ECX
        MOV   ECX,LA
        DEC   ECX
        JZ    @@Done
        PUSH  ESI
        LEA   ESI,[EAX+4]
@@Loop:
        LODSD             // EAX <-- [ESI], ESI <-- ESI + 4
        LEA   EDX,[EDX+4]
        ADC   EAX,0
        MOV   [EDX],EAX
        LOOP  @@Loop
        POP   ESI
@@Done:
        SETC  AL
        MOVZX EAX,AL
        LEA   EDX,[EDX+4]
        MOV   [EDX],EAX
end;
{$ELSE}
{$IFDEF ASM64}
function arrAddLimb(A: PLimb; Limb: TLimb; Res: PLimb; LA: Cardinal): Boolean;
{$IFDEF FPC}assembler; nostackframe;{$ENDIF}
asm
        ADD   EDX,[RCX]     // Limb:= Limb + A[0]
        MOV   [R8],EDX
        MOV   RDX,R8
        LEA   R10,[RCX+4]
        MOV   RCX,R9
        DEC   ECX
        JZ    @@Done
@@Loop:
        MOV   EAX,[R10]
        LEA   R10,[R10+4]
        LEA   RDX,[RDX+4]
        ADC   EAX,0
        MOV   [RDX],EAX
        DEC   ECX
        JNZ   @@Loop
@@Done:
        SETC  AL
        MOVZX EAX,AL
        LEA   RDX,[RDX+4]
        MOV   [RDX],EAX
end;
{$ELSE}
function arrAddLimb(A: PLimb; Limb: TLimb; Res: PLimb; LA: Cardinal): Boolean;
var
  CarryIn: Boolean;
  Tmp: TLimb;

begin
  Tmp:= A^ + Limb;
  CarryIn:= Tmp < Limb;
  Inc(A);
  Dec(LA);
  Res^:= Tmp;
  Inc(Res);
  while (LA > 0) and CarryIn do begin
    Tmp:= A^ + 1;
    CarryIn:= Tmp = 0;
    Inc(A);
    Res^:= Tmp;
    Inc(Res);
    Dec(LA);
  end;
  while (LA > 0) do begin
    Res^:= A^;
    Inc(A);
    Inc(Res);
    Dec(LA);
  end;
  Res^:= Ord(CarryIn);
  Result:= CarryIn;
end;
{$ENDIF}
{$ENDIF}

{$IFDEF ASM86}
function arrInc(A: PLimb; Res: PLimb; L: Cardinal): Boolean;
{$IFDEF FPC}assembler; nostackframe;{$ENDIF}
asm
        PUSH  DWORD [EAX]
        POP   DWORD [EDX]
        ADD   DWORD [EDX],1
        DEC   ECX
        JZ    @@Done
        PUSH  ESI
        LEA   ESI,[EAX+4]
//        MOV   ESI,EAX
@@Loop:
        LODSD             // EAX <-- [ESI], ESI <-- ESI + 4
        LEA   EDX,[EDX+4]
        ADC   EAX,0
        MOV   [EDX],EAX
        LOOP  @@Loop
        POP   ESI
@@Done:
        SETC  AL
        MOVZX EAX,AL
        LEA   EDX,[EDX+4]
        MOV   [EDX],EAX
end;
{$ELSE}
{$IFDEF ASM64}
// RCX <-- A, RDX <--Res, R8D <-- L
function arrInc(A: PLimb; Res: PLimb; L: Cardinal): Boolean;
{$IFDEF FPC}assembler; nostackframe;{$ENDIF}
asm
        MOV   R9D,[RCX]
        MOV   [RDX],R9D
        ADD   DWORD [RDX],1
        DEC   R8D
        JZ    @@Done
@@Loop:
        LEA   RCX,[RCX+4]
        LEA   EDX,[RDX+4]
        MOV   EAX,[RCX]
        ADC   EAX,0
        MOV   [RDX],EAX
        DEC   R8D
        JNZ   @@Loop
@@Done:
        SETC  AL
        MOVZX EAX,AL
        LEA   RDX,[RDX+4]
        MOV   [RDX],EAX
end;
{$ELSE}
function arrInc(A: PLimb; Res: PLimb; L: Cardinal): Boolean;
var
  Tmp: TLimb;

begin
  Tmp:= A^ + 1;
  Res^:= Tmp;
                          //  while we have carry from prev limb ..
  while (Tmp = 0) do begin
    Dec(L);
    Inc(Res);
    if (L = 0) then begin
      Res^:= 1;
      Result:= True;
      Exit;
    end;
    Inc(A);
    Tmp:= A^ + 1;
    Res^:= Tmp;
  end;
  repeat
    Inc(A);
    Inc(Res);
    Dec(L);
    Res^:= A^;
  until L = 0;
  Res^:= 0;
  Result:= False;
end;
{$ENDIF}
{$ENDIF}

function arrSelfAdd(A, B: PLimb; LA, LB: Cardinal): Boolean;
{$IFDEF WIN32_ASM86}
asm
        PUSH  ESI
        PUSH  EDI
        MOV   EDI,EAX     // EDI <-- A
        MOV   ESI,EDX     // ESI <-- B
        SUB   ECX,LB
        PUSH  ECX         // -(SP) <-- LA - LB;
        MOV   ECX,LB
        CLC
@@Loop:
        LODSD             // EAX <-- [ESI], ESI <-- ESI + 4
        ADC   EAX,[EDI]
        STOSD             // [EDI] <-- EAX, EDI <-- EDI + 4
        LOOP  @@Loop

        MOV   EAX,0
        POP   ECX         // ECX <-- LA - LB;
        JECXZ @@Done
@@Loop2:
        ADC   [EDI], 0
        LEA   EDI,[EDI+4]
        JNC   @@Exit
        LOOP  @@Loop2
@@Done:
        JNC   @@Exit
        INC   EAX
        MOV   [EDI],1
@@Exit:
        POP   EDI
        POP   ESI
end;
{$ELSE}
{$IFDEF WIN64_ASM86}
asm
        .PUSHNV  RSI
        .PUSHNV  RDI
        MOV   RDI,RCX     // RDI <-- A
        MOV   RSI,RDX     // RSI <-- B
        SUB   R8,R9       // R8 <-- LA - LB
        MOV   RCX,R9      // RCX <-- LB
        CLC
@@Loop:
        LODSD             // EAX <-- [RSI], RSI <-- RSI + 4
        ADC   EAX,[RDI]
        STOSD             // [RDI] <-- EAX, RDI <-- RDI + 4
        LOOP  @@Loop

        MOV   EAX,0
        MOV   RCX,R8         // RCX <-- LA - LB;
        JECXZ @@Done
@@Loop2:
        ADC   [RDI], 0
        LEA   RDI,[RDI+4]
        JNC   @@Exit
        LOOP  @@Loop2
@@Done:
        JNC   @@Exit
        INC   EAX
        MOV   [RDI],1
@@Exit:
end;
{$ELSE}
var
  CarryOut, CarryIn: Boolean;
  Tmp: TLimb;

begin
  Dec(LA, LB);
  CarryIn:= False;
  while LB > 0 do begin
    Tmp:= A^ + B^;
    CarryOut:= Tmp < A^;
    Inc(B);
    if CarryIn then begin
      Inc(Tmp);
      CarryOut:= CarryOut or (Tmp = 0);
    end;
    CarryIn:= CarryOut;
    A^:= Tmp;
    Inc(A);
    Dec(LB);
  end;
  while (LA > 0) and CarryIn do begin
    Tmp:= A^ + 1;
    CarryIn:= Tmp = 0;
    A^:= Tmp;
    Inc(A);
    Dec(LA);
  end;
//  Inc(A, LA);
//  A^:= Ord(CarryIn);
  if CarryIn then A^:= 1;
  Result:= CarryIn;
end;
{$ENDIF}
{$ENDIF}

{
  Description:
    A:= A + Limb
  Asserts:
    L >= 1                                             +
    A must have enougth space for L + 1 limbs
  Remarks:
    function returns True if carry is propagated out of A[L-1];
    if function returns True the A senior limb is set: A[L] = 1
}
function arrSelfAddLimb(A: PLimb; Limb: TLimb; L: Cardinal): Boolean;
{$IFDEF WIN32_ASM86}
asm
        ADD   [EAX],EDX
        JNC   @@Exit
        DEC   ECX
        JECXZ @@Done
@@Loop:
        LEA   EAX,[EAX+4]
        ADC   [EAX], 0
        JNC   @@Exit
        LOOP  @@Loop
        JNC   @@Exit
@@Done:
        LEA   EAX,[EAX+4]
        MOV   [EAX],1
@@Exit:
        SETC  AL
        MOVZX EAX,AL
end;
{$ELSE}
{$IFDEF WIN64_ASM86}
{$ELSE}
var
  CarryIn: Boolean;
  Tmp: TLimb;

begin
  Tmp:= A^ + Limb;
  CarryIn:= Tmp < Limb;
  A^:= Tmp;
  Inc(A);
  Dec(L);
  while (L > 0) and CarryIn do begin
    Tmp:= A^ + 1;
    CarryIn:= Tmp = 0;
    A^:= Tmp;
    Inc(A);
    Dec(L);
  end;
//  Inc(A, L);
//  A^:= Ord(CarryIn);
  if CarryIn then A^:= 1;
  Result:= CarryIn;
end;
{$ENDIF}
{$ENDIF}

{$IFDEF WIN32_ASM86}
function arrSelfInc(A: PLimb; L: Cardinal): Boolean;
asm
        ADD   [EAX],1
        JNC   @@Exit
        MOV   ECX,EDX
        DEC   ECX
        JECXZ @@Done
@@Loop:
        LEA   EAX,[EAX+4]
        ADC   [EAX], 0
        JNC   @@Exit
        LOOP  @@Loop
        JNC   @@Exit
@@Done:
        LEA   EAX,[EAX+4]
        MOV   [EAX],1
@@Exit:
        SETC  AL
        MOVZX EAX,AL
end;
{$ELSE}
function arrSelfInc(A: PLimb; L: Cardinal): Boolean;
var
  Tmp: TLimb;

begin
  Tmp:= A^ + 1;
  A^:= Tmp;
                          //  while we have carry from prev limb ..
  while (Tmp = 0) do begin
    Dec(L);
    Inc(A);
    if (L = 0) then begin
      A^:= 1;
      Result:= True;
      Exit;
    end;
    Tmp:= A^ + 1;
    A^:= Tmp;
  end;
  Result:= False;
end;
{$ENDIF}

{
  Description:
    Res:= A - B
  Asserts:
    LA >= LB >= 1
    Res must have enough space for LA limbs
  Remarks:
    function returns True if borrow is propagated out of A[LA-1] (A < B);
    if function returns True the Res is invalid
    any (A = B = Res) coincidence is allowed
}
{$IFDEF ASM86}
function arrSub(A, B, Res: PLimb; LA, LB: Cardinal): Boolean;
asm
        PUSH  ESI
        PUSH  EDI
        MOV   EDI,ECX     // EDI <-- Res
        MOV   ESI,EAX     // ESI <-- A
        MOV   ECX,LA
        SUB   ECX,LB
        PUSH  ECX         // -(SP) <-- LA - LB;
        MOV   ECX,LB
        CLC
@@Loop:
        LODSD             // EAX <-- [ESI], ESI <-- ESI + 4
        SBB   EAX,[EDX]
        STOSD             // [EDI] <-- EAX, EDI <-- EDI + 4
        LEA   EDX,[EDX+4]
        LOOP  @@Loop

        POP   ECX         // ECX <-- LA - LB;
        JECXZ @@Done
@@Loop2:
        LODSD
        SBB   EAX, 0
        STOSD
        LOOP  @@Loop2
@@Done:
//        MOV   EAX,0
        SETC  AL
        MOVZX EAX,AL      // not needed really ..
@@Exit:
        POP   EDI
        POP   ESI
end;

{$ELSE}
{$IFDEF ASM64}
function arrSub(A, B, Res: PLimb; LA, LB: Cardinal): Boolean;
asm
        MOV   R10,RCX       // R10 <-- A
        MOV   ECX,LB        // ECX <-- LB
        SUB   R9,RCX        // R9D <-- LA - LB
        CLC
@@Loop:
        MOV   EAX,[R10]
        LEA   R10,[R10+4]
        SBB   EAX,[RDX]
        MOV   [R8],EAX
        LEA   R8,[R8+4]
        LEA   RDX,[RDX+4]
        DEC   ECX
        JNZ   @@Loop

        MOV   ECX,R9D       // ECX <-- LA - LB
        JECXZ @@Done
@@Loop2:
        MOV   EAX,[R10]
        LEA   R10,[R10+4]
        SBB   EAX, 0
        MOV   [R8],EAX
        LEA   R8,[R8+4]
        DEC   ECX
        JNZ   @@Loop2
@@Done:
        SETC  AL
        MOVZX EAX,AL      // not needed really ..
end;

{$ELSE}
function arrSub(A, B, Res: PLimb; LA, LB: Cardinal): Boolean;
var
  BorrowOut, BorrowIn: Boolean;
  Tmp: TLimb;

begin
  Assert(LA >= LB);
  Assert(LB >= 1);
  Dec(LA, LB);
  BorrowIn:= False;
  while LB > 0 do begin
    Tmp:= A^ - B^;
    BorrowOut:= Tmp > A^;
    Inc(A);
    Inc(B);
    if BorrowIn then begin
      BorrowOut:= BorrowOut or (Tmp = 0);
      Dec(Tmp);
    end;
    BorrowIn:= BorrowOut;
    Res^:= Tmp;
    Inc(Res);
    Dec(LB);
  end;
  while (LA > 0) and BorrowIn do begin
    Tmp:= A^;
    BorrowIn:= Tmp = 0;
    Dec(Tmp);
    Inc(A);
    Res^:= Tmp;
    Inc(Res);
    Dec(LA);
  end;
  while (LA > 0) do begin
    Res^:= A^;
    Inc(A);
    Inc(Res);
    Dec(LA);
  end;
  Result:= BorrowIn;
end;
{$ENDIF}
{$ENDIF}

{
  Description:
    A:= A - B
  Asserts:
    LA >= LB >= 1
  Remarks:
    function returns True if borrow is propagated out of A[LA-1] (A < B);
    if function returns True the A is invalid
    (A = B) coincidence is allowed
}
function arrSelfSub(A, B: PLimb; LA, LB: Cardinal): Boolean;
var
  BorrowOut, BorrowIn: Boolean;
  Tmp: TLimb;

begin
  Dec(LA, LB);
  BorrowIn:= False;
  while LB > 0 do begin
    Tmp:= A^ - B^;
    BorrowOut:= Tmp > A^;
    Inc(B);
    if BorrowIn then begin
      BorrowOut:= BorrowOut or (Tmp = 0);
      Dec(Tmp);
    end;
    BorrowIn:= BorrowOut;
    A^:= Tmp;
    Inc(A);
    Dec(LB);
  end;
  while (LA > 0) and BorrowIn do begin
    Tmp:= A^;
    BorrowIn:= Tmp = 0;
    Dec(Tmp);
    A^:= Tmp;
    Inc(A);
    Dec(LA);
  end;
  Result:= BorrowIn;
end;

{
  Description:
    Res:= A - Limb
  Asserts:
    L >= 1
    Res must have enough space for L limbs
  Remarks:
    function returns True if borrow is propagated out of A[L-1] (A < B);
    if function returns True the Res is invalid
}
function arrSubLimb(A: PLimb; Limb: TLimb; Res: PLimb; L: Cardinal): Boolean;
var
  BorrowIn: Boolean;
  Tmp: TLimb;

begin
  Tmp:= A^ - Limb;
  BorrowIn:= Tmp > A^;
  Inc(A);
  Dec(L);
  Res^:= Tmp;
  while (L > 0) and BorrowIn do begin
    Tmp:= A^;
    BorrowIn:= Tmp = 0;
    Dec(Tmp);
    Inc(A);
    Inc(Res);
    Res^:= Tmp;
    Dec(L);
  end;
  while (L > 0) do begin
    Inc(Res);
    Res^:= A^;
    Inc(A);
    Dec(L);
  end;
{
  if BorrowIn then
// we get here if L = 1 and A[0] < Limb; set Res[0] = Limb - A[0]
    Res^:= LongWord(-LongInt(Res^));
}
  Result:= BorrowIn;
end;

{
  Description:
    A:= A - Limb
  Asserts:
    L >= 1
  Remarks:
    function returns True if borrow is propagated out of A[L-1] (A < B);
    if function returns True the A is invalid
}
function arrSelfSubLimb(A: PLimb; Limb: TLimb; L: Cardinal): Boolean;
var
  BorrowIn: Boolean;
  Tmp: TLimb;

begin
  Tmp:= A^ - Limb;
  BorrowIn:= Tmp > A^;
  A^:= Tmp;
  Inc(A);
  Dec(L);
  while (L > 0) and BorrowIn do begin
    Tmp:= A^;
    BorrowIn:= Tmp = 0;
    Dec(Tmp);
    A^:= Tmp;
    Inc(A);
    Dec(L);
  end;

  Result:= BorrowIn;
end;

function arrDec(A: PLimb; Res: PLimb; L: Cardinal): Boolean;
var
  Tmp: TLimb;
  Borrow: Boolean;

begin
  Tmp:= A^;
  Borrow:= Tmp = 0;
  Res^:= Tmp - 1;
  while Borrow do begin
    Dec(L);
    if (L = 0) then begin
      Result:= True;
      Exit;
    end;
    Inc(A);
    Inc(Res);
    Tmp:= A^;
    Borrow:= Tmp = 0;
    Res^:= Tmp - 1;
  end;
  repeat
    Inc(A);
    Inc(Res);
    Res^:= A^;
    Dec(L);
  until (L = 0);
  Result:= False;
end;

function arrSelfDec(A: PLimb; L: Cardinal): Boolean;
var
  Tmp: TLimb;
  Borrow: Boolean;

begin
  Tmp:= A^;
  Borrow:= Tmp = 0;
  A^:= Tmp - 1;
  while Borrow do begin
    Dec(L);
    if (L = 0) then begin
      Result:= True;
      Exit;
    end;
    Inc(A);
    Tmp:= A^;
    Borrow:= Tmp = 0;
    A^:= Tmp - 1;
  end;
  Result:= False;
end;

{ Bitwise boolean }

procedure arrAnd(A, B, Res: PLimb; L: Cardinal);
begin
  Assert(L > 0);
  repeat
    Res^:= A^ and B^;
    Inc(A);
    Inc(B);
    Inc(Res);
    Dec(L);
  until L = 0;
end;

// Res = A and (-B)) = A and not(B-1)
// B[0..LB-1] <> 0 because is abs of negative value
// Res[0..LA-1]
procedure arrAndTwoCompl(A, B, Res: PLimb; LA, LB: Cardinal);
var
  Borrow: Boolean;
  Tmp: TLimb;

begin
  Assert(LA > 0);
  Assert(LB > 0);
  if LA >= LB then begin
    Dec(LA, LB);
    repeat
      Tmp:= B^;
      Borrow:= Tmp = 0;
      Dec(Tmp);
      Res^:= A^ and not Tmp;
      Inc(A);
      Inc(B);
      Inc(Res);
      Dec(LB);
//    until (LB = 0) or not Borrow;
    until not Borrow;
    while (LB > 0) do begin
      Res^:= A^ and not B^;
      Inc(A);
      Inc(B);
      Inc(Res);
      Dec(LB);
    end;
    if (LA > 0) then
      Move(A^, Res^, LA * SizeOf(TLimb));
  end
  else begin    { LA < LB }
    repeat
      Tmp:= B^;
      Borrow:= Tmp = 0;
      Dec(Tmp);
      Res^:= A^ and not Tmp;
      Inc(A);
      Inc(B);
      Inc(Res);
      Dec(LA);
    until (LA = 0) or not Borrow;
    while (LA > 0) do begin
      Res^:= A^ and not B^;
      Inc(A);
      Inc(B);
      Inc(Res);
      Dec(LA);
    end;
  end;
end;

(*
procedure arrAndTwoCompl(A, B, Res: PLimb; LA, LB: Cardinal);
var
  Carry: Boolean;
  Tmp: TLimb;

begin
  if LA >= LB then begin
    Assert(LB > 0);
    Dec(LA, LB);
//    Carry:= True;
    repeat
      Tmp:= not B^;
      Inc(Tmp);
      Carry:= Tmp = 0;
      Res^:= A^ and Tmp;
      Inc(A);
      Inc(B);
      Inc(Res);
      Dec(LB);
    until (LB = 0) or not Carry;
    while (LB > 0) do begin
      Res^:= A^ and not B^;
      Inc(A);
      Inc(B);
      Inc(Res);
      Dec(LB);
    end;
    while (LA > 0) and Carry do begin
      Tmp:= A^ and TLimbInfo.MaxLimb;
      Inc(Tmp);
      Carry:= Tmp = 0;
      Res^:= Tmp;
      Inc(A);
      Inc(Res);
      Dec(LA);
    end;
    while (LA > 0) do begin
      Res^:= A^ and TLimbInfo.MaxLimb;
      Inc(A);
      Inc(Res);
      Dec(LA);
    end;
  end
  else begin
    Assert(LA > 0);
//    Carry:= True;
    repeat
      Tmp:= not B^;
      Inc(Tmp);
      Carry:= Tmp = 0;
      Res^:= A^ and Tmp;
      Inc(A);
      Inc(B);
      Inc(Res);
      Dec(LA);
    until (LA = 0) or not Carry;
    while (LA > 0) do begin
      Res^:= A^ and not B^;
      Inc(A);
      Inc(B);
      Inc(Res);
      Dec(LA);
    end;
  end;
end;
*)

// A < 0, B < 0
// Res = -((-A) and (-B)) = -(not(A - 1) and not(B - 1)) =
//     = not(not(A - 1) and not(B - 1)) + 1 =
//     = ((A - 1) or (B - 1)) + 1
function arrAndTwoCompl2(A, B, Res: PLimb; LA, LB: Cardinal): Boolean;
var
  CarryA, CarryB, CarryR: Boolean;
  TmpA, TmpB: TLimb;
  SaveRes: PLimb;

begin
  Assert(LA >= LB);
  Assert(LB > 0);
  CarryA:= True;
  CarryB:= True;
  SaveRes:= Res;
  Dec(LA, LB);
  repeat
    TmpA:= not A^;
    if CarryA then begin
      Inc(TmpA);
      CarryA:= TmpA = 0;
    end;
    TmpB:= not B^;
    if CarryB then begin
      Inc(TmpB);
      CarryB:= TmpB = 0;
    end;
    Res^:= TmpA and TmpB;
    Inc(A);
    Inc(B);
    Inc(Res);
    Dec(LB);
  until (LB = 0);

  while (LA > 0) do begin
    TmpA:= not A^;
    if CarryA then begin
      Inc(TmpA);
      CarryA:= TmpA = 0;
    end;
                            // should be B = -0 to produce CarryB here
    Assert(CarryB = False);
    TmpB:= TLimbInfo.MaxLimb;
    Res^:= TmpA and TmpB;
    Inc(A);
    Inc(Res);
    Dec(LA);
  end;
//  CarryR:= True;
  Result:= True;
  repeat
    SaveRes^:= not SaveRes^ + 1;
    CarryR:= (SaveRes^ = 0);
    Result:= Result and (SaveRes^ = 0);
    Inc(SaveRes);
  until (SaveRes = Res) or not CarryR;
  while (SaveRes <> Res) do begin
    SaveRes^:= not SaveRes^;
    Result:= Result and (SaveRes^ = 0);
    Inc(SaveRes);
  end;
  Res^:= Ord(Result);
end;

procedure arrOr(A, B, Res: PLimb; LA, LB: Cardinal);
begin
  if (LA >= LB) then begin
    LA:= LA - LB;
    repeat
      Res^:= A^ or B^;
      Inc(A);
      Inc(B);
      Inc(Res);
      Dec(LB);
    until (LB = 0);
    if (LA > 0) then
      Move(A^, Res^, LA * SizeOf(TLimb));
  end
  else begin
    LB:= LB - LA;
    repeat
      Res^:= A^ or B^;
      Inc(A);
      Inc(B);
      Inc(Res);
      Dec(LA);
    until (LA = 0);
    Move(B^, Res^, LB * SizeOf(TLimb));
  end;
end;

// Res = -(A or (-B)) = -(A or not(B-1)) = not(A or not(B-1)) + 1 =
//     = (not(A) and (B-1)) + 1
// B[0..LB-1] <> 0 because is abs of negative value
// Res[0..LB-1]
procedure arrOrTwoCompl(A, B, Res: PLimb; LA, LB: Cardinal);
var
  Borrow, Carry: Boolean;
  Tmp: TLimb;

begin
  if LA >= LB then begin
    Assert(LB > 0);
    Dec(LA, LB);
    Borrow:= True;
    Carry:= True;
    repeat
      Tmp:= B^;
      if Borrow then begin
        Borrow:= Tmp = 0;
        Dec(Tmp);
      end;
      Tmp:= not (A^) and Tmp;
      if Carry then begin
        Inc(Tmp);
        Carry:= Tmp = 0;
      end;
      Res^:= Tmp;
      Inc(A);
      Inc(B);
      Inc(Res);
      Dec(LB);
    until (LB = 0);
  end
  else begin
    Assert(LA > 0);
    Dec(LB, LA);
    Borrow:= True;
    Carry:= True;

    repeat
      Tmp:= B^;
      if Borrow then begin
        Borrow:= Tmp = 0;
        Dec(Tmp);
      end;
      Tmp:= not (A^) and Tmp;
      if Carry then begin
        Inc(Tmp);
        Carry:= Tmp = 0;
      end;
      Res^:= Tmp;
      Inc(A);
      Inc(B);
      Inc(Res);
      Dec(LA);
    until (LA = 0);

    repeat
      Tmp:= B^;
      if Borrow then begin
        Borrow:= Tmp = 0;
        Dec(Tmp);
      end;
      if Carry then begin
        Inc(Tmp);
        Carry:= Tmp = 0;
      end;
      Res^:= Tmp;
      Inc(B);
      Inc(Res);
      Dec(LB);
    until (LB = 0);
  end;
end;

// Res = -((-A) or (-B)) = -(not(A-1) or not(B-1)) =
//     = not(not(A-1) or not(B-1)) + 1 =
//     = (A-1) and (B-1) + 1
procedure arrOrTwoCompl2(A, B, Res: PLimb; LA, LB: Cardinal);
var
  BorrowA, BorrowB, CarryR: Boolean;
  TmpA, TmpB, TmpR: TLimb;
  L: Cardinal;

begin
  BorrowA:= True;
  BorrowB:= True;
  CarryR:= True;
  if (LA >= LB)
    then L:= LB
    else L:= LA;
  Assert(L > 0);
  repeat
    TmpA:= A^;
    if BorrowA then begin
      BorrowA:= TmpA = 0;
      Dec(TmpA);
    end;
    TmpB:= B^;
    if BorrowB then begin
      BorrowB:= TmpB = 0;
      Dec(TmpB);
    end;
    TmpR:= TmpA and TmpB;
    if CarryR then begin
      Inc(TmpR);
      CarryR:= TmpR = 0;
    end;
    Res^:= TmpR;
    Inc(A);
    Inc(B);
    Inc(Res);
    Dec(L);
  until (L = 0);
end;

procedure arrXor(A, B, Res: PLimb; LA, LB: Cardinal);
begin
  if (LA >= LB) then begin
    LA:= LA - LB;
    repeat
      Res^:= A^ xor B^;
      Inc(A);
      Inc(B);
      Inc(Res);
      Dec(LB);
    until (LB = 0);
    if (LA > 0) then
      Move(A^, Res^, LA * SizeOf(TLimb));
  end
  else begin
    LB:= LB - LA;
    repeat
      Res^:= A^ xor B^;
      Inc(A);
      Inc(B);
      Inc(Res);
      Dec(LA);
    until (LA = 0);
    Move(B^, Res^, LB * SizeOf(TLimb));
  end;
end;

// Res = -(A xor (-B)) = -(A xor not(B-1)) = not(A xor not(B-1)) + 1 =
//     = (A xor (B-1)) + 1
// B[0..LB-1] <> 0 because is abs of negative value
procedure arrXorTwoCompl(A, B, Res: PLimb; LA, LB: Cardinal);
var
  Borrow, Carry: Boolean;
  Tmp: TLimb;

begin
  if LA >= LB then begin
    Assert(LB > 0);
    Dec(LA, LB);
    Borrow:= True;
    Carry:= True;
    repeat
      Tmp:= B^;
      if Borrow then begin
        Borrow:= Tmp = 0;
        Dec(Tmp);
      end;
      Tmp:= A^ xor Tmp;
      if Carry then begin
        Inc(Tmp);
        Carry:= Tmp = 0;
      end;
      Res^:= Tmp;
      Inc(A);
      Inc(B);
      Inc(Res);
      Dec(LB);
    until (LB = 0);
    Assert(not Borrow);
    while Carry and (LA > 0) do begin
      Tmp:= A^ + 1;
      Carry:= Tmp = 0;
      Res^:= Tmp;
      Inc(A);
      Inc(Res);
      Dec(LA);
    end;
    if (LA > 0) then
      Move(A^, Res^, LA * SizeOf(TLimb));
  end
  else begin
    Assert(LA > 0);
    Dec(LB, LA);
    Borrow:= True;
    Carry:= True;
    repeat
      Tmp:= B^;
      if Borrow then begin
        Borrow:= Tmp = 0;
        Dec(Tmp);
      end;
      Tmp:= A^ xor Tmp;
      if Carry then begin
        Inc(Tmp);
        Carry:= Tmp = 0;
      end;
      Res^:= Tmp;
      Inc(A);
      Inc(B);
      Inc(Res);
      Dec(LA);
    until (LA = 0);

    repeat
      Tmp:= B^;
      if Borrow then begin
        Borrow:= Tmp = 0;
        Dec(Tmp);
      end;
      if Carry then begin
        Inc(Tmp);
        Carry:= Tmp = 0;
      end;
      Res^:= Tmp;
      Inc(B);
      Inc(Res);
      Dec(LB);
    until (LB = 0);
  end;
end;

// Res = (-A) xor (-B) = not(A-1) xor not(B-1) =
//     = (A-1) xor (B-1)
procedure arrXorTwoCompl2(A, B, Res: PLimb; LA, LB: Cardinal);
var
  BorrowA, BorrowB: Boolean;
  TmpA, TmpB: TLimb;

begin
  Assert(LA > 0);
  Assert(LB > 0);
  BorrowA:= True;
  BorrowB:= True;
  if (LA >= LB) then begin
    Dec(LA, LB);
    repeat
      TmpA:= A^;
      if BorrowA then begin
        BorrowA:= TmpA = 0;
        Dec(TmpA);
      end;
      TmpB:= B^;
      if BorrowB then begin
        BorrowB:= TmpB = 0;
        Dec(TmpB);
      end;
      Res^:= TmpA xor TmpB;
      Inc(A);
      Inc(B);
      Inc(Res);
      Dec(LB);
    until (LB = 0);
    if (LA > 0) then
      Move(A^, Res^, LA * SizeOf(TLimb));
  end
  else begin
    Dec(LB, LA);
    repeat
      TmpA:= A^;
      if BorrowA then begin
        BorrowA:= TmpA = 0;
        Dec(TmpA);
      end;
      TmpB:= B^;
      if BorrowB then begin
        BorrowB:= TmpB = 0;
        Dec(TmpB);
      end;
      Res^:= TmpA xor TmpB;
      Inc(A);
      Inc(B);
      Inc(Res);
      Dec(LA);
    until (LA = 0);
    Move(B^, Res^, LB * SizeOf(TLimb));
  end;
end;

{
  Description:
    Res:= A * B
  Asserts:
    LA >= 1, LB >= 1
    Res must have enough space for LA + LB limbs
  Remarks:
    none
}
{$IFDEF ASM86}
function arrMul(A, B, Res: PLimb; LA, LB: Cardinal): Boolean;
asm
        PUSH  ESI
        PUSH  EDI
        PUSH  EBX
        PUSH  EBP

        PUSH  EDX         // B  [SP+12]
        PUSH  LB
        PUSH  EAX         // A, [SP+4]
        PUSH  LA

        MOV   EDI,ECX     // Res
        MOV   ECX,LA
//        ADD   ECX,LB

        PUSH  EDI
        XOR   EAX,EAX
@@Clear:
        MOV   [EDI],EAX
        LEA   EDI,[EDI+4]
        LOOP  @@Clear
        POP   EDI

@@ExtLoop:
        XOR   EBX,EBX       // Carry
        MOV   ESI,[ESP+12]  // B
        MOV   EBP,[ESI]
        LEA   ESI,[ESI+4]   // Inc(B);
        MOV   [ESP+12],ESI
        MOV   ECX,[ESP]     // LA
        MOV   ESI,[ESP+4]   // A
        PUSH  EDI

@@Loop:
        LODSD               // EAX <-- [ESI], ESI <-- ESI + 4
        MUL   EBP
        ADD   EAX,EBX
        ADC   EDX,0
        ADD   EAX,[EDI]
        ADC   EDX,0
        STOSD               // [EDI] <-- EAX, EDI <-- EDI + 4
        MOV   EBX,EDX
        LOOP  @@Loop

        MOV   [EDI],EBX
        POP   EDI
        LEA   EDI,[EDI+4]   // Inc(Res);
        DEC   [ESP+8]       // Dec(LB);
        JNZ   @@ExtLoop

        OR    EBX,EBX       // Result:= Carry <> 0
        SETNZ AL

        ADD   ESP,16

        POP   EBP
        POP   EBX
        POP   EDI
        POP   ESI
end;
{$ELSE}
{$IFDEF ASM64}
function arrMul(A, B, Res: PLimb; LA, LB: Cardinal): Boolean;
asm
        PUSH  RSI
        PUSH  RDI
        PUSH  RBX
        PUSH  RBP
        PUSH  R12

        MOV   R10D,LB       // LB
        MOV   R11,RDX       // B
        MOV   R12,RCX       // A

        MOV   ECX,R9D       // LA
        MOV   RDI,R8        // Res
        XOR   EAX,EAX
@@Clear:
        MOV   [RDI],EAX
        LEA   RDI,[RDI+4]
        LOOP  @@Clear
        MOV   RDI,R8        // Res

@@ExtLoop:
        XOR   EBX,EBX       // Carry
        MOV   EBP,[R11]     // B
        MOV   ECX,R9D       // LA
        MOV   RSI,R12       // A
        MOV   RDI,R8        // Res

@@Loop:
        LODSD               // RAX <-- [RSI], RSI <-- RSI + 4
        MUL   EBP
        ADD   EAX,EBX
        ADC   EDX,0
        ADD   EAX,[RDI]
        ADC   EDX,0
        STOSD               // [RDI] <-- RAX, RDI <-- RDI + 4
        MOV   EBX,EDX
        LOOP  @@Loop

        MOV   [RDI],EBX
        LEA   R11,[R11+4]   // Inc(B);
        LEA   R8,[R8+4]     // Inc(Res);
        DEC   R10D          // Dec(LB);
        JNZ   @@ExtLoop

        OR    EBX,EBX       // Result:= Carry <> 0
        SETNZ AL

        POP   R12
        POP   RBP
        POP   RBX
        POP   RDI
        POP   RSI
end;
{$ELSE}
function arrMul(A, B, Res: PLimb; LA, LB: Cardinal): Boolean;
var
  PA, PRes: PLimb;
  Cnt: Integer;
  TmpB: TLimbVector;
  TmpRes: TLimbVector;
  Carry: TLimb;

begin
//  FillChar(Res^, (LA + LB) * SizeOf(TLimb), 0);
  FillChar(Res^, LA * SizeOf(TLimb), 0);
//  while LB > 0 do begin
  repeat
    Carry:= 0;
    if B^ <> 0 then begin
      TmpB.Value:= B^;
      PA:= A;
      PRes:= Res;
      Cnt:= LA;
      while Cnt > 0 do begin
        TmpRes.Value:= TmpB.Value * PA^ + Carry;
        TmpRes.Value:= TmpRes.Value + PRes^;
        PRes^:= TmpRes.Lo;
        Inc(PRes);
        Carry:= TmpRes.Hi;
        Inc(PA);
        Dec(Cnt);
      end;
      PRes^:= Carry;
    end;
    Inc(B);
    Inc(Res);
    Dec(LB);
//  end;
  until LB = 0;
  Result:= Carry <> 0;
end;
{$ENDIF}
{$ENDIF}

function arrSqr(A, Res: PLimb; LA: Cardinal): Boolean;
var
  PA, PB, PRes: PLimb;
  LB, Cnt: Integer;
  TmpB: TLimbVector;
  TmpRes: TLimbVector;
  Carry: TLimb;

begin
  FillChar(Res^, LA * SizeOf(TLimb), 0);
  PB:= A;
  LB:= LA;
  repeat
    Carry:= 0;
    if PB^ <> 0 then begin
      TmpB.Value:= PB^;
      PA:= A;
      PRes:= Res;
      Cnt:= LA;
      while Cnt > 0 do begin
        TmpRes.Value:= TmpB.Value * PA^ + Carry;
        TmpRes.Value:= TmpRes.Value + PRes^;
        PRes^:= TmpRes.Lo;
        Inc(PRes);
        Carry:= TmpRes.Hi;
        Inc(PA);
        Dec(Cnt);
      end;
      PRes^:= Carry;
    end;
    Inc(PB);
    Inc(Res);
    Dec(LB);
  until LB = 0;
  Result:= Carry <> 0;
end;

{$IFDEF ASM86}
function arrMulLimb(A: PLimb; Limb: TLimb; Res: PLimb; L: Cardinal): Boolean;
asm
        PUSH  ESI
        PUSH  EDI
        PUSH  EBX
        PUSH  EBP

        MOV   EDI,ECX     // EDI <-- Res
        MOV   ESI,EAX     // ESI <-- A
        MOV   ECX,L
        XOR   EBX,EBX     // EBX = Carry
        MOV   EBP,EDX     // EBP <-- Limb
@@Loop:
        LODSD             // EAX <-- [ESI], ESI <-- ESI + 4
//        MOV   EDX,EBP     // Limb
//        MUL   EDX
        MUL   EBP
        ADD   EAX,EBX
        ADC   EDX,0
        STOSD             // [EDI] <-- EAX, EDI <-- EDI + 4
        MOV   EBX,EDX
        LOOP  @@Loop
        MOV   [EDI],EBX
        OR    EBX,EBX
        SETNZ AL

        POP   EBP
        POP   EBX
        POP   EDI
        POP   ESI
end;

{$ELSE}
{$IFDEF ASM64}
function arrMulLimb(A: PLimb; Limb: TLimb; Res: PLimb; L: Cardinal): Boolean;
{$IFDEF FPC}assembler; nostackframe;{$ENDIF}
asm
        MOV   R10D,EDX    // Limb
        XOR   R11,R11     // Carry
@@Loop:
        MOV   EAX,[RCX]
        LEA   RCX,[RCX+4]
        MUL   R10D
        ADD   EAX,R11D
        ADC   EDX,0
        MOV   [R8],EAX
        LEA   R8,[R8+4]
        MOV   R11D,EDX
        DEC   R9D
        JNE   @@Loop
        MOV   [R8],EDX
        OR    EDX,EDX
        SETNZ AL
end;
{$ELSE}
function arrMulLimb(A: PLimb; Limb: TLimb; Res: PLimb; L: Cardinal): Boolean;
var
  Tmp: TLimbVector;
  Carry: Cardinal;

begin
  Carry:= 0;
  while L > 0 do begin
    Tmp.Lo:= A^;
    Tmp.Hi:= 0;
    Tmp.Value:= Tmp.Value * Limb + Carry;
    Res^:= Tmp.Lo;
    Inc(A);
    Inc(Res);
    Carry:= Tmp.Hi;
    Dec(L);
  end;
  Res^:= Carry;
  Result:= Carry <> 0;
end;
{$ENDIF}
{$ENDIF}

// A:= A * Limb;
// A must have enough space for L + 1 limbs
// returns: True if senior (L+1)-th limb of the multiplication result is nonzero
function arrSelfMulLimb(A: PLimb; Limb: TLimb; L: Cardinal): Boolean;
var
  Tmp: TLimbVector;
  Carry: Cardinal;

begin
  Carry:= 0;
  while L > 0 do begin
    Tmp.Lo:= A^;
    Tmp.Hi:= 0;
    Tmp.Value:= Tmp.Value * Limb + Carry;
    A^:= Tmp.Lo;
    Inc(A);
    Carry:= Tmp.Hi;
    Dec(L);
  end;
  A^:= Carry;
  Result:= Carry <> 0;
end;

function arrCmp(A, B: PLimb; L: Cardinal): Integer;
begin
  if L > 0 then begin
    Inc(A, L - 1);
    Inc(B, L - 1);
    repeat
{$IFDEF TFL_EXITPARAM}
      if A^ > B^ then Exit(1);
      if A^ < B^ then Exit(-1);
{$ELSE}
      if A^ > B^ then begin
        Result:= 1;
        Exit;
      end;
      if A^ < B^ then begin
        Result:= -1;
        Exit;
      end;
{$ENDIF}
      Dec(A);
      Dec(B);
      Dec(L);
    until L = 0;
  end;
{$IFDEF TFL_EXITPARAM}
  Exit(0);
{$ELSE}
  Result:= 0;
  Exit;
{$ENDIF}
end;

// LA >= 1
// Root should have (LA + 1) shr 1 limbs at least
// returns:
// - 0: error occured (EOutOfMemory raised)
// > 0: Root Length in limbs
function arrSqrt(A, Root: PLimb; LA: Cardinal): Cardinal;

var
  Shift: Cardinal;
  HighLimb0: TLimb;
  InitA, InitX, InitY: Cardinal;
  NormalizedA: PLimb;
  DivRem: PLimb;
  X, Y, TmpXY: PLimb;
  LNorm, L1, L2: Cardinal;
  Diff: Integer;
  P: PLimb;
  Buffer: PLimb;
// Buffer structure:
// - NormalizedA: LA + 1 Limbs;
// - X: LA + 1 Limbs;
// - Y: LA + 1 Limbs;
// - DivRem: LA + 1 Limbs;
begin

  Assert(LA > 0);

  if LA = 1 then begin
// this may be incorrect if SizeOf(Limb) >= 8
//   because Double mantisse < 64 bits
    Root^:= TLimb(Trunc(Sqrt(A^)));
    Result:= 1;
    Exit;
  end;

  HighLimb0:= A[LA-1];

  Shift:= SizeOf(TLimb) * 8;
  while HighLimb0 <> 0 do begin
    Dec(Shift);
    HighLimb0:= HighLimb0 shr 1;
  end;

  Shift:= Shift and $FE;        // Shift should be even

// A = $5.6BC75E2D.63100000 = 1.0000.0000.0000.0000.0000
// Sqrt(A) = $2.540BE400 = 100.0000.0000

  Assert(LA > 1);

  try
    GetMem(Buffer, (LA + 1) * 4 * SizeOf(TLimb));
    try

      NormalizedA:= Buffer;
      X:= Buffer + LA + 1;
      Y:= X + LA + 1;
      DivRem:= Y + LA + 1;


      if Odd(LA) then begin
        arrShlShort(A, @NormalizedA[1], LA, Shift);
        NormalizedA[0]:= 0;
        LNorm:= LA + 1;
      end
      else begin
        arrShlShort(A, NormalizedA, LA, Shift);
        LNorm:= LA;
      end;

// NormalizedA = $56BC75E2.D6310000.00000000.00000000
//             = 625.0000.0000.0000.0000 * 2^64
// Sqrt(NormalizedA) = 9502F900.00000000
//                   = 25.0000.0000 * 2^32

{
      if LNorm = 2 then begin
  // todo: arrNormDivMod requires LNorm >= 3
  //       so LNorm = 2 case should be treated separately here
        Result:= 0;
        Exit;
      end;
}
      P:= @NormalizedA[LNorm - 1];
      L1:= 0;
      while P <> NormalizedA do begin
        if P^ = TLimbInfo.MaxLimb then begin
          Inc(L1);
          Dec(P);
        end
        else Break;
      end;
      if L1 >= LNorm shr 1 then begin
        L1:= LNorm shr 1;
// we got the result, nothing else needed
        FillChar(X^, L1 * SizeOf(TLimb), $FF);
      end
      else begin
        if (L1 > 0) then begin
          FillChar(X^, L1 * SizeOf(TLimb), $FF);
          FillChar(Y^, L1 * SizeOf(TLimb), $FF);
  {todo: P^ = TLimbInfo.MaxLimb - 1 case probably should be treated separately

  // obtain root approximation from above of length Count or Count + 1
          Assert(Count < LNorm shr 1);
          if P^ = TLimbInfo.MaxLimb - 1 then begin
            L1:= 0;
            repeat
              Dec(P);
              if P^ <> 0 then Break;
              Inc(L1);
            until P = NormalizedA;
  // todo:          if (L1 = Count) and (
          end
          else ;
  }
        end
        else begin
          L1:= 1;
          Y^:= (Trunc(Sqrt(NormalizedA[LNorm-1])) shl (TLimbInfo.BitSize shr 1))
               or (TLimbInfo.MaxLimb shr (TLimbInfo.BitSize shr 1));
    // the first iteration gives lower half of X^

          Move(NormalizedA[LNorm-2], DivRem^, 2 * SizeOf(TLimb));
          arrDivModLimb(DivRem, X, 2, Y^);                // X:= DivRem div Y^
        end;

  {
        HighLimb0:= NormalizedA[LNorm-1];

        X^:= Trunc(Sqrt(HighLimb0));
        X^:= (X^ shl (TLimbInfo.BitSize shr 1))
             or (TLimbInfo.MaxLimb shr (TLimbInfo.BitSize shr 1));
  }

  // LNorm = 2 case should be treated separately
  //   because arrNormDivMod requires LNorm >= 3
        if LNorm = 2 then begin
          if X^ <> Y^ then begin
            if X^ < Y^ then begin
              TmpXY:= X;
              X:= Y;
              Y:= TmpXY;
            end;
            repeat
              X^:= ((X^ + Y^) shr 1) or (1 shl (TLimbInfo.BitSize - 1));
              if X^ <= Y^ then Break;
              Move(NormalizedA[LNorm-2], DivRem^, 2 * SizeOf(TLimb));
              arrDivModLimb(DivRem, Y, 2, X^);     // Y:= DivRem div X^
            until False;
          end;
        end
        else begin
// we have approx L1 valid root limbs, L1 * 2 < LNorm

          Assert(L1 * 2 < LNorm);
//          L2:= 2 * L1;
          repeat

            L2:= L1 * 2;
            if L2 > LNorm shr 1 then begin
              L2:= LNorm shr 1;
            end;

            Move(X^, X[L2 - L1], L1 * SizeOf(TLimb));
            FillChar(X^, (L2 - L1) * SizeOf(TLimb), $FF);

            L1:= L2;
            L2:= L1 * 2;

            Move(NormalizedA[LNorm - L2], DivRem^, L2 * SizeOf(TLimb));

            arrNormDivMod(DivRem, X, Y, L2, L1);

            if L2 = LNorm then Break;

// carry is lost
            arrSelfAdd(X, Y, L1, L1);
            arrSelfShrOne(X, L1);
// restore carry
            X[L1-1]:= X[L1-1] or (1 shl (TLimbInfo.BitSize - 1));
          until False;

          Diff:= arrCmp(X, Y, L1);
          if Diff <> 0 then begin

      // make sure X is approximation from above
            if Diff < 0 then begin
              TmpXY:= X;
              X:= Y;
              Y:= TmpXY;
            end;

            arrSelfAdd(Y, X, L1, L1);
            arrSelfShrOne(Y, L1);
// restore carry
            Y[L1-1]:= Y[L1-1] or (1 shl (TLimbInfo.BitSize - 1));

            if arrCmp(X, Y, L1) > 0 then begin
              repeat
                Move(NormalizedA^, DivRem^, L2 * SizeOf(TLimb));
{
                if (L1 = 1) then begin
                  arrDivModLimb(DivRem, Y, L2, X^);
                end
                else begin
}
                arrNormDivMod(DivRem, X, Y, L2, L1);
//                end;

                arrSelfAdd(Y, X, L1, L1);
                arrSelfShrOne(Y, L1);
// restore carry
                Y[L1-1]:= Y[L1-1] or (1 shl (TLimbInfo.BitSize - 1));

                if arrCmp(X, Y, L1) <= 0 then Break;
                TmpXY:= X;
                X:= Y;
                Y:= TmpXY;
              until False;
            end;
          end;
        end;
      end;

// X = 9502F900.00000000
//   = 25.0000.0000 * 2^32

      if Odd(LA) then Shift:= Shift + TLimbInfo.BitSize;

      L1:= arrShrShort(X, Root, L1, Shift shr 1);

// Root = 2.540BE400
//      = 100.0000.0000
      Result:= arrGetLimbCount(Root, L1);
    finally
      FreeMem(Buffer);
    end;
  except
    Result:= 0;
  end;

end;

function arrShlShort(A, Res: PLimb; LA, Shift: Cardinal): Cardinal;
var
  Tmp, Carry: TLimb;

begin
  Assert(Shift < TLimbInfo.BitSize);
  Result:= LA;
  if Shift = 0 then begin
    Move(A^, Res^, LA * SizeOf(TLimb));
  end
  else begin
    Carry:= 0;
    repeat
      Tmp:= (A^ shl Shift) or Carry;
      Carry:= A^ shr (TLimbInfo.BitSize - Shift);
      Res^:= Tmp;
      Inc(A);
      Inc(Res);
      Dec(LA);
    until (LA = 0);
    if Carry <> 0 then begin
      Res^:= Carry;
      Inc(Result);
    end;
  end;
end;

// Short Shift Right
// A = Res is acceptable
// LA >= 1
// Shift < 32
function arrShrShort(A, Res: PLimb; LA, Shift: Cardinal): Cardinal;
var
  Carry: TLimb;

begin
//  Assert(Shift < 32);
  Result:= LA;
  if Shift = 0 then begin
    Move(A^, Res^, LA * SizeOf(TLimb));
  end
  else begin
    Carry:= A^ shr Shift;
    Inc(A);
    Dec(LA);
    while (LA > 0) do begin
      Res^:= (A^ shl (TLimbInfo.BitSize - Shift)) or Carry;
      Carry:= A^ shr Shift;
      Inc(A);
      Inc(Res);
      Dec(LA);
    end;
    if (Carry <> 0) or (Result = 1) then begin
      Res^:= Carry;
    end
    else begin
      Dec(Result);
    end;
  end;
end;

function arrShlOne(A, Res: PLimb; LA: Cardinal): Cardinal;
var
  Tmp, Carry: TLimb;

begin
  Result:= LA;
  Carry:= 0;
  repeat
    Tmp:= (A^ shl 1) or Carry;
    Carry:= A^ shr (TLimbInfo.BitSize - 1);
    Res^:= Tmp;
    Inc(A);
    Inc(Res);
    Dec(LA);
  until (LA = 0);
  if Carry <> 0 then begin
    Res^:= Carry;
    Inc(Result);
  end;
end;

function arrShrOne(A, Res: PLimb; LA: Cardinal): Cardinal;
var
  Carry: TLimb;

begin
  Result:= LA;
  Carry:= A^ shr 1;
  Inc(A);
  Dec(LA);
  while (LA > 0) do begin
    Res^:= (A^ shl (TLimbInfo.BitSize - 1)) or Carry;
    Carry:= A^ shr 1;
    Inc(A);
    Inc(Res);
    Dec(LA);
  end;
  if (Carry <> 0) or (Result = 1) then begin
    Res^:= Carry;
  end
  else begin
    Dec(Result);
  end;
end;

// LA >= 1
function arrSelfShrOne(A: PLimb; LA: Cardinal): Cardinal;
var
  Res: PLimb;

begin
  Result:= LA;
  Res:= A;
  Inc(A);
  Dec(LA);
  while (LA > 0) do begin
    Res^:= (Res^ shr 1) or (A^ shl (TLimbInfo.BitSize - 1));
    Inc(A);
    Inc(Res);
    Dec(LA);
  end;
  Res^:= Res^ shr 1;
  if Res^ = 0 then Dec(Result);
end;


// Q := A div D;
// Result:= A mod D;
function arrDivModLimb(A, Q: PLimb; L, D: TLimb): TLimb;
var
  Tmp: TLimbVector;

begin
  Dec(L);
  Inc(A, L);
  Inc(Q, L);
  Tmp.Lo:= A^;
  if Tmp.Lo >= D then begin
    Q^:= Tmp.Lo div D;
    Tmp.Hi:= Tmp.Lo mod D;
  end
  else begin
    Q^:= 0;
    Tmp.Hi:= Tmp.Lo;
  end;
  while L > 0 do begin
    Dec(A);
    Dec(Q);
    Tmp.Lo:= A^;
    Q^:= TLimb(Tmp.Value div D);
    Tmp.Hi:= TLimb(Tmp.Value mod D);
    Dec(L);
  end;
  Result:= Tmp.Hi;
end;

function arrSelfDivModLimb(A: PLimb; L: Cardinal; D: TLimb): TLimb;
var
  Tmp: TLimbVector;

begin
  Dec(L);
  Inc(A, L);
  Tmp.Lo:= A^;
  if Tmp.Lo >= D then begin
    A^:= Tmp.Lo div D;
    Tmp.Hi:= Tmp.Lo mod D;
  end
  else begin
    A^:= 0;
    Tmp.Hi:= Tmp.Lo;
  end;
  while L > 0 do begin
    Dec(A);
    Tmp.Lo:= A^;
    A^:= TLimb(Tmp.Value div D);
    Tmp.Hi:= TLimb(Tmp.Value mod D);
    Dec(L);
  end;
  Result:= Tmp.Hi;
end;

// normalized division (Divisor[DsrLen-1] and $80000000 <> 0)
// in: Dividend: Dividend;
//     Divisor: Divisor;
//     DndLen: Dividend Length
//     DsrLen: Divisor Length
// out: Quotient:= Dividend div Divisor
//      Dividend:= Dividend mod Divisor
procedure arrNormDivMod(Dividend, Divisor, Quotient: PLimb;
                        DndLen, DsrLen: TLimb);
var
  Tmp: TLimbVector;
  PDnd, PDsr: PLimb;
  QGuess, RGuess: TLimbVector;
  LoopCount, Count: Integer;
  TmpLimb, Carry: TLimb;
  CarryIn, CarryOut: Boolean;

begin
  Assert(DndLen > DsrLen);
  Assert(DsrLen >= 2);

  LoopCount:= DndLen - DsrLen;
  Inc(Quotient, LoopCount);

{$IFDEF TFL_POINTERMATH}
  PDnd:= Dividend + DndLen;
  PDsr:= Divisor + DsrLen;
{$ELSE}
  PDnd:= Dividend;
  Inc(PDnd, DndLen);
  PDsr:= Divisor;
  Inc(PDsr, DsrLen);
{$ENDIF}

  repeat
    Dec(PDnd);    // PDnd points to (current) senior dividend/remainder limb
    Dec(PDsr);    // PDns points to senior divisor limb
    Assert(PDnd^ <= PDsr^);

    Dec(Quotient);

// Делим число, составленное из двух старших цифр делимого на старшую цифру
//   делителя; это даст нам оценку очередной цифры частного QGuess

    if PDnd^ < PDsr^ then begin
{$IFDEF TFL_POINTERMATH}
      Tmp.Lo:= (PDnd - 1)^;
{$ELSE}
      Tmp.Lo:= GetLimb(PDnd, -1);
{$ENDIF}
      Tmp.Hi:= PDnd^;
      QGuess.Lo:= Tmp.Value div PDsr^;
      QGuess.Hi:= 0;
      RGuess.Lo:= Tmp.Value mod PDsr^;
      RGuess.Hi:= 0;
    end
    else begin
      QGuess.Lo:= 0;
      QGuess.Hi:= 1;
{$IFDEF TFL_POINTERMATH}
      RGuess.Lo:= (PDnd - 1)^;
{$ELSE}
      RGuess.Lo:= GetLimb(PDnd, -1);
{$ENDIF}
      RGuess.Hi:= 0;
    end;

// Для точного значения цифры частного Q имеем
//   QGuess - 2 <= Q <= QGuess;
//   улучшаем оценку

    repeat
      if (QGuess.Hi = 0) then begin
//   yмножаем вторую по старшинству цифру делителя на QGuess
{$IFDEF TFL_POINTERMATH}
        Tmp.Value:= (PDsr - 1)^ * QGuess.Value;
        if (Tmp.Hi < RGuess.Lo) then Break;
        if (Tmp.Hi = RGuess.Lo) and
           (Tmp.Lo <= (PDnd - 2)^) then Break;
{$ELSE}
        Tmp.Value:= GetLimb(PDsr, -1) * QGuess.Value;
        if (Tmp.Hi < RGuess.Lo) then Break;
        if (Tmp.Hi = RGuess.Lo) and
           (Tmp.Lo <= GetLimb(PDnd, -2)) then Break;
{$ENDIF}
        Dec(QGuess.Lo);
      end
      else begin
        QGuess.Lo:= TLimbInfo.MaxLimb;
        QGuess.Hi:= 0;
      end;
      RGuess.Value:= RGuess.Value + PDsr^;
    until RGuess.Hi <> 0;

// Здесь имеем QGuess - 1 <= Q <= QGuess;
// Вычитаем из делимого умноженный на QGuess делитель

    Count:= DsrLen;
{$IFDEF TFL_POINTERMATH}
    PDnd:= PDnd - Count;
{$ELSE}
    PDnd:= PDnd;
    Dec(PDnd, Count);
{$ENDIF}
    PDsr:= Divisor;
    Carry:= 0;
    repeat
      Tmp.Value:= PDsr^ * QGuess.Value + Carry;
      Carry:= Tmp.Hi;
      TmpLimb:= PDnd^ - Tmp.Lo;
      if (TmpLimb > PDnd^) then Inc(Carry);
      PDnd^:= TmpLimb;
      Inc(PDnd);
      Inc(PDsr);
      Dec(Count);
    until Count = 0;

    TmpLimb:= PDnd^ - Carry;
    if (TmpLimb > PDnd^) then begin
// если мы попали сюда значит QGuess = Q + 1;
// прибавляем делитель
      Count:= DsrLen;
{$IFDEF TFL_POINTERMATH}
      PDnd:= PDnd - Count;
{$ELSE}
      PDnd:= PDnd;
      Dec(PDnd, Count);
{$ENDIF}
      PDsr:= Divisor;
      CarryIn:= False;

      repeat
        TmpLimb:= PDnd^ + PDsr^;
        CarryOut:= TmpLimb < PDnd^;
        Inc(PDsr);
        if CarryIn then begin
          Inc(TmpLimb);
          CarryOut:= CarryOut or (TmpLimb = 0);
        end;
        CarryIn:= CarryOut;
        PDnd^:= TmpLimb;
        Inc(PDnd);
        Dec(Count);
      until Count = 0;

      Assert(CarryIn);

      Dec(QGuess.Lo);
    end;

// Возможно этот лимб больше не нужен и обнулять его необязательно
    PDnd^:= 0;

    Quotient^:= QGuess.Lo;
    Dec(LoopCount);
  until LoopCount = 0;

end;

// normalized division (Divisor[DsrLen-1] and $80000000 <> 0)
// in:  Dividend: Dividend;
//      Divisor: Divisor;
//      DndLen: Dividend Length
//      DsrLen: Divisor Length
// out: Dividend:= Dividend mod Divisor
procedure arrNormMod(Dividend, Divisor: PLimb;
                        DndLen, DsrLen: TLimb);
var
  Tmp: TLimbVector;
  PDnd, PDsr: PLimb;
  QGuess, RGuess: TLimbVector;
  LoopCount, Count: Integer;
  TmpLimb, Carry: TLimb;
  CarryIn, CarryOut: Boolean;

begin
  Assert(DndLen > DsrLen);
  Assert(DsrLen >= 2);

  LoopCount:= DndLen - DsrLen;

{$IFDEF TFL_POINTERMATH}
  PDnd:= Dividend + DndLen;
  PDsr:= Divisor + DsrLen;
{$ELSE}
  PDnd:= Dividend;
  Inc(PDnd, DndLen);
  PDsr:= Divisor;
  Inc(PDsr, DsrLen);
{$ENDIF}

  repeat
    Dec(PDnd);    // PDnd points to (current) senior dividend/remainder limb
    Dec(PDsr);    // PDns points to senior divisor limb
    Assert(PDnd^ <= PDsr^);

// Делим число, составленное из двух старших цифр делимого на старшую цифру
//   делителя; это даст нам оценку очередной цифры частного QGuess

    if PDnd^ < PDsr^ then begin
{$IFDEF TFL_POINTERMATH}
      Tmp.Lo:= (PDnd - 1)^;
{$ELSE}
      Tmp.Lo:= GetLimb(PDnd, -1);
{$ENDIF}
      Tmp.Hi:= PDnd^;
      QGuess.Lo:= Tmp.Value div PDsr^;
      QGuess.Hi:= 0;
      RGuess.Lo:= Tmp.Value mod PDsr^;
      RGuess.Hi:= 0;
    end
    else begin
      QGuess.Lo:= 0;
      QGuess.Hi:= 1;
{$IFDEF TFL_POINTERMATH}
      RGuess.Lo:= (PDnd - 1)^;
{$ELSE}
      RGuess.Lo:= GetLimb(PDnd, -1);
{$ENDIF}
      RGuess.Hi:= 0;
    end;

// Для точного значения цифры частного Q имеем
//   QGuess - 2 <= Q <= QGuess;
//   улучшаем оценку

    repeat
      if (QGuess.Hi = 0) then begin
//   yмножаем вторую по старшинству цифру делителя на QGuess
{$IFDEF TFL_POINTERMATH}
        Tmp.Value:= (PDsr - 1)^ * QGuess.Value;
        if (Tmp.Hi < RGuess.Lo) then Break;
        if (Tmp.Hi = RGuess.Lo) and
           (Tmp.Lo <= (PDnd - 2)^) then Break;
{$ELSE}
        Tmp.Value:= GetLimb(PDsr, -1) * QGuess.Value;
        if (Tmp.Hi < RGuess.Lo) then Break;
        if (Tmp.Hi = RGuess.Lo) and
           (Tmp.Lo <= GetLimb(PDnd, -2)) then Break;
{$ENDIF}
        Dec(QGuess.Lo);
      end
      else begin
        QGuess.Lo:= TLimbInfo.MaxLimb;
        QGuess.Hi:= 0;
      end;
      RGuess.Value:= RGuess.Value + PDsr^;
    until RGuess.Hi <> 0;

// Здесь имеем QGuess - 1 <= Q <= QGuess;
// Вычитаем из делимого умноженный на QGuess делитель

    Count:= DsrLen;
{$IFDEF TFL_POINTERMATH}
    PDnd:= PDnd - Count;
{$ELSE}
    PDnd:= PDnd;
    Dec(PDnd, Count);
{$ENDIF}
    PDsr:= Divisor;
    Carry:= 0;
    repeat
      Tmp.Value:= PDsr^ * QGuess.Value + Carry;
      Carry:= Tmp.Hi;
      TmpLimb:= PDnd^ - Tmp.Lo;
      if (TmpLimb > PDnd^) then Inc(Carry);
      PDnd^:= TmpLimb;
      Inc(PDnd);
      Inc(PDsr);
      Dec(Count);
    until Count = 0;

    TmpLimb:= PDnd^ - Carry;
    if (TmpLimb > PDnd^) then begin
// если мы попали сюда значит QGuess = Q + 1;
// прибавляем делитель
      Count:= DsrLen;
{$IFDEF TFL_POINTERMATH}
      PDnd:= PDnd - Count;
{$ELSE}
      PDnd:= PDnd;
      Dec(PDnd, Count);
{$ENDIF}
      PDsr:= Divisor;
      CarryIn:= False;

      repeat
        TmpLimb:= PDnd^ + PDsr^;
        CarryOut:= TmpLimb < PDnd^;
        Inc(PDsr);
        if CarryIn then begin
          Inc(TmpLimb);
          CarryOut:= CarryOut or (TmpLimb = 0);
        end;
        CarryIn:= CarryOut;
        PDnd^:= TmpLimb;
        Inc(PDnd);
        Dec(Count);
      until Count = 0;

      Assert(CarryIn);

      Dec(QGuess.Lo);
    end;

// Возможно этот лимб больше не нужен и обнулять его необязательно
    PDnd^:= 0;

    Dec(LoopCount);
  until LoopCount = 0;
end;

end.
