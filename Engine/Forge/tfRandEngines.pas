{ *********************************************************** }
{ *                     TForge Library                      * }
{ *       Copyright (c) Sergey Kasandrov 1997, 2016         * }
{ ----------------------------------------------------------- }
{ *      # Standard secure pseudorandom generator           * }
{ *********************************************************** }

unit tfRandEngines;

interface

{$I TFL.inc}

uses tfTypes, tfSalsa20,
     {$IFDEF TFL_WINDOWS}tfWindows{$ELSE}tfStubOS{$ENDIF};

type
  PRandEngine = ^TRandEngine;
  TRandEngine = record
  private
    const BUF_SIZE = 1024;
  private
    FVTable: Pointer;
    FRefCount: Integer;
    FState: TChaChaPRG;
    FCount: Integer;
    FHave: Integer;
    FBuffer: array[0..BUF_SIZE - 1] of Byte;
    function Reset: TF_RESULT;
  public
    class function Release(Inst: PRandEngine): Integer; stdcall; static;
    class procedure Burn(Inst: PRandEngine); static;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF}
    class function GetRand(Inst: PRandEngine; Buf: PByte; BufSize: Cardinal): TF_RESULT; static;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF}
  end;

function GetRandInstance(var Inst: PRandEngine): TF_RESULT;

function GetRand(Buf: PByte; BufSize: Cardinal): TF_RESULT;

implementation

uses tfRecords;

const
  PRGVTable: array[0..4] of Pointer = (
   @TForgeInstance.QueryIntf,
   @TForgeInstance.Addref,
   @TRandEngine.Release,

   @TRandEngine.Burn,
   @TRandEngine.GetRand
   );

var
  RandGen: TRandEngine;

// GetRand is threadsafe
function GetRand(Buf: PByte; BufSize: Cardinal): TF_RESULT;
begin
{$IFDEF TFL_WINDOWS}
  Result:= CryptLock.Acquire;
  if Result = TF_S_OK then begin
    if RandGen.FVTable = nil then begin
      RandGen.FVTable:= @PRGVTable;
      RandGen.FRefCount:= -1;
    end;
    Result:= TRandEngine.GetRand(@RandGen, Buf, BufSize);
    CryptLock.Resease;
  end;
{$ELSE}
  Result:= TF_E_NOTIMPL;
{$ENDIF}
end;

function GetRandInstance(var Inst: PRandEngine): TF_RESULT;
var
  P: PRandEngine;

begin
  try
    GetMem(P, SizeOf(TRandEngine));
    P^.FVTable:= @PRGVTable;
    P^.FRefCount:= 1;
//    P^.FState:=
    P^.FCount:= 0;
    P^.FHave:= 0;
    if Inst <> nil then TRandEngine.Release(Inst);
    Inst:= P;
    Result:= TF_S_OK;
  except
    Result:= TF_E_OUTOFMEMORY;
  end;
end;

{ TPRGEngine }

class procedure TRandEngine.Burn(Inst: PRandEngine);
var
  BurnSize: Integer;

begin
  BurnSize:= SizeOf(TRandEngine) - Integer(@PRandEngine(nil)^.FState);
  FillChar(Inst^.FState, BurnSize, 0);
end;

class function TRandEngine.Release(Inst: PRandEngine): Integer;
begin
  if Inst.FRefCount > 0 then begin
    Result:= tfDecrement(Inst.FRefCount);
    if Result = 0 then begin
      FillChar(Inst^, SizeOf(TRandEngine), 0);
      FreeMem(Inst);
    end;
  end
  else
    Result:= Inst.FRefCount;
end;

class function TRandEngine.GetRand(Inst: PRandEngine; Buf: PByte; BufSize: Cardinal): TF_RESULT;
var
  N: Cardinal;
  P: PByte;

begin
  while (BufSize > 0) do begin
    if Inst.FHave = 0 then begin
      Result:= Inst.Reset;
      if Result <> TF_S_OK then Exit;
    end;
// here Inst.FHave > 0
    N:= Inst.FHave;
    if BufSize < N then N:= BufSize;
    P:= PByte(@Inst.FBuffer) + BUF_SIZE - Inst.FHave;
    Move(P^, Buf^, N);
    FillChar(P^, N, 0);
    Inc(Buf, N);
    Dec(BufSize, N);
    Dec(Inst.FHave, N);
  end;
  Result:= TF_S_OK;
end;

function TRandEngine.Reset: TF_RESULT;
const
  SEED_SIZE = 40;
  BUF_COUNT = 10000;  // number of buffers generated until reseed

var
  Seed: array[0..SEED_SIZE-1] of Byte;

begin
  if FCount = 0 then begin
    Result:= GenRandom(Seed, SizeOf(Seed));
    if Result = TF_S_OK then begin
      Result:= FState.Init(@Seed, SizeOf(Seed));
      FillChar(Seed, SizeOf(Seed), 0);
    end;
    if Result <> TF_S_OK then Exit;
    FCount:= BUF_COUNT;
  end;

  Result:= FState.GetKeyStream(@FBuffer, SizeOf(FBuffer));
// immediately reinit for backtracking resistance
  if Result = TF_S_OK then begin
    FState.Init(@FBuffer, SEED_SIZE);
   	FillChar(FBuffer, SEED_SIZE, 0);
    FHave:= SizeOf(FBuffer) - SEED_SIZE;
  end;
  Dec(FCount);
end;

end.
