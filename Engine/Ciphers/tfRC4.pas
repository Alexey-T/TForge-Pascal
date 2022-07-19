{ *********************************************************** }
{ *                     TForge Library                      * }
{ *       Copyright (c) Sergey Kasandrov 1997, 2016         * }
{ *********************************************************** }

unit tfRC4;

{$I TFL.inc}

interface

uses
  tfTypes;

type
  PRC4Algorithm = ^TRC4Algorithm;
  TRC4Algorithm = record
  private type
    PState = ^TState;
    TState = record
      S: array[0..255] of Byte;
      I, J: Byte;
    end;

  private
{$HINTS OFF}                    // -- inherited fields begin --
                                // from tfRecord
    FVTable:   Pointer;
    FRefCount: Integer;
                                // from tfStreamCipher
    FValidKey: Boolean;
                                // -- inherited fields end --
    FState:    TState;
{$HINTS ON}
  public
    class function Release(Inst: PRC4Algorithm): Integer; stdcall; static;
    class function ExpandKey(Inst: PRC4Algorithm; Key: PByte; KeySize: Cardinal): TF_RESULT;
          {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function GetBlockSize(Inst: PRC4Algorithm): Integer;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function DuplicateKey(Inst: PRC4Algorithm; var Key: PRC4Algorithm): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class procedure DestroyKey(Inst: PRC4Algorithm);{$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function RandBlock(Inst: PRC4Algorithm; Data: PByte): TF_RESULT;
          {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
  end;

function GetRC4Algorithm(var A: PRC4Algorithm): TF_RESULT;

implementation

uses tfRecords, tfBaseCiphers;

const
  RC4VTable: array[0..16] of Pointer = (
   @TForgeInstance.QueryIntf,
   @TForgeInstance.Addref,
   @TRC4Algorithm.Release,

   @TRC4Algorithm.DestroyKey,
   @TRC4Algorithm.DuplicateKey,
   @TRC4Algorithm.ExpandKey,
   @TBaseStreamCipher.SetKeyParam,
   @TBaseStreamCipher.GetKeyParam,
   @TRC4Algorithm.GetBlockSize,
   @TBaseStreamCipher.Encrypt,
   @TBaseStreamCipher.Decrypt,
   @TBaseStreamCipher.EncryptBlock,
   @TBaseStreamCipher.EncryptBlock,
   @TBaseStreamCipher.GetRand,
   @TRC4Algorithm.RandBlock,
   @TBaseStreamCipher.RandCrypt,
   @TBaseStreamCipher.GetIsBlockCipher
   );

function GetRC4Algorithm(var A: PRC4Algorithm): TF_RESULT;
var
  Tmp: PRC4Algorithm;

begin
  try
    Tmp:= AllocMem(SizeOf(TRC4Algorithm));
    Tmp^.FVTable:= @RC4VTable;
    Tmp^.FRefCount:= 1;

    if A <> nil then TRC4Algorithm.Release(A);
    A:= Tmp;
    Result:= TF_S_OK;
  except
    Result:= TF_E_OUTOFMEMORY;
  end;
end;

{ TRC4Algorithm }

procedure BurnKey(Inst: PRC4Algorithm); inline;
var
  BurnSize: Integer;

begin
  BurnSize:= SizeOf(TRC4Algorithm)
             - Integer(@PRC4Algorithm(nil)^.FValidKey);
  FillChar(Inst.FValidKey, BurnSize, 0);
end;

class function TRC4Algorithm.Release(Inst: PRC4Algorithm): Integer;
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

class procedure TRC4Algorithm.DestroyKey(Inst: PRC4Algorithm);
begin
  BurnKey(Inst);
end;

class function TRC4Algorithm.DuplicateKey(Inst: PRC4Algorithm;
  var Key: PRC4Algorithm): TF_RESULT;
begin
  Result:= GetRC4Algorithm(Key);
  if Result = TF_S_OK then begin
    Key.FValidKey:= Inst.FValidKey;
    Key.FState:= Inst.FState;
  end;
end;

class function TRC4Algorithm.ExpandKey(Inst: PRC4Algorithm; Key: PByte;
  KeySize: Cardinal): TF_RESULT;
var
  I: Cardinal;
  J, Tmp: Byte;

begin
  I:= 0;
  repeat
    Inst.FState.S[I]:= I;
    Inc(I);
  until I = 256;
  I:= 0;
  J:= 0;
  repeat
    J:= J + Inst.FState.S[I] + Key[I mod KeySize];
    Tmp:= Inst.FState.S[I];
    Inst.FState.S[I]:= Inst.FState.S[J];
    Inst.FState.S[J]:= Tmp;
    Inc(I);
  until I = 256;
  Inst.FState.I:= 0;
  Inst.FState.J:= 0;

  Inst.FValidKey:= True;
  Result:= TF_S_OK;
end;

class function TRC4Algorithm.GetBlockSize(Inst: PRC4Algorithm): Integer;
begin
  Result:= 1;
end;

class function TRC4Algorithm.RandBlock(Inst: PRC4Algorithm; Data: PByte): TF_RESULT;
var
  Tmp: Byte;
  State: PState;

begin
  State:= @Inst.FState;
  Inc(State.I);
  Tmp:= State.S[State.I];
  State.J:= State.J + Tmp;
  State.S[State.I]:= State.S[State.J];
  State.S[State.J]:= Tmp;
  Tmp:= Tmp + State.S[State.I];
  Data^:= State.S[Tmp];
  Result:= TF_S_OK;
end;

end.
