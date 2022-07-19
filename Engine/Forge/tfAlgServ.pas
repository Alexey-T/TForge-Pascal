{ *********************************************************** }
{ *                     TForge Library                      * }
{ *       Copyright (c) Sergey Kasandrov 1997, 2015         * }
{ *********************************************************** }

unit tfAlgServ;

interface

{$I TFL.inc}

{$R-}

uses tfRecords, tfTypes, tfByteVectors;

type
  TAlgGetter = function(var A: IInterface): TF_RESULT;
                {$IFDEF TFL_STDCALL}stdcall;{$ENDIF}

type
  PAlgItem = ^TAlgItem;
  TAlgItem = record
  public const
    NAME_SIZE = 16;
  private
    FName: array[0..NAME_SIZE - 1] of Byte;
    FGetter: Pointer;
  end;

type
  PAlgServer = ^TAlgServer;
  TAlgServer = record
  public
    FVTable: PPointer;
    FCapacity: Integer;   // set in derived classes
    FCount: Integer;
//    FAlgTable: array[0..TABLE_SIZE - 1] of TAlgItem;
    FAlgTable: array[0..0] of TAlgItem;  // var size

  public
    class function AddTableItem(Inst: Pointer;
            const AName: RawByteString; AGetter: Pointer): Boolean; static;

    class function GetByName(Inst: Pointer; AName: Pointer; CharSize: Integer;
          var Alg: IInterface): TF_RESULT;
          {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function GetByIndex(Inst: Pointer; Index: Integer;
          var Alg: IInterface): TF_RESULT;
          {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function GetName(Inst: Pointer; Index: Integer;
          var Name: PByteVector): TF_RESULT;
          {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function GetCount(Inst: Pointer): Integer;
          {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
  end;

implementation

// AName should be uppecase string
//function TAlgServer.AddTableItem(const AName: RawByteString; AGetter: Pointer): Boolean;
class function TAlgServer.AddTableItem(Inst: Pointer;
        const AName: RawByteString; AGetter: Pointer): Boolean;
var
  P: PAlgItem;
  L: Integer;

begin
  with PAlgServer(Inst)^ do
    if FCount < FCapacity then begin
      P:= @FAlgTable[FCount];
      FillChar(P^.FName, SizeOf(P^.FName), 0);
      L:= Length(AName);
      if L > SizeOf(P^.FName) then L:= SizeOf(P^.FName);
      Move(Pointer(AName)^, P^.FName, L);
      P^.FGetter:= AGetter;
      Inc(FCount);
      Result:= True;
    end
    else
      Result:= False;
end;

class function TAlgServer.GetByName(Inst: Pointer; AName: Pointer;
        CharSize: Integer; var Alg: IInterface): TF_RESULT;
const
  ANSI_a = Ord('a');

var
  I: Integer;
  PItem, Sentinel: PAlgItem;
  P1, P2: PByte;
  Found: Boolean;
  UP2: Byte;

begin
  PItem:= @PAlgServer(Inst).FAlgTable;
  Sentinel:= PItem;
  Inc(Sentinel, PAlgServer(Inst).FCount);
  while PItem <> Sentinel do begin
    P1:= @PItem.FName;
    P2:= AName;
    Found:= True;
    I:= SizeOf(PItem.FName);
    repeat
      UP2:= P2^;
      if UP2 >= ANSI_a then
        UP2:= UP2 and not $20;  { upcase }
      if P1^ <> UP2 then begin
        Found:= False;
        Break;
      end;
      if P1^ = 0 then Break;
      Inc(P1);
      Inc(P2, CharSize);
      Dec(I);
    until I = 0;
    if Found then begin
      Result:= TAlgGetter(PItem.FGetter)(Alg);
      Exit;
    end;
    Inc(PItem);
  end;
  Result:= TF_E_INVALIDARG;
end;

class function TAlgServer.GetByIndex(Inst: Pointer; Index: Integer;
        var Alg: IInterface): TF_RESULT;
begin
  if Cardinal(Index) >= Cardinal(PAlgServer(Inst).FCount) then
    Result:= TF_E_INVALIDARG
  else
    Result:= TAlgGetter(PAlgServer(Inst).FAlgTable[Index].FGetter)(Alg);
end;

class function TAlgServer.GetCount(Inst: Pointer): Integer;
begin
  Result:= PAlgServer(Inst).FCount;
end;

class function TAlgServer.GetName(Inst: Pointer; Index: Integer;
        var Name: PByteVector): TF_RESULT;
var
  Tmp: PByteVector;
  P, P1: PByte;
  I: Integer;

begin
  if Cardinal(Index) >= Cardinal(PAlgServer(Inst).FCount) then
    Result:= TF_E_INVALIDARG
  else begin
    P:= @PAlgServer(Inst).FAlgTable[Index].FName;
    P1:= P;
    I:= 0;
    repeat
      if P1^ = 0 then Break;
      Inc(P1);
      Inc(I);
    until I = 16;
    if I = 0 then
      Result:= TF_E_UNEXPECTED
    else begin
      Tmp:= nil;
      Result:= ByteVectorAlloc(Tmp, I);
      if Result = TF_S_OK then begin
        Move(P^, Tmp.FData, I);
        tfFreeInstance(Name); //if Name <> nil then TtfRecord.Release(Name);
        Name:= Tmp;
      end;
    end;
  end;
end;

end.
