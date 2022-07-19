{ *********************************************************** }
{ *                     TForge Library                      * }
{ *       Copyright (c) Sergey Kasandrov 1997, 2014         * }
{ *********************************************************** }

unit tfGNumerics;

interface

uses tfNumerics, Generics.Defaults, Generics.Collections;

function GetBigCardinalComparer: IComparer<BigCardinal>;
function GetBigIntegerComparer: IComparer<BigInteger>;

function GetBigCardinalEqualityComparer: IEqualityComparer<BigCardinal>;
function GetBigIntegerEqualityComparer: IEqualityComparer<BigInteger>;

type
  TBigCardinalList = class(TList<BigCardinal>)
  public
    constructor Create; overload;
  end;

  TBigIntegerList = class(TList<BigInteger>)
  public
    constructor Create; overload;
  end;

  TBigCardinalDictionary<TValue> = class(TDictionary<BigCardinal,TValue>)
  public
    constructor Create(ACapacity: Integer = 0); overload;
  end;

  TBigIntegerDictionary<TValue> = class(TDictionary<BigInteger,TValue>)
  public
    constructor Create(ACapacity: Integer = 0); overload;
  end;

implementation

function NopAddref(Inst: Pointer): Integer; stdcall;
begin
  Result := -1;
end;

function NopRelease(Inst: Pointer): Integer; stdcall;
begin
  Result := -1;
end;

function NopQueryInterface(Inst: Pointer; const IID: TGUID; out Obj): HResult; stdcall;
begin
  Result := E_NOINTERFACE;
end;

function Compare_BigCardinal(Inst: Pointer; const Left, Right: BigCardinal): Integer;
begin
  Result:= BigCardinal.Compare(Left, Right);
end;

function Compare_BigInteger(Inst: Pointer; const Left, Right: BigInteger): Integer;
begin
  Result:= BigInteger.Compare(Left, Right);
end;

function Equals_BigCardinal(Inst: Pointer; const Left, Right: BigCardinal): Boolean;
begin
  Result:= BigCardinal.Equals(Left, Right);
end;

function GetHashCode_BigCardinal(Inst: Pointer; const Value: BigCardinal): Integer;
begin
  Result:= Value.GetHashCode;
end;

function Equals_BigInteger(Inst: Pointer; const Left, Right: BigInteger): Boolean;
begin
  Result:= BigInteger.Equals(Left, Right);
end;

function GetHashCode_BigInteger(Inst: Pointer; const Value: BigInteger): Integer;
begin
  Result:= Value.GetHashCode;
end;

const
  Comparer_BigCardinal: array[0..3] of Pointer =
  (
    @NopQueryInterface,
    @NopAddref,
    @NopRelease,
    @Compare_BigCardinal
  );

  Comparer_BigInteger: array[0..3] of Pointer =
  (
    @NopQueryInterface,
    @NopAddref,
    @NopRelease,
    @Compare_BigInteger
  );

  EqualityComparer_BigCardinal: array[0..4] of Pointer =
  (
    @NopQueryInterface,
    @NopAddref,
    @NopRelease,
    @Equals_BigCardinal,
    @GetHashCode_BigCardinal
  );

  EqualityComparer_BigInteger: array[0..4] of Pointer =
  (
    @NopQueryInterface,
    @NopAddref,
    @NopRelease,
    @Equals_BigInteger,
    @GetHashCode_BigInteger
  );

type
  PDummyInstance = ^TDummyInstance;
  TDummyInstance = record
    VTable: Pointer;
  end;

const
  Comparer_BigCardinal_Instance: TDummyInstance =
    (VTable: @Comparer_BigCardinal);

  Comparer_BigInteger_Instance: TDummyInstance =
    (VTable: @Comparer_BigInteger);

  EqualityComparer_BigCardinal_Instance: TDummyInstance =
    (VTable: @EqualityComparer_BigCardinal);

  EqualityComparer_BigInteger_Instance: TDummyInstance =
    (VTable: @EqualityComparer_BigInteger);

function GetBigCardinalComparer: IComparer<BigCardinal>;
begin
  Result:= IComparer<BigCardinal>(@Comparer_BigCardinal_Instance);
end;

function GetBigIntegerComparer: IComparer<BigInteger>;
begin
  Result:= IComparer<BigInteger>(@Comparer_BigInteger_Instance);
end;

function GetBigCardinalEqualityComparer: IEqualityComparer<BigCardinal>;
begin
  Pointer(Result):= @EqualityComparer_BigCardinal_Instance;
end;

function GetBigIntegerEqualityComparer: IEqualityComparer<BigInteger>;
begin
  Pointer(Result):= @EqualityComparer_BigInteger_Instance;
end;

{ TBigCardinalList }

constructor TBigCardinalList.Create;
begin
  inherited Create(GetBigCardinalComparer);
end;

{ TBigIntegerList }

constructor TBigIntegerList.Create;
begin
  inherited Create(GetBigIntegerComparer);
end;

{ TBigCardinalDictionary<TValue> }

constructor TBigCardinalDictionary<TValue>.Create(ACapacity: Integer);
begin
  inherited Create(ACapacity, GetBigCardinalEqualityComparer);
end;

{ TBigIntegerDictionary<TValue> }

constructor TBigIntegerDictionary<TValue>.Create(ACapacity: Integer);
begin
  inherited Create(ACapacity, GetBigIntegerEqualityComparer);
end;

end.
