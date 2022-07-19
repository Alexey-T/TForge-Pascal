{ *********************************************************** }
{ *                     TForge Library                      * }
{ *       Copyright (c) Sergey Kasandrov 1997, 2016         * }
{ *********************************************************** }

unit tfNumerics;

{$I TFL.inc}

{$IFDEF TFL_LIMB32}
  {$DEFINE LIMB32}
{$ENDIF}

interface

uses SysUtils, tfLimbs, tfTypes,
    {$IFDEF TFL_DLL} tfImport {$ELSE} tfNumbers, tfMontMath {$ENDIF};

type
  BigCardinal = record
  private
    FNumber: IBigNumber;
  public
    procedure Free;

    function ToString: string;
    function ToHexString(Digits: Integer = 0; const Prefix: string = '';
                         TwoCompl: Boolean = False): string;
    function ToBytes: TBytes;

    class function TryParse(const S: string; var R: BigCardinal): Boolean; static;
    class function Parse(const S: string): BigCardinal; static;

    function GetSign: Integer;
    property Sign: Integer read GetSign;

    function GetHashCode: Integer;
    property HashCode: Integer read GetHashCode;

    class function Compare(const A, B: BigCardinal): Integer; overload; static;
    class function Compare(const A: BigCardinal; const B: TLimb): Integer; overload; static;
    class function Compare(const A: BigCardinal; const B: TIntLimb): Integer; overload; static;
    class function Compare(const A: BigCardinal; const B: TDLimb): Integer; overload; static;
    class function Compare(const A: BigCardinal; const B: TDIntLimb): Integer; overload; static;

    class function Equals(const A, B: BigCardinal): Boolean; overload; static;
//    class function Equals(const A: BigCardinal; const B: TLimb): Boolean; overload; static;
//    class function Equals(const A: BigCardinal; const B: TIntLimb): Boolean; overload; static;
//    class function Equals(const A: BigCardinal; const B: TDblLimb): Boolean; overload; static;
//    class function Equals(const A: BigCardinal; const B: TDblIntLimb): Boolean; overload; static;

    class function Pow(const Base: BigCardinal; Value: Cardinal): BigCardinal; overload; static;
    class function Sqr(const A: BigCardinal): BigCardinal; static;
    class function Sqrt(const A: BigCardinal): BigCardinal; overload; static;
    class function GCD(const A, B: BigCardinal): BigCardinal; overload; static;
    class function LCM(const A, B: BigCardinal): BigCardinal; overload; static;
    class function ModPow(const BaseValue, ExpValue, Modulo: BigCardinal): BigCardinal; static;
    class function ModInverse(const A, Modulo: BigCardinal): BigCardinal; overload; static;
    class function DivRem(const Dividend, Divisor: BigCardinal;
                          var Remainder: BigCardinal): BigCardinal; overload; static;
    class function DivRem(const Dividend: BigCardinal; Divisor: TLimb;
                          var Remainder: TLimb): BigCardinal; overload; static;
    class function DivRem(const Dividend: TLimb; Divisor: BigCardinal;
                          var Remainder: TLimb): TLimb; overload; static;

    function CompareTo(const B: BigCardinal): Integer; overload;
    function CompareTo(const B: TLimb): Integer; overload;
    function CompareTo(const B: TIntLimb): Integer; overload;
    function CompareTo(const B: TDLimb): Integer; overload;
    function CompareTo(const B: TDIntLimb): Integer; overload;

    function EqualsTo(const B: BigCardinal): Boolean; overload;
//    function EqualsTo(const B: TLimb): Boolean; overload;
//    function EqualsTo(const B: TIntLimb): Boolean; overload;
//    function EqualsTo(const B: TDblLimb): Boolean; overload;
//    function EqualsTo(const B: TDblIntLimb): Boolean; overload;

    class operator Explicit(const Value: BigCardinal): TLimb;
    class operator Explicit(const Value: BigCardinal): TIntLimb;
    class operator Explicit(const Value: BigCardinal): TDLimb;
    class operator Explicit(const Value: BigCardinal): TDIntLimb;
    class operator Implicit(const Value: TLimb): BigCardinal;
    class operator Implicit(const Value: TDLimb): BigCardinal;
    class operator Explicit(const Value: TIntLimb): BigCardinal;
    class operator Explicit(const Value: TDIntLimb): BigCardinal;
    class operator Explicit(const Value: TBytes): BigCardinal;
    class operator Explicit(const Value: string): BigCardinal;

    class operator Equal(const A, B: BigCardinal): Boolean;
    class operator NotEqual(const A, B: BigCardinal): Boolean;
    class operator GreaterThan(const A, B: BigCardinal): Boolean;
    class operator GreaterThanOrEqual(const A, B: BigCardinal): Boolean;
    class operator LessThan(const A, B: BigCardinal): Boolean;
    class operator LessThanOrEqual(const A, B: BigCardinal): Boolean;

    class operator Add(const A, B: BigCardinal): BigCardinal;
    class operator Subtract(const A, B: BigCardinal): BigCardinal;
    class operator Multiply(const A, B: BigCardinal): BigCardinal;
    class operator IntDivide(const A, B: BigCardinal): BigCardinal;
    class operator Modulus(const A, B: BigCardinal): BigCardinal;

    class operator LeftShift(const A: BigCardinal; Shift: Cardinal): BigCardinal;
    class operator RightShift(const A: BigCardinal; Shift: Cardinal): BigCardinal;

    class operator BitwiseAnd(const A, B: BigCardinal): BigCardinal;
    class operator BitwiseOr(const A, B: BigCardinal): BigCardinal;

    class operator Equal(const A: BigCardinal; const B: TLimb): Boolean;
    class operator Equal(const A: TLimb; const B: BigCardinal): Boolean;
    class operator Equal(const A: BigCardinal; const B: TIntLimb): Boolean;
    class operator Equal(const A: TIntLimb; const B: BigCardinal): Boolean;
    class operator NotEqual(const A: BigCardinal; const B: TLimb): Boolean;
    class operator NotEqual(const A: TLimb; const B: BigCardinal): Boolean;
    class operator NotEqual(const A: BigCardinal; const B: TIntLimb): Boolean;
    class operator NotEqual(const A: TIntLimb; const B: BigCardinal): Boolean;
    class operator GreaterThan(const A: BigCardinal; const B: TLimb): Boolean;
    class operator GreaterThan(const A: TLimb; const B: BigCardinal): Boolean;
    class operator GreaterThan(const A: BigCardinal; const B: TIntLimb): Boolean;
    class operator GreaterThan(const A: TIntLimb; const B: BigCardinal): Boolean;
    class operator GreaterThanOrEqual(const A: BigCardinal; const B: TLimb): Boolean;
    class operator GreaterThanOrEqual(const A: TLimb; const B: BigCardinal): Boolean;
    class operator GreaterThanOrEqual(const A: BigCardinal; const B: TIntLimb): Boolean;
    class operator GreaterThanOrEqual(const A: TIntLimb; const B: BigCardinal): Boolean;
    class operator LessThan(const A: BigCardinal; const B: TLimb): Boolean;
    class operator LessThan(const A: TLimb; const B: BigCardinal): Boolean;
    class operator LessThan(const A: BigCardinal; const B: TIntLimb): Boolean;
    class operator LessThan(const A: TIntLimb; const B: BigCardinal): Boolean;
    class operator LessThanOrEqual(const A: BigCardinal; const B: TLimb): Boolean;
    class operator LessThanOrEqual(const A: TLimb; const B: BigCardinal): Boolean;
    class operator LessThanOrEqual(const A: BigCardinal; const B: TIntLimb): Boolean;
    class operator LessThanOrEqual(const A: TIntLimb; const B: BigCardinal): Boolean;

    class operator Equal(const A: BigCardinal; const B: TDLimb): Boolean;
    class operator Equal(const A: TDLimb; const B: BigCardinal): Boolean;
    class operator Equal(const A: BigCardinal; const B: TDIntLimb): Boolean;
    class operator Equal(const A: TDIntLimb; const B: BigCardinal): Boolean;
    class operator NotEqual(const A: BigCardinal; const B: TDLimb): Boolean;
    class operator NotEqual(const A: TDLimb; const B: BigCardinal): Boolean;
    class operator NotEqual(const A: BigCardinal; const B: TDIntLimb): Boolean;
    class operator NotEqual(const A: TDIntLimb; const B: BigCardinal): Boolean;
    class operator GreaterThan(const A: BigCardinal; const B: TDLimb): Boolean;
    class operator GreaterThan(const A: TDLimb; const B: BigCardinal): Boolean;
    class operator GreaterThan(const A: BigCardinal; const B: TDIntLimb): Boolean;
    class operator GreaterThan(const A: TDIntLimb; const B: BigCardinal): Boolean;
    class operator GreaterThanOrEqual(const A: BigCardinal; const B: TDLimb): Boolean;
    class operator GreaterThanOrEqual(const A: TDLimb; const B: BigCardinal): Boolean;
    class operator GreaterThanOrEqual(const A: BigCardinal; const B: TDIntLimb): Boolean;
    class operator GreaterThanOrEqual(const A: TDIntLimb; const B: BigCardinal): Boolean;
    class operator LessThan(const A: BigCardinal; const B: TDLimb): Boolean;
    class operator LessThan(const A: TDLimb; const B: BigCardinal): Boolean;
    class operator LessThan(const A: BigCardinal; const B: TDIntLimb): Boolean;
    class operator LessThan(const A: TDIntLimb; const B: BigCardinal): Boolean;
    class operator LessThanOrEqual(const A: BigCardinal; const B: TDLimb): Boolean;
    class operator LessThanOrEqual(const A: TDLimb; const B: BigCardinal): Boolean;
    class operator LessThanOrEqual(const A: BigCardinal; const B: TDIntLimb): Boolean;
    class operator LessThanOrEqual(const A: TDIntLimb; const B: BigCardinal): Boolean;

    class operator Add(const A: BigCardinal; const B: TLimb): BigCardinal;
    class operator Add(const A: TLimb; const B: BigCardinal): BigCardinal;
    class operator Subtract(const A: BigCardinal; const B: TLimb): BigCardinal;
    class operator Subtract(const A: TLimb; const B: BigCardinal): Cardinal;
    class operator Multiply(const A: BigCardinal; const B: TLimb): BigCardinal;
    class operator Multiply(const A: TLimb; const B: BigCardinal): BigCardinal;
    class operator IntDivide(const A: BigCardinal; const B: TLimb): BigCardinal;
    class operator IntDivide(const A: TLimb; const B: BigCardinal): TLimb;
    class operator Modulus(const A: BigCardinal; const B: TLimb): TLimb;
    class operator Modulus(const A: TLimb; const B: BigCardinal): TLimb;

// unary plus
    class operator Positive(const A: BigCardinal): BigCardinal;

    class function PowerOfTwo(APower: Cardinal): BigCardinal; static;
    function IsPowerOfTwo: Boolean;

    function Next: BigCardinal;
    function Prev: BigCardinal;
  end;

  BigInteger = record
  private
    FNumber: IBigNumber;
  public
    procedure Free;

    function ToString: string;
    function ToHexString(Digits: Integer = 0; const Prefix: string = '';
                         TwoCompl: Boolean = False): string;
    function ToBytes: TBytes;

    class function TryParse(const S: string; var R: BigInteger; TwoCompl: Boolean = False): Boolean; static;
    class function Parse(const S: string; TwoCompl: Boolean = False): BigInteger; static;

    function GetSign: Integer;
    property Sign: Integer read GetSign;

    function GetHashCode: Integer;
    property HashCode: Integer read GetHashCode;

    class function Compare(const A, B: BigInteger): Integer; overload; static;
    class function Compare(const A: BigInteger; const B: BigCardinal): Integer; overload; static;
    class function Compare(const A: BigCardinal; const B: BigInteger): Integer; overload; static;

    class function Compare(const A: BigInteger; const B: TLimb): Integer; overload; static;
    class function Compare(const A: BigInteger; const B: TIntLimb): Integer; overload; static;
    class function Compare(const A: BigInteger; const B: TDLimb): Integer; overload; static;
    class function Compare(const A: BigInteger; const B: TDIntLimb): Integer; overload; static;

    function CompareTo(const B: BigInteger): Integer; overload;
    function CompareTo(const B: BigCardinal): Integer; overload;
    function CompareTo(const B: TLimb): Integer; overload;
    function CompareTo(const B: TIntLimb): Integer; overload;
    function CompareTo(const B: TDLimb): Integer; overload;
    function CompareTo(const B: TDIntLimb): Integer; overload;

    class function Equals(const A, B: BigInteger): Boolean; overload; static;
    class function Equals(const A: BigInteger; const B: BigCardinal): Boolean; overload; static;
    class function Equals(const A: BigCardinal; const B: BigInteger): Boolean; overload; static;

    function EqualsTo(const B: BigInteger): Boolean; overload;
    function EqualsTo(const B: BigCardinal): Boolean; overload;

    class function Abs(const A: BigInteger): BigInteger; static;
    class function Pow(const Base: BigInteger; Value: Cardinal): BigInteger; overload; static;
    class function Sqr(const A: BigInteger): BigInteger; static;
    class function Sqrt(const A: BigInteger): BigInteger; static;
    class function GCD(const A, B: BigInteger): BigInteger; overload; static;
    class function EGCD(const A, B: BigInteger; var X, Y: BigInteger): BigInteger; static;
    class function LCM(const A, B: BigInteger): BigInteger; overload; static;
    class function ModPow(const BaseValue, ExpValue, Modulo: BigInteger): BigInteger; static;
    class function ModInverse(const A, Modulo: BigInteger): BigInteger; overload; static;

// removed because lead to overload ambiguity with hardcoded constants
//    class function GCD(const A: BigInteger; const B: BigCardinal): BigInteger; overload; static;
//    class function GCD(const A: BigCardinal; const B: BigInteger): BigInteger; overload; static;
//    class function ModInverse(const A: BigInteger; const Modulo: BigCardinal): BigInteger; overload; static;
//    class function ModInverse(const A: BigCardinal; const Modulo: BigInteger): BigInteger; overload; static;

    class function DivRem(const Dividend, Divisor: BigInteger;
                          var Remainder: BigInteger): BigInteger; overload; static;

    class operator Implicit(const Value: BigCardinal): BigInteger; inline;
    class operator Explicit(const Value: BigInteger): BigCardinal; inline;

    class operator Explicit(const Value: BigInteger): TLimb;
    class operator Explicit(const Value: BigInteger): TDLimb;
    class operator Explicit(const Value: BigInteger): TIntLimb;
    class operator Explicit(const Value: BigInteger): TDIntLimb;
    class operator Implicit(const Value: TLimb): BigInteger;
    class operator Implicit(const Value: TDLimb): BigInteger;
    class operator Implicit(const Value: TIntLimb): BigInteger;
    class operator Implicit(const Value: TDIntLimb): BigInteger;
    class operator Explicit(const Value: TBytes): BigInteger;
    class operator Explicit(const Value: string): BigInteger;

    class operator Equal(const A, B: BigInteger): Boolean;
    class operator Equal(const A: BigInteger; const B: BigCardinal): Boolean;
    class operator Equal(const A: BigCardinal; const B: BigInteger): Boolean;
    class operator NotEqual(const A, B: BigInteger): Boolean;
    class operator NotEqual(const A: BigInteger; const B: BigCardinal): Boolean;
    class operator NotEqual(const A: BigCardinal; const B: BigInteger): Boolean;
    class operator GreaterThan(const A, B: BigInteger): Boolean;
    class operator GreaterThan(const A: BigInteger; const B: BigCardinal): Boolean;
    class operator GreaterThan(const A: BigCardinal; const B: BigInteger): Boolean;
    class operator GreaterThanOrEqual(const A, B: BigInteger): Boolean;
    class operator GreaterThanOrEqual(const A: BigInteger; const B: BigCardinal): Boolean;
    class operator GreaterThanOrEqual(const A: BigCardinal; const B: BigInteger): Boolean;
    class operator LessThan(const A, B: BigInteger): Boolean;
    class operator LessThan(const A: BigInteger; const B: BigCardinal): Boolean;
    class operator LessThan(const A: BigCardinal; const B: BigInteger): Boolean;
    class operator LessThanOrEqual(const A, B: BigInteger): Boolean;
    class operator LessThanOrEqual(const A: BigInteger; const B: BigCardinal): Boolean;
    class operator LessThanOrEqual(const A: BigCardinal; const B: BigInteger): Boolean;

    class operator Add(const A, B: BigInteger): BigInteger;
    class operator Subtract(const A, B: BigInteger): BigInteger;
    class operator Multiply(const A, B: BigInteger): BigInteger;
    class operator IntDivide(const A, B: BigInteger): BigInteger;
    class operator Modulus(const A, B: BigInteger): BigInteger;

    class operator LeftShift(const A: BigInteger; Shift: Cardinal): BigInteger;
    class operator RightShift(const A: BigInteger; Shift: Cardinal): BigInteger;

    class operator BitwiseAnd(const A, B: BigInteger): BigInteger;
    class operator BitwiseOr(const A, B: BigInteger): BigInteger;
    class operator BitwiseXor(const A, B: BigInteger): BigInteger;

    class operator Equal(const A: BigInteger; const B: TLimb): Boolean;
    class operator Equal(const A: TLimb; const B: BigInteger): Boolean;
    class operator Equal(const A: BigInteger; const B: TIntLimb): Boolean;
    class operator Equal(const A: TIntLimb; const B: BigInteger): Boolean;
    class operator NotEqual(const A: BigInteger; const B: TLimb): Boolean;
    class operator NotEqual(const A: TLimb; const B: BigInteger): Boolean;
    class operator NotEqual(const A: BigInteger; const B: TIntLimb): Boolean;
    class operator NotEqual(const A: TIntLimb; const B: BigInteger): Boolean;
    class operator GreaterThan(const A: BigInteger; const B: TLimb): Boolean;
    class operator GreaterThan(const A: TLimb; const B: BigInteger): Boolean;
    class operator GreaterThan(const A: BigInteger; const B: TIntLimb): Boolean;
    class operator GreaterThan(const A: TIntLimb; const B: BigInteger): Boolean;
    class operator GreaterThanOrEqual(const A: BigInteger; const B: TLimb): Boolean;
    class operator GreaterThanOrEqual(const A: TLimb; const B: BigInteger): Boolean;
    class operator GreaterThanOrEqual(const A: BigInteger; const B: TIntLimb): Boolean;
    class operator GreaterThanOrEqual(const A: TIntLimb; const B: BigInteger): Boolean;
    class operator LessThan(const A: BigInteger; const B: TLimb): Boolean;
    class operator LessThan(const A: TLimb; const B: BigInteger): Boolean;
    class operator LessThan(const A: BigInteger; const B: TIntLimb): Boolean;
    class operator LessThan(const A: TIntLimb; const B: BigInteger): Boolean;
    class operator LessThanOrEqual(const A: BigInteger; const B: TLimb): Boolean;
    class operator LessThanOrEqual(const A: TLimb; const B: BigInteger): Boolean;
    class operator LessThanOrEqual(const A: BigInteger; const B: TIntLimb): Boolean;
    class operator LessThanOrEqual(const A: TIntLimb; const B: BigInteger): Boolean;

    class operator Equal(const A: BigInteger; const B: TDLimb): Boolean;
    class operator Equal(const A: TDLimb; const B: BigInteger): Boolean;
    class operator Equal(const A: BigInteger; const B: TDIntLimb): Boolean;
    class operator Equal(const A: TDIntLimb; const B: BigInteger): Boolean;
    class operator NotEqual(const A: BigInteger; const B: TDLimb): Boolean;
    class operator NotEqual(const A: TDLimb; const B: BigInteger): Boolean;
    class operator NotEqual(const A: BigInteger; const B: TDIntLimb): Boolean;
    class operator NotEqual(const A: TDIntLimb; const B: BigInteger): Boolean;
    class operator GreaterThan(const A: BigInteger; const B: TDLimb): Boolean;
    class operator GreaterThan(const A: TDLimb; const B: BigInteger): Boolean;
    class operator GreaterThan(const A: BigInteger; const B: TDIntLimb): Boolean;
    class operator GreaterThan(const A: TDIntLimb; const B: BigInteger): Boolean;
    class operator GreaterThanOrEqual(const A: BigInteger; const B: TDLimb): Boolean;
    class operator GreaterThanOrEqual(const A: TDLimb; const B: BigInteger): Boolean;
    class operator GreaterThanOrEqual(const A: BigInteger; const B: TDIntLimb): Boolean;
    class operator GreaterThanOrEqual(const A: TDIntLimb; const B: BigInteger): Boolean;
    class operator LessThan(const A: BigInteger; const B: TDLimb): Boolean;
    class operator LessThan(const A: TDLimb; const B: BigInteger): Boolean;
    class operator LessThan(const A: BigInteger; const B: TDIntLimb): Boolean;
    class operator LessThan(const A: TDIntLimb; const B: BigInteger): Boolean;
    class operator LessThanOrEqual(const A: BigInteger; const B: TDLimb): Boolean;
    class operator LessThanOrEqual(const A: TDLimb; const B: BigInteger): Boolean;
    class operator LessThanOrEqual(const A: BigInteger; const B: TDIntLimb): Boolean;
    class operator LessThanOrEqual(const A: TDIntLimb; const B: BigInteger): Boolean;

// arithmetic operations on BigInteger & TLimb
    class operator Add(const A: BigInteger; const B: TLimb): BigInteger;
    class operator Subtract(const A: BigInteger; const B: TLimb): BigInteger;
    class operator Multiply(const A: BigInteger; const B: TLimb): BigInteger;
    class operator IntDivide(const A: BigInteger; const B: TLimb): BigInteger;
    class operator Modulus(const A: BigInteger; const B: TLimb): BigInteger;
    class function DivRem(const Dividend: BigInteger; const Divisor: TLimb;
                          var Remainder: BigInteger): BigInteger; overload; static;

// arithmetic operations on TLimb & BigInteger
    class operator Add(const A: TLimb; const B: BigInteger): BigInteger;
    class operator Subtract(const A: TLimb; const B: BigInteger): BigInteger;
    class operator Multiply(const A: TLimb; const B: BigInteger): BigInteger;
    class operator IntDivide(const A: TLimb; const B: BigInteger): BigInteger;
    class operator Modulus(const A: TLimb; const B: BigInteger): TLimb;
    class function DivRem(const Dividend: TLimb; const Divisor: BigInteger;
                          var Remainder: TLimb): BigInteger; overload; static;

// arithmetic operations on BigInteger & TIntLimb
    class operator Add(const A: BigInteger; const B: TIntLimb): BigInteger;
    class operator Subtract(const A: BigInteger; const B: TIntLimb): BigInteger;
    class operator Multiply(const A: BigInteger; const B: TIntLimb): BigInteger;
    class operator IntDivide(const A: BigInteger; const B: TIntLimb): BigInteger;
    class operator Modulus(const A: BigInteger; const B: TIntLimb): TIntLimb;
    class function DivRem(const Dividend: BigInteger; const Divisor: TIntLimb;
                          var Remainder: TIntLimb): BigInteger; overload; static;

// arithmetic operations on TIntLimb & BigInteger
    class operator Add(const A: TIntLimb; const B: BigInteger): BigInteger;
    class operator Subtract(const A: TIntLimb; const B: BigInteger): BigInteger;
    class operator Multiply(const A: TIntLimb; const B: BigInteger): BigInteger;
    class operator IntDivide(const A: TIntLimb; const B: BigInteger): TIntLimb;
    class operator Modulus(const A: TIntLimb; const B: BigInteger): TIntLimb;
    class function DivRem(const Dividend: TIntLimb; const Divisor: BigInteger;
                          var Remainder: TIntLimb): TIntLimb; overload; static;

// unary minus/plus
    class operator Negative(const A: BigInteger): BigInteger;
    class operator Positive(const A: BigInteger): BigInteger;

    function Next: BigInteger;
    function Prev: BigInteger;

    class function PowerOfTwo(APower: Cardinal): BigInteger; static;
    function IsPowerOfTwo: Boolean;
    function IsEven: Boolean;

// -- mutating methods will NOT be supported in user classes
//    procedure SelfAdd(const A: BigInteger); overload;
//    procedure SelfAdd(const A: TLimb); overload;
//    procedure SelfAdd(const A: TIntLimb); overload;

//    procedure SelfSub(const A: BigInteger); overload;
//    procedure SelfSub(const A: TLimb); overload;
//    procedure SelfSub(const A: TIntLimb); overload;

end;

type
  TMont = record
  private
    FInstance: IMont;
  public
    class function GetInstance(const Modulus: BigInteger): TMont; static;
    procedure Free;
    function IsAssigned: Boolean;
    procedure Burn;
    function Reduce(const A: BigInteger): BigInteger;
    function Convert(const A: BigInteger): BigInteger;
    function Add(const A, B: BigInteger): BigInteger;
    function Subtract(const A, B: BigInteger): BigInteger;
    function Multiply(const A, B: BigInteger): BigInteger;
    function ModMul(const A, B: BigInteger): BigInteger;
    function ModPow(const Base, Pow: BigInteger): BigInteger; overload;
    function ModPow(const Base: BigInteger; Pow: TLimb): BigInteger; overload;
    function GetRModulus: BigInteger;
  end;

type
  EBigNumberError = class(Exception)
  private
    FCode: TF_RESULT;
  public
    constructor Create(ACode: TF_RESULT; const Msg: string = '');
    property Code: TF_RESULT read FCode;
  end;

procedure BigNumberError(ACode: TF_RESULT; const Msg: string = '');

implementation

{ EBigNumberError }

constructor EBigNumberError.Create(ACode: TF_RESULT; const Msg: string);
begin
  if Msg = '' then
    inherited Create(Format('Big Number Error 0x%.8x', [ACode]))
  else
    inherited Create(Msg);
  FCode:= ACode;
end;

procedure BigNumberError(ACode: TF_RESULT; const Msg: string);
begin
  raise EBigNumberError.Create(ACode, Msg);
end;

procedure HResCheck(Value: TF_RESULT); inline;
begin
  if Value <> TF_S_OK then
    BigNumberError(Value);
end;

{-----------------------  Compare Inlines ----------------------}

function Compare_BigCard_BigCard(const A, B: BigCardinal): Integer; inline;
begin
{$IFDEF TFL_INTFCALL}
  Result:= A.FNumber.CompareNumberU(B.FNumber);
{$ELSE}
  Result:= TBigNumber.CompareNumbersU(PBigNumber(A.FNumber),
                      PBigNumber(B.FNumber));
{$ENDIF}
end;

function Compare_BigInt_BigInt(const A, B: BigInteger): Integer; inline;
begin
{$IFDEF TFL_INTFCALL}
  Result:= A.FNumber.CompareNumber(B.FNumber);
{$ELSE}
  Result:= TBigNumber.CompareNumbers(PBigNumber(A.FNumber),
                      PBigNumber(B.FNumber));
{$ENDIF}
end;

function Compare_BigInt_BigCard(const A: BigInteger; const B: BigCardinal): Integer; inline;
begin
{$IFDEF TFL_INTFCALL}
  Result:= A.FNumber.CompareNumber(B.FNumber);
{$ELSE}
  Result:= TBigNumber.CompareNumbers(PBigNumber(A.FNumber),
                      PBigNumber(B.FNumber));
{$ENDIF}
end;

function Compare_BigCard_BigInt(const A: BigCardinal; const B: BigInteger): Integer; inline;
begin
{$IFDEF TFL_INTFCALL}
  Result:= A.FNumber.CompareNumber(B.FNumber);
{$ELSE}
  Result:= TBigNumber.CompareNumbers(PBigNumber(A.FNumber),
                      PBigNumber(B.FNumber));
{$ENDIF}
end;

function Compare_BigCard_Limb(const A: BigCardinal; const B: TLimb): Integer; inline;
begin
{$IFDEF TFL_INTFCALL}
  Result:= A.FNumber.CompareToLimbU(B);
{$ELSE}
  Result:= TBigNumber.CompareToLimbU(PBigNumber(A.FNumber), B);
{$ENDIF}
end;

function Compare_BigCard_IntLimb(const A: BigCardinal; const B: TIntLimb): Integer; inline;
begin
{$IFDEF TFL_INTFCALL}
  Result:= A.FNumber.CompareToIntLimbU(B);
{$ELSE}
  Result:= TBigNumber.CompareToIntLimbU(PBigNumber(A.FNumber), B);
{$ENDIF}
end;

function Compare_BigCard_DblLimb(const A: BigCardinal; const B: TDLimb): Integer; inline;
begin
{$IFDEF TFL_INTFCALL}
  Result:= A.FNumber.CompareToDblLimbU(B);
{$ELSE}
  Result:= TBigNumber.CompareToDblLimbU(PBigNumber(A.FNumber), B);
{$ENDIF}
end;

function Compare_BigCard_DblIntLimb(const A: BigCardinal; const B: TDIntLimb): Integer; inline;
begin
{$IFDEF TFL_INTFCALL}
  Result:= A.FNumber.CompareToDblIntLimbU(B);
{$ELSE}
  Result:= TBigNumber.CompareToDblIntLimbU(PBigNumber(A.FNumber), B);
{$ENDIF}
end;

function Compare_BigInt_Limb(const A: BigInteger; const B: TLimb): Integer; inline;
begin
{$IFDEF TFL_INTFCALL}
  Result:= A.FNumber.CompareToLimb(B);
{$ELSE}
  Result:= TBigNumber.CompareToLimb(PBigNumber(A.FNumber), B);
{$ENDIF}
end;

function Compare_BigInt_IntLimb(const A: BigInteger; const B: TIntLimb): Integer; inline;
begin
{$IFDEF TFL_INTFCALL}
  Result:= A.FNumber.CompareToIntLimb(B);
{$ELSE}
  Result:= TBigNumber.CompareToIntLimb(PBigNumber(A.FNumber), B);
{$ENDIF}
end;

function Compare_BigInt_DblLimb(const A: BigInteger; const B: TDLimb): Integer; inline;
begin
{$IFDEF TFL_INTFCALL}
  Result:= A.FNumber.CompareToDblLimb(B);
{$ELSE}
  Result:= TBigNumber.CompareToDblLimb(PBigNumber(A.FNumber), B);
{$ENDIF}
end;

function Compare_BigInt_DblIntLimb(const A: BigInteger; const B: TDIntLimb): Integer; inline;
begin
{$IFDEF TFL_INTFCALL}
  Result:= A.FNumber.CompareToDblIntLimb(B);
{$ELSE}
  Result:= TBigNumber.CompareToDblIntLimb(PBigNumber(A.FNumber), B);
{$ENDIF}
end;

{------------------------ Equal Inlines -----------------------}

function Equal_BigCard_BigCard(const A, B: BigCardinal): Boolean; inline;
begin
{$IFDEF TFL_INTFCALL}
  Result:= A.FNumber.EqualsNumberU(B.FNumber);
{$ELSE}
  Result:= TBigNumber.EqualNumbersU(PBigNumber(A.FNumber),
                      PBigNumber(B.FNumber));
{$ENDIF}
end;

function Equal_BigInt_BigInt(const A, B: BigInteger): Boolean; inline;
begin
{$IFDEF TFL_INTFCALL}
  Result:= A.FNumber.EqualsNumber(B.FNumber);
{$ELSE}
  Result:= TBigNumber.EqualNumbers(PBigNumber(A.FNumber),
                      PBigNumber(B.FNumber));
{$ENDIF}
end;

function Equal_BigInt_BigCard(const A: BigInteger; const B: BigCardinal): Boolean; inline;
begin
{$IFDEF TFL_INTFCALL}
  Result:= A.FNumber.EqualsNumber(B.FNumber);
{$ELSE}
  Result:= TBigNumber.EqualNumbers(PBigNumber(A.FNumber),
                      PBigNumber(B.FNumber));
{$ENDIF}
end;

function Equal_BigCard_BigInt(const A: BigCardinal; const B: BigInteger): Boolean; inline;
begin
{$IFDEF TFL_INTFCALL}
  Result:= A.FNumber.EqualsNumber(B.FNumber);
{$ELSE}
  Result:= TBigNumber.EqualNumbers(PBigNumber(A.FNumber),
                      PBigNumber(B.FNumber));
{$ENDIF}
end;

function Equal_BigCard_Limb(const A: BigCardinal; const B: TLimb): Boolean; inline;
begin
  Result:= Compare_BigCard_Limb(A, B) = 0;
end;

function Equal_BigCard_IntLimb(const A: BigCardinal; const B: TIntLimb): Boolean; inline;
begin
  Result:= Compare_BigCard_IntLimb(A, B) = 0;
end;

function Equal_BigCard_DblLimb(const A: BigCardinal; const B: TDLimb): Boolean; inline;
begin
  Result:= Compare_BigCard_DblLimb(A, B) = 0;
end;

function Equal_BigCard_DblIntLimb(const A: BigCardinal; const B: TDIntLimb): Boolean; inline;
begin
  Result:= Compare_BigCard_DblIntLimb(A, B) = 0;
end;

function Equal_BigInt_Limb(const A: BigInteger; const B: TLimb): Boolean; inline;
begin
  Result:= Compare_BigInt_Limb(A, B) = 0;
end;

function Equal_BigInt_IntLimb(const A: BigInteger; const B: TIntLimb): Boolean; inline;
begin
  Result:= Compare_BigInt_IntLimb(A, B) = 0;
end;

function Equal_BigInt_DblLimb(const A: BigInteger; const B: TDLimb): Boolean; inline;
begin
  Result:= Compare_BigInt_DblLimb(A, B) = 0;
end;

function Equal_BigInt_DblIntLimb(const A: BigInteger; const B: TDIntLimb): Boolean; inline;
begin
  Result:= Compare_BigInt_DblIntLimb(A, B) = 0;
end;

{ BigCardinal }

function BigCardinal.ToString: string;
var
  BytesUsed: Integer;
  L: Integer;
  P, P1: PByte;
  I: Integer;

begin
{$IFDEF TFL_INTFCALL}
  BytesUsed:= FNumber.GetSize;
{$ELSE}
  BytesUsed:= TBigNumber.GetSize(PBigNumber(FNumber));
{$ENDIF}
// log(256) approximated from above by 41/17
  L:= (BytesUsed * 41) div 17 + 1;
  GetMem(P, L);
  try
{$IFDEF TFL_INTFCALL}
    HResCheck(FNumber.ToDec(P, L));
{$ELSE}
    HResCheck(TBigNumber.ToDec(PBigNumber(FNumber), P, L));
{$ENDIF}
    Result:= '';
    SetLength(Result, L);
    P1:= P;
    for I:= 1 to L do begin
      Result[I]:= Char(P1^);
      Inc(P1);
    end;
  finally
    FreeMem(P);
  end;
end;

function BigCardinal.ToHexString(Digits: Integer; const Prefix: string;
                         TwoCompl: Boolean): string;
var
  L: Integer;
  P, P1: PByte;
  HR: TF_RESULT;
  I: Integer;

begin
  HR:= FNumber.ToHex(nil, L, TwoCompl);
  if HR = TF_E_INVALIDARG then begin
    GetMem(P, L);
    try
{$IFDEF TFL_INTFCALL}
      HResCheck(FNumber.ToHex(P, L, TwoCompl));
{$ELSE}
      HResCheck(TBigNumber.ToHex(PBigNumber(FNumber), P, L, TwoCompl));
{$ENDIF}
      if Digits < L then Digits:= L;
      Inc(Digits, Length(Prefix));
      Result:= '';
      SetLength(Result, Digits);
      Move(Pointer(Prefix)^, Pointer(Result)^, Length(Prefix) * SizeOf(Char));
      P1:= P;
      I:= Length(Prefix);
      while I + L < Digits do begin
        Inc(I);
        Result[I]:= '0';
      end;
      while I < Digits do begin
        Inc(I);
        Result[I]:= Char(P1^);
        Inc(P1);
      end;
    finally
      FreeMem(P);
    end;
  end
  else
    BigNumberError(HR);
end;

function BigCardinal.ToBytes: TBytes;
var
  HR: TF_RESULT;
  L: Cardinal;

begin
  L:= 0;
  HR:= FNumber.ToPByte(nil, L);
  if (HR = TF_E_INVALIDARG) and (L > 0) then begin
    Result:= nil;
    SetLength(Result, L);
{$IFDEF TFL_INTFCALL}
    HR:= FNumber.ToPByte(Pointer(Result), L);
{$ELSE}
    HR:= TBigNumber.ToPByte(PBigNumber(FNumber), Pointer(Result), L);
{$ENDIF}
  end;
  HResCheck(HR);
end;

class function BigCardinal.Parse(const S: string): BigCardinal;
begin
{$IFDEF TFL_DLL}
  HResCheck(BigNumberFromPChar(Result.FNumber, Pointer(S), Length(S),
                               SizeOf(Char), False, False));
{$ELSE}
  HResCheck(BigNumberFromPChar(PBigNumber(Result.FNumber), Pointer(S), Length(S),
                              SizeOf(Char), False, False));
{$ENDIF}
end;

class function BigCardinal.TryParse(const S: string; var R: BigCardinal): Boolean;
begin
{$IFDEF TFL_DLL}
  Result:= BigNumberFromPChar(R.FNumber, Pointer(S), Length(S),
                              SizeOf(Char), False, False) = TF_S_OK;
{$ELSE}
  Result:= BigNumberFromPChar(PBigNumber(R.FNumber), Pointer(S), Length(S),
                              SizeOf(Char), False, False) = TF_S_OK;
{$ENDIF}
end;

function BigCardinal.GetHashCode: Integer;
begin
{$IFDEF TFL_INTFCALL}
  Result:= FNumber.GetHashCode;
{$ELSE}
  Result:= TBigNumber.GetHashCode(PBigNumber(FNumber));
{$ENDIF}
end;

function BigCardinal.GetSign: Integer;
begin
{$IFDEF TFL_INTFCALL}
  Result:= FNumber.GetSign;
{$ELSE}
  Result:= TBigNumber.GetSign(PBigNumber(FNumber));
{$ENDIF}
end;

function BigCardinal.CompareTo(const B: BigCardinal): Integer;
begin
  Result:= Compare_BigCard_BigCard(Self, B);
end;

function BigCardinal.EqualsTo(const B: BigCardinal): Boolean;
begin
  Result:= Equal_BigCard_BigCard(Self, B);
end;

class operator BigCardinal.Equal(const A, B: BigCardinal): Boolean;
begin
  Result:= Equal_BigCard_BigCard(A, B);
end;

class operator BigCardinal.NotEqual(const A, B: BigCardinal): Boolean;
begin
  Result:= not Equal_BigCard_BigCard(A, B);
end;

class operator BigCardinal.GreaterThan(const A, B: BigCardinal): Boolean;
begin
  Result:= Compare_BigCard_BigCard(A, B) > 0;
end;

class operator BigCardinal.GreaterThanOrEqual(const A, B: BigCardinal): Boolean;
begin
  Result:= Compare_BigCard_BigCard(A, B) >= 0;
end;

class operator BigCardinal.LessThan(const A, B: BigCardinal): Boolean;
begin
  Result:= Compare_BigCard_BigCard(A, B) < 0;
end;

class operator BigCardinal.LessThanOrEqual(const A, B: BigCardinal): Boolean;
begin
  Result:= Compare_BigCard_BigCard(A, B) <= 0;
end;

class function BigCardinal.LCM(const A, B: BigCardinal): BigCardinal;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(A.FNumber.LCM(B.FNumber, Result.FNumber));
{$ELSE}
  HResCheck(TBigNumber.LCM(PBigNumber(A.FNumber), PBigNumber(B.FNumber),
            PBigNumber(Result.FNumber)));
{$ENDIF}
end;

class operator BigCardinal.LeftShift(const A: BigCardinal; Shift: Cardinal): BigCardinal;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(A.FNumber.ShlNumber(Shift, Result.FNumber));
{$ELSE}
  HResCheck(TBigNumber.ShlNumber(PBigNumber(A.FNumber), Shift,
                       PBigNumber(Result.FNumber)));
{$ENDIF}
end;

class operator BigCardinal.RightShift(const A: BigCardinal; Shift: Cardinal): BigCardinal;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(A.FNumber.ShrNumber(Shift, Result.FNumber));
{$ELSE}
  HResCheck(TBigNumber.ShrNumber(PBigNumber(A.FNumber), Shift,
                       PBigNumber(Result.FNumber)));
{$ENDIF}
end;

class operator BigCardinal.Explicit(const Value: string): BigCardinal;
begin
{$IFDEF TFL_DLL}
  HResCheck(BigNumberFromPChar(Result.FNumber, Pointer(Value), Length(Value),
                               SizeOf(Char), False, False));
{$ELSE}
  HResCheck(BigNumberFromPChar(PBigNumber(Result.FNumber), Pointer(Value),
            Length(Value), SizeOf(Char), False, False));
{$ENDIF}
end;

class operator BigCardinal.Explicit(const Value: TBytes): BigCardinal;
begin
  HResCheck(BigNumberFromPByte(
{$IFDEF TFL_DLL}
    Result.FNumber,
{$ELSE}
    PBigNumber(Result.FNumber),
{$ENDIF}
      Pointer(Value), Length(Value), False));
end;

procedure BigCardinal.Free;
begin
  FNumber:= nil;
end;

class operator BigCardinal.Explicit(const Value: BigCardinal): TLimb;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(Value.FNumber.ToLimb(Result));
{$ELSE}
  HResCheck(TBigNumber.ToLimb(PBigNumber(Value.FNumber), Result));
{$ENDIF}
end;

class operator BigCardinal.Explicit(const Value: BigCardinal): TIntLimb;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(Value.FNumber.ToIntLimb(Result));
{$ELSE}
  HResCheck(TBigNumber.ToIntLimb(PBigNumber(Value.FNumber), Result));
{$ENDIF}
end;

class operator BigCardinal.Explicit(const Value: BigCardinal): TDLimb;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(Value.FNumber.ToDblLimb(Result));
{$ELSE}
  HResCheck(TBigNumber.ToDblLimb(PBigNumber(Value.FNumber), Result));
{$ENDIF}
end;

class operator BigCardinal.Explicit(const Value: BigCardinal): TDIntLimb;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(Value.FNumber.ToDblIntLimb(Result));
{$ELSE}
  HResCheck(TBigNumber.ToDblIntLimb(PBigNumber(Value.FNumber), Result));
{$ENDIF}
end;

class operator BigCardinal.Explicit(const Value: TIntLimb): BigCardinal;
begin
  if Value < 0 then
    BigNumberError(TF_E_INVALIDARG)
  else begin
{$IFDEF TFL_INTFCALL}
    HResCheck(BigNumberFromIntLimb(Result.FNumber, TLimb(Value)));
{$ELSE}
    HResCheck(BigNumberFromIntLimb(PBigNumber(Result.FNumber), TLimb(Value)));
{$ENDIF}
  end;
end;

class operator BigCardinal.Explicit(const Value: TDIntLimb): BigCardinal;
begin
  if Value < 0 then
    BigNumberError(TF_E_INVALIDARG)
  else begin
{$IFDEF TFL_INTFCALL}
    HResCheck(BigNumberFromDblIntLimb(Result.FNumber, TDblLimb(Value)));
{$ELSE}
    HResCheck(BigNumberFromDblIntLimb(PBigNumber(Result.FNumber), TDLimb(Value)));
{$ENDIF}
  end;
end;

class operator BigCardinal.Implicit(const Value: TLimb): BigCardinal;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(BigNumberFromLimb(Result.FNumber, Value));
{$ELSE}
  HResCheck(BigNumberFromLimb(PBigNumber(Result.FNumber), Value));
{$ENDIF}
end;

class operator BigCardinal.Implicit(const Value: TDLimb): BigCardinal;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(BigNumberFromDblLimb(Result.FNumber, Value));
{$ELSE}
  HResCheck(BigNumberFromDblLimb(PBigNumber(Result.FNumber), Value));
{$ENDIF}
end;

class operator BigCardinal.BitwiseAnd(const A, B: BigCardinal): BigCardinal;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(A.FNumber.AndNumberU(B.FNumber, Result.FNumber));
{$ELSE}
  HResCheck(TBigNumber.AndNumbersU(PBigNumber(A.FNumber),
            PBigNumber(B.FNumber), PBigNumber(Result.FNumber)));
{$ENDIF}
end;

class operator BigCardinal.BitwiseOr(const A, B: BigCardinal): BigCardinal;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(A.FNumber.OrNumberU(B.FNumber, Result.FNumber));
{$ELSE}
  HResCheck(TBigNumber.OrNumbersU(PBigNumber(A.FNumber),
            PBigNumber(B.FNumber), PBigNumber(Result.FNumber)));
{$ENDIF}
end;

class operator BigCardinal.Add(const A, B: BigCardinal): BigCardinal;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(A.FNumber.AddNumberU(B.FNumber, Result.FNumber));
{$ELSE}
  HResCheck(TBigNumber.AddNumbersU(PBigNumber(A.FNumber),
            PBigNumber(B.FNumber), PBigNumber(Result.FNumber)));
{$ENDIF}
end;

class operator BigCardinal.Subtract(const A, B: BigCardinal): BigCardinal;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(A.FNumber.SubNumberU(B.FNumber, Result.FNumber));
{$ELSE}
  HResCheck(TBigNumber.SubNumbersU(PBigNumber(A.FNumber),
            PBigNumber(B.FNumber), PBigNumber(Result.FNumber)));
{$ENDIF}
end;

class operator BigCardinal.Multiply(const A, B: BigCardinal): BigCardinal;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(A.FNumber.MulNumberU(B.FNumber, Result.FNumber));
{$ELSE}
  HResCheck(TBigNumber.MulNumbersU(PBigNumber(A.FNumber),
            PBigNumber(B.FNumber), PBigNumber(Result.FNumber)));
{$ENDIF}
end;

class operator BigCardinal.IntDivide(const A, B: BigCardinal): BigCardinal;
var
  Remainder: IBigNumber;

begin
{$IFDEF TFL_INTFCALL}
  HResCheck(A.FNumber.DivRemNumberU(B.FNumber, Result.FNumber, Remainder));
{$ELSE}
  HResCheck(TBigNumber.DivRemNumbersU(PBigNumber(A.FNumber),
            PBigNumber(B.FNumber), PBigNumber(Result.FNumber),
            PBigNumber(Remainder)));
{$ENDIF}
end;

class operator BigCardinal.Modulus(const A, B: BigCardinal): BigCardinal;
var
  Quotient: IBigNumber;

begin
{$IFDEF TFL_INTFCALL}
  HResCheck(A.FNumber.DivRemNumberU(B.FNumber, Quotient, Result.FNumber));
{$ELSE}
  HResCheck(TBigNumber.DivRemNumbersU(PBigNumber(A.FNumber),
            PBigNumber(B.FNumber), PBigNumber(Quotient),
            PBigNumber(Result.FNumber)));
{$ENDIF}
end;

function BigCardinal.CompareTo(const B: TLimb): Integer;
begin
  Result:= Compare_BigCard_Limb(Self, B);
end;

function BigCardinal.CompareTo(const B: TIntLimb): Integer;
begin
  Result:= Compare_BigCard_IntLimb(Self, B);
end;

function BigCardinal.CompareTo(const B: TDLimb): Integer;
begin
  Result:= Compare_BigCard_DblLimb(Self, B);
end;

function BigCardinal.CompareTo(const B: TDIntLimb): Integer;
begin
  Result:= Compare_BigCard_DblIntLimb(Self, B);
end;

class operator BigCardinal.Equal(const A: BigCardinal; const B: TLimb): Boolean;
begin
  Result:= Equal_BigCard_Limb(A, B);
end;

class operator BigCardinal.Equal(const A: TLimb; const B: BigCardinal): Boolean;
begin
  Result:= Equal_BigCard_Limb(B, A);
end;

class operator BigCardinal.Equal(const A: BigCardinal; const B: TIntLimb): Boolean;
begin
  Result:= Equal_BigCard_IntLimb(A, B);
end;

class operator BigCardinal.Equal(const A: TIntLimb; const B: BigCardinal): Boolean;
begin
  Result:= Equal_BigCard_IntLimb(B, A);
end;

class operator BigCardinal.NotEqual(const A: BigCardinal; const B: TLimb): Boolean;
begin
  Result:= not Equal_BigCard_Limb(A, B);
end;

class operator BigCardinal.NotEqual(const A: TLimb; const B: BigCardinal): Boolean;
begin
  Result:= not Equal_BigCard_Limb(B, A);
end;

class operator BigCardinal.NotEqual(const A: BigCardinal; const B: TIntLimb): Boolean;
begin
  Result:= not Equal_BigCard_IntLimb(A, B);
end;

class operator BigCardinal.NotEqual(const A: TIntLimb; const B: BigCardinal): Boolean;
begin
  Result:= not Equal_BigCard_IntLimb(B, A);
end;

class operator BigCardinal.GreaterThan(const A: BigCardinal; const B: TLimb): Boolean;
begin
  Result:= Compare_BigCard_Limb(A, B) > 0;
end;

class operator BigCardinal.GreaterThan(const A: TLimb; const B: BigCardinal): Boolean;
begin
  Result:= Compare_BigCard_Limb(B, A) < 0;
end;

class operator BigCardinal.GreaterThan(const A: BigCardinal; const B: TIntLimb): Boolean;
begin
  Result:= Compare_BigCard_IntLimb(A, B) > 0;
end;

class operator BigCardinal.GreaterThan(const A: TIntLimb; const B: BigCardinal): Boolean;
begin
  Result:= Compare_BigCard_IntLimb(B, A) < 0;
end;

class operator BigCardinal.GreaterThanOrEqual(const A: BigCardinal; const B: TLimb): Boolean;
begin
  Result:= Compare_BigCard_Limb(A, B) >= 0;
end;

class operator BigCardinal.GreaterThanOrEqual(const A: TLimb; const B: BigCardinal): Boolean;
begin
  Result:= Compare_BigCard_Limb(B, A) <= 0;
end;

class operator BigCardinal.GreaterThanOrEqual(const A: BigCardinal; const B: TIntLimb): Boolean;
begin
  Result:= Compare_BigCard_IntLimb(A, B) >= 0;
end;

class operator BigCardinal.GreaterThanOrEqual(const A: TIntLimb; const B: BigCardinal): Boolean;
begin
  Result:= Compare_BigCard_IntLimb(B, A) <= 0;
end;

class operator BigCardinal.LessThan(const A: BigCardinal; const B: TLimb): Boolean;
begin
  Result:= Compare_BigCard_Limb(A, B) < 0;
end;

class operator BigCardinal.LessThan(const A: TLimb; const B: BigCardinal): Boolean;
begin
  Result:= Compare_BigCard_Limb(B, A) > 0;
end;

class operator BigCardinal.LessThan(const A: BigCardinal; const B: TIntLimb): Boolean;
begin
  Result:= Compare_BigCard_IntLimb(A, B) < 0;
end;

class operator BigCardinal.LessThan(const A: TIntLimb; const B: BigCardinal): Boolean;
begin
  Result:= Compare_BigCard_IntLimb(B, A) > 0;
end;

class operator BigCardinal.LessThanOrEqual(const A: BigCardinal; const B: TLimb): Boolean;
begin
  Result:= Compare_BigCard_Limb(A, B) <= 0;
end;

class operator BigCardinal.LessThanOrEqual(const A: TLimb; const B: BigCardinal): Boolean;
begin
  Result:= Compare_BigCard_Limb(B, A) >= 0;
end;

class operator BigCardinal.LessThanOrEqual(const A: BigCardinal; const B: TIntLimb): Boolean;
begin
  Result:= Compare_BigCard_IntLimb(A, B) <= 0;
end;

class operator BigCardinal.LessThanOrEqual(const A: TIntLimb; const B: BigCardinal): Boolean;
begin
  Result:= Compare_BigCard_IntLimb(B, A) >= 0;
end;

class operator BigCardinal.Equal(const A: BigCardinal; const B: TDLimb): Boolean;
begin
  Result:= Equal_BigCard_DblLimb(A, B);
end;

class operator BigCardinal.Equal(const A: TDLimb; const B: BigCardinal): Boolean;
begin
  Result:= Equal_BigCard_DblLimb(B, A);
end;

class operator BigCardinal.Equal(const A: BigCardinal; const B: TDIntLimb): Boolean;
begin
  Result:= Equal_BigCard_DblIntLimb(A, B);
end;

class operator BigCardinal.Equal(const A: TDIntLimb; const B: BigCardinal): Boolean;
begin
  Result:= Equal_BigCard_DblIntLimb(B, A);
end;

class operator BigCardinal.NotEqual(const A: BigCardinal; const B: TDLimb): Boolean;
begin
  Result:= not Equal_BigCard_DblLimb(A, B);
end;

class operator BigCardinal.NotEqual(const A: TDLimb; const B: BigCardinal): Boolean;
begin
  Result:= not Equal_BigCard_DblLimb(B, A);
end;

class operator BigCardinal.NotEqual(const A: BigCardinal; const B: TDIntLimb): Boolean;
begin
  Result:= not Equal_BigCard_DblIntLimb(A, B);
end;

function BigCardinal.Next: BigCardinal;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(FNumber.NextNumberU(Result.FNumber);
{$ELSE}
  HResCheck(TBigNumber.NextNumberU(PBigNumber(FNumber),
                                       PBigNumber(Result.FNumber)));
{$ENDIF}
end;

class operator BigCardinal.NotEqual(const A: TDIntLimb; const B: BigCardinal): Boolean;
begin
  Result:= not Equal_BigCard_DblIntLimb(B, A);
end;

class operator BigCardinal.GreaterThan(const A: BigCardinal; const B: TDLimb): Boolean;
begin
  Result:= Compare_BigCard_DblLimb(A, B) > 0;
end;

class operator BigCardinal.GreaterThan(const A: TDLimb; const B: BigCardinal): Boolean;
begin
  Result:= Compare_BigCard_DblLimb(B, A) < 0;
end;

class operator BigCardinal.GreaterThan(const A: BigCardinal; const B: TDIntLimb): Boolean;
begin
  Result:= Compare_BigCard_DblIntLimb(A, B) > 0;
end;

class operator BigCardinal.GreaterThan(const A: TDIntLimb; const B: BigCardinal): Boolean;
begin
  Result:= Compare_BigCard_DblIntLimb(B, A) < 0;
end;

class operator BigCardinal.GreaterThanOrEqual(const A: BigCardinal; const B: TDLimb): Boolean;
begin
  Result:= Compare_BigCard_DblLimb(A, B) >= 0;
end;

class operator BigCardinal.GreaterThanOrEqual(const A: TDLimb; const B: BigCardinal): Boolean;
begin
  Result:= Compare_BigCard_DblLimb(B, A) <= 0;
end;

class operator BigCardinal.GreaterThanOrEqual(const A: BigCardinal; const B: TDIntLimb): Boolean;
begin
  Result:= Compare_BigCard_DblIntLimb(A, B) >= 0;
end;

class operator BigCardinal.GreaterThanOrEqual(const A: TDIntLimb; const B: BigCardinal): Boolean;
begin
  Result:= Compare_BigCard_DblIntLimb(B, A) <= 0;
end;

class operator BigCardinal.LessThan(const A: BigCardinal; const B: TDLimb): Boolean;
begin
  Result:= Compare_BigCard_DblLimb(A, B) < 0;
end;

class operator BigCardinal.LessThan(const A: TDLimb; const B: BigCardinal): Boolean;
begin
  Result:= Compare_BigCard_DblLimb(B, A) > 0;
end;

class operator BigCardinal.LessThan(const A: BigCardinal; const B: TDIntLimb): Boolean;
begin
  Result:= Compare_BigCard_DblIntLimb(A, B) < 0;
end;

class operator BigCardinal.LessThan(const A: TDIntLimb; const B: BigCardinal): Boolean;
begin
  Result:= Compare_BigCard_DblIntLimb(B, A) > 0;
end;

class operator BigCardinal.LessThanOrEqual(const A: BigCardinal; const B: TDLimb): Boolean;
begin
  Result:= Compare_BigCard_DblLimb(A, B) <= 0;
end;

class operator BigCardinal.LessThanOrEqual(const A: TDLimb; const B: BigCardinal): Boolean;
begin
  Result:= Compare_BigCard_DblLimb(B, A) >= 0;
end;

class operator BigCardinal.LessThanOrEqual(const A: BigCardinal; const B: TDIntLimb): Boolean;
begin
  Result:= Compare_BigCard_DblIntLimb(A, B) <= 0;
end;

class operator BigCardinal.LessThanOrEqual(const A: TDIntLimb; const B: BigCardinal): Boolean;
begin
  Result:= Compare_BigCard_DblIntLimb(B, A) >= 0;
end;

class operator BigCardinal.Add(const A: BigCardinal; const B: TLimb): BigCardinal;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(A.FNumber.AddLimbU(B, Result.FNumber));
{$ELSE}
  HResCheck(TBigNumber.AddLimbU(PBigNumber(A.FNumber), B,
            PBigNumber(Result.FNumber)));
{$ENDIF}
end;

class operator BigCardinal.Add(const A: TLimb; const B: BigCardinal): BigCardinal;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(B.FNumber.AddLimbU(A, Result.FNumber));
{$ELSE}
  HResCheck(TBigNumber.AddLimbU(PBigNumber(B.FNumber), A,
            PBigNumber(Result.FNumber)));
{$ENDIF}
end;

class operator BigCardinal.Subtract(const A: BigCardinal; const B: TLimb): BigCardinal;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(A.FNumber.SubLimbU(B, Result.FNumber));
{$ELSE}
  HResCheck(TBigNumber.SubLimbU(PBigNumber(A.FNumber), B,
            PBigNumber(Result.FNumber)));
{$ENDIF}
end;

class operator BigCardinal.Subtract(const A: TLimb; const B: BigCardinal): Cardinal;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(B.FNumber.SubLimbU2(A, Result));
{$ELSE}
  HResCheck(TBigNumber.SubLimbU2(PBigNumber(B.FNumber), A, Result));
{$ENDIF}
end;

class operator BigCardinal.Multiply(const A: BigCardinal; const B: TLimb): BigCardinal;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(A.FNumber.MulLimbU(B, Result.FNumber));
{$ELSE}
  HResCheck(TBigNumber.MulLimbU(PBigNumber(A.FNumber), B,
            PBigNumber(Result.FNumber)));
{$ENDIF}
end;

class operator BigCardinal.Multiply(const A: TLimb; const B: BigCardinal): BigCardinal;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(B.FNumber.MulLimbU(A, Result.FNumber));
{$ELSE}
  HResCheck(TBigNumber.MulLimbU(PBigNumber(B.FNumber), A,
            PBigNumber(Result.FNumber)));
{$ENDIF}
end;

class operator BigCardinal.IntDivide(const A: BigCardinal; const B: TLimb): BigCardinal;
var
  Remainder: TLimb;

begin
{$IFDEF TFL_INTFCALL}
  HResCheck(A.FNumber.DivRemLimbU(B, Result.FNumber, Remainder));
{$ELSE}
  HResCheck(TBigNumber.DivRemLimbU(PBigNumber(A.FNumber), B,
            PBigNumber(Result.FNumber), Remainder));
{$ENDIF}
end;

class operator BigCardinal.IntDivide(const A: TLimb; const B: BigCardinal): TLimb;
var
  Remainder: TLimb;

begin
{$IFDEF TFL_INTFCALL}
  HResCheck(B.FNumber.DivRemLimbU2(A, Result, Remainder));
{$ELSE}
  HResCheck(TBigNumber.DivRemLimbU2(PBigNumber(B.FNumber), A,
                       Result, Remainder));
{$ENDIF}
end;

class operator BigCardinal.Modulus(const A: BigCardinal; const B: TLimb): TLimb;
var
  Quotient: IBigNumber;

begin
{$IFDEF TFL_INTFCALL}
  HResCheck(A.FNumber.DivRemLimbU(B, Quotient, Result));
{$ELSE}
  HResCheck(TBigNumber.DivRemLimbU(PBigNumber(A.FNumber),
            B, PBigNumber(Quotient), Result));
{$ENDIF}
end;

class operator BigCardinal.Modulus(const A: TLimb; const B: BigCardinal): TLimb;
var
  Quotient: TLimb;

begin
{$IFDEF TFL_INTFCALL}
  HResCheck(B.FNumber.DivRemLimbU2(A, Quotient, Result));
{$ELSE}
  HResCheck(TBigNumber.DivRemLimbU2(PBigNumber(B.FNumber), A,
                       Quotient, Result));
{$ENDIF}
end;


{ BigInteger }

function BigInteger.ToString: string;
var
  BytesUsed: Integer;
  L: Integer;
  P, P1: PByte;
  I: Integer;
  IsMinus: Boolean;

begin
{$IFDEF TFL_INTFCALL}
  BytesUsed:= FNumber.GetSize;
{$ELSE}
  BytesUsed:= TBigNumber.GetSize(PBigNumber(FNumber));
//  BytesUsed:= PBigNumber(FNumber).FUsed;
{$ENDIF}
// log(256) approximated from above by 41/17
  L:= (BytesUsed * 41) div 17 + 1;
  GetMem(P, L);
  try
{$IFDEF TFL_INTFCALL}
    HResCheck(FNumber.ToDec(P, L));
{$ELSE}
    HResCheck(TBigNumber.ToDec(PBigNumber(FNumber), P, L));
{$ENDIF}
    IsMinus:= GetSign < 0;
    if IsMinus then Inc(L);
    Result:= '';
    SetLength(Result, L);
    I:= 1;
    if IsMinus then begin
      Result[1]:= '-';
      Inc(I);
    end;
    P1:= P;
    while I <= L do begin
      Result[I]:= Char(P1^);
      Inc(P1);
      Inc(I);
    end;
  finally
    FreeMem(P);
  end;
end;

function BigInteger.ToHexString(Digits: Integer; const Prefix: string;
                                TwoCompl: Boolean): string;
const
  ASCII_8 = 56;   // Ord('8')

var
  L: Integer;
  P, P1: PByte;
  HR: TF_RESULT;
  Filler: Char;
  I: Integer;

begin
{$IFDEF TFL_INTFCALL}
  HR:= FNumber.ToHex(nil, L, TwoCompl);
{$ELSE}
  HR:= TBigNumber.ToHex(PBigNumber(FNumber), nil, L, TwoCompl);
{$ENDIF}
  if HR = TF_E_INVALIDARG then begin
    GetMem(P, L);
    try
{$IFDEF TFL_INTFCALL}
      HResCheck(FNumber.ToHex(P, L, TwoCompl));
{$ELSE}
      HResCheck(TBigNumber.ToHex(PBigNumber(FNumber), P, L, TwoCompl));
{$ENDIF}
      if Digits < L then Digits:= L;
      I:= 1;
      Result:= '';
      if (FNumber.GetSign < 0) and not TwoCompl then begin
        Inc(I);
        SetLength(Result, Digits + Length(Prefix) + 1);
        Result[1]:= '-';
      end
      else
        SetLength(Result, Digits + Length(Prefix));
      Move(Pointer(Prefix)^, Result[I], Length(Prefix) * SizeOf(Char));
      Inc(I, Length(Prefix));
      if Digits > L then begin
        if TwoCompl and (P[L] >= ASCII_8) then Filler:= 'F'
        else Filler:= '0';
        while I + L <= Length(Result) do begin
          Result[I]:= Filler;
          Inc(I);
        end;
      end;
      P1:= P;
      while I <= Length(Result) do begin
        Result[I]:= Char(P1^);
        Inc(I);
        Inc(P1);
      end;
    finally
      FreeMem(P);
    end;
  end
  else
    BigNumberError(HR);
end;

function BigInteger.ToBytes: TBytes;
var
  HR: TF_RESULT;
  L: Cardinal;

begin
  Result:= nil;
{$IFDEF TFL_INTFCALL}
  HR:= FNumber.ToPByte(nil, L);
{$ELSE}
  HR:= TBigNumber.ToPByte(PBigNumber(FNumber), nil, L);
{$ENDIF}
  if (HR = TF_E_INVALIDARG) and (L > 0) then begin
    SetLength(Result, L);
    HR:= FNumber.ToPByte(Pointer(Result), L);
  end;
  HResCheck(HR);
end;

class function BigInteger.Parse(const S: string; TwoCompl: Boolean): BigInteger;
begin
{$IFDEF TFL_DLL}
  HResCheck(BigNumberFromPChar(Result.FNumber, Pointer(S), Length(S),
                               SizeOf(Char), True, TwoCompl));
{$ELSE}
  HResCheck(BigNumberFromPChar(PBigNumber(Result.FNumber), Pointer(S), Length(S),
                              SizeOf(Char), True, TwoCompl));
{$ENDIF}
end;

class function BigInteger.TryParse(const S: string; var R: BigInteger; TwoCompl: Boolean): Boolean;
begin
{$IFDEF TFL_DLL}
  Result:= BigNumberFromPChar(R.FNumber, Pointer(S), Length(S),
                              SizeOf(Char), True, TwoCompl) = TF_S_OK;
{$ELSE}
  Result:= BigNumberFromPChar(PBigNumber(R.FNumber), Pointer(S), Length(S),
                              SizeOf(Char), True, TwoCompl) = TF_S_OK;
{$ENDIF}
end;

function BigInteger.GetSign: Integer;
begin
{$IFDEF TFL_INTFCALL}
  Result:= FNumber.GetSign;
{$ELSE}
  Result:= TBigNumber.GetSign(PBigNumber(FNumber));
{$ENDIF}
end;

function BigInteger.GetHashCode: Integer;
begin
{$IFDEF TFL_INTFCALL}
  Result:= FNumber.GetHashCode;
{$ELSE}
  Result:= TBigNumber.GetHashCode(PBigNumber(FNumber));
{$ENDIF}
end;

function BigInteger.IsEven: Boolean;
begin
{$IFDEF TFL_INTFCALL}
  Result:= FNumber.GetIsEven;
{$ELSE}
  Result:= TBigNumber.GetIsEven(PBigNumber(FNumber));
{$ENDIF}
end;

function BigInteger.IsPowerOfTwo: Boolean;
begin
{$IFDEF TFL_INTFCALL}
  Result:= FNumber.GetIsPowerOfTwo;
{$ELSE}
  Result:= TBigNumber.GetIsPowerOfTwo(PBigNumber(FNumber));
{$ENDIF}
end;

class function BigInteger.PowerOfTwo(APower: Cardinal): BigInteger;
begin
{$IFDEF TFL_DLL}
  HResCheck(BigNumberPowerOfTwo(Result.FNumber, APower));
{$ELSE}
  HResCheck(BigNumberPowerOfTwo(PBigNumber(Result.FNumber), APower));
{$ENDIF}
end;

class function BigCardinal.Compare(const A, B: BigCardinal): Integer;
begin
  Result:= Compare_BigCard_BigCard(A, B);
end;

class function BigInteger.Compare(const A, B: BigInteger): Integer;
begin
  Result:= Compare_BigInt_BigInt(A, B);
end;

class function BigInteger.Compare(const A: BigInteger; const B: BigCardinal): Integer;
begin
  Result:= Compare_BigInt_BigCard(A, B);
end;

class function BigInteger.Compare(const A: BigCardinal; const B: BigInteger): Integer;
begin
  Result:= Compare_BigCard_BigInt(A, B);
end;

class function BigCardinal.Compare(const A: BigCardinal; const B: TLimb): Integer;
begin
  Result:= Compare_BigCard_Limb(A, B);
end;

class function BigCardinal.Compare(const A: BigCardinal; const B: TIntLimb): Integer;
begin
  Result:= Compare_BigCard_IntLimb(A, B);
end;

class function BigCardinal.Compare(const A: BigCardinal; const B: TDLimb): Integer;
begin
  Result:= Compare_BigCard_DblLimb(A, B);
end;

class function BigCardinal.Compare(const A: BigCardinal; const B: TDIntLimb): Integer;
begin
  Result:= Compare_BigCard_DblIntLimb(A, B);
end;

class function BigInteger.Compare(const A: BigInteger; const B: TLimb): Integer;
begin
  Result:= Compare_BigInt_Limb(A, B);
end;

class function BigInteger.Compare(const A: BigInteger; const B: TIntLimb): Integer;
begin
  Result:= Compare_BigInt_IntLimb(A, B);
end;

class function BigInteger.Compare(const A: BigInteger; const B: TDLimb): Integer;
begin
  Result:= Compare_BigInt_DblLimb(A, B);
end;

class function BigInteger.Compare(const A: BigInteger; const B: TDIntLimb): Integer;
begin
  Result:= Compare_BigInt_DblIntLimb(A, B);
end;

function BigInteger.CompareTo(const B: TLimb): Integer;
begin
  Result:= Compare_BigInt_Limb(Self, B);
end;

function BigInteger.CompareTo(const B: TIntLimb): Integer;
begin
  Result:= Compare_BigInt_IntLimb(Self, B);
end;

function BigInteger.CompareTo(const B: TDLimb): Integer;
begin
  Result:= Compare_BigInt_DblLimb(Self, B);
end;

function BigInteger.CompareTo(const B: TDIntLimb): Integer;
begin
  Result:= Compare_BigInt_DblIntLimb(Self, B);
end;

function BigInteger.CompareTo(const B: BigInteger): Integer;
begin
  Result:= Compare_BigInt_BigInt(Self, B);
end;

function BigInteger.CompareTo(const B: BigCardinal): Integer;
begin
  Result:= Compare_BigInt_BigCard(Self, B);
end;


class function BigCardinal.Equals(const A, B: BigCardinal): Boolean;
begin
  Result:= Equal_BigCard_BigCard(A, B);
end;

class function BigInteger.Equals(const A, B: BigInteger): Boolean;
begin
  Result:= Equal_BigInt_BigInt(A, B);
end;

class function BigInteger.Equals(const A: BigInteger; const B: BigCardinal): Boolean;
begin
  Result:= Equal_BigInt_BigCard(A, B);
end;

class function BigInteger.Equals(const A: BigCardinal; const B: BigInteger): Boolean;
begin
  Result:= Equal_BigCard_BigInt(A, B);
end;

function BigInteger.EqualsTo(const B: BigInteger): Boolean;
begin
  Result:= Equal_BigInt_BigInt(Self, B);
end;

function BigInteger.EqualsTo(const B: BigCardinal): Boolean;
begin
  Result:= Equal_BigInt_BigCard(Self, B);
end;

class function BigInteger.Abs(const A: BigInteger): BigInteger;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(A.FNumber.AbsNumber(Result.FNumber));
{$ELSE}
  HResCheck(TBigNumber.AbsNumber(PBigNumber(A.FNumber), PBigNumber(Result.FNumber)));
{$ENDIF}
end;

class function BigCardinal.Pow(const Base: BigCardinal; Value: Cardinal): BigCardinal;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(Base.FNumber.PowU(Value, Result.FNumber));
{$ELSE}
  HResCheck(TBigNumber.PowU(PBigNumber(Base.FNumber), Value,
                       PBigNumber(Result.FNumber)));
{$ENDIF}
end;

function BigCardinal.IsPowerOfTwo: Boolean;
begin
{$IFDEF TFL_INTFCALL}
  Result:= FNumber.GetIsPowerOfTwo;
{$ELSE}
  Result:= TBigNumber.GetIsPowerOfTwo(PBigNumber(FNumber));
{$ENDIF}
end;

class function BigCardinal.PowerOfTwo(APower: Cardinal): BigCardinal;
begin
{$IFDEF TFL_DLL}
  HResCheck(BigNumberPowerOfTwo(Result.FNumber, APower));
{$ELSE}
  HResCheck(BigNumberPowerOfTwo(PBigNumber(Result.FNumber), APower));
{$ENDIF}
end;

function BigCardinal.Prev: BigCardinal;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(FNumber.PrevNumberU(Result.FNumber);
{$ELSE}
  HResCheck(TBigNumber.PrevNumberU(PBigNumber(FNumber),
                                       PBigNumber(Result.FNumber)));
{$ENDIF}
end;

class function BigInteger.Pow(const Base: BigInteger; Value: Cardinal): BigInteger;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(Base.FNumber.Pow(Value, Result.FNumber));
{$ELSE}
  HResCheck(TBigNumber.Pow(PBigNumber(Base.FNumber), Value,
                       PBigNumber(Result.FNumber)));
{$ENDIF}
end;

class operator BigInteger.BitwiseAnd(const A, B: BigInteger): BigInteger;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(A.FNumber.AndNumber(B.FNumber, Result.FNumber));
{$ELSE}
  HResCheck(TBigNumber.AndNumbers(PBigNumber(A.FNumber),
                       PBigNumber(B.FNumber), PBigNumber(Result.FNumber)));
{$ENDIF}
end;

class operator BigInteger.BitwiseOr(const A, B: BigInteger): BigInteger;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(A.FNumber.OrNumber(B.FNumber, Result.FNumber));
{$ELSE}
  HResCheck(TBigNumber.OrNumbers(PBigNumber(A.FNumber),
                       PBigNumber(B.FNumber), PBigNumber(Result.FNumber)));
{$ENDIF}
end;

class operator BigInteger.BitwiseXor(const A, B: BigInteger): BigInteger;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(A.FNumber.XorNumber(B.FNumber, Result.FNumber));
{$ELSE}
  HResCheck(TBigNumber.XorNumbers(PBigNumber(A.FNumber),
                       PBigNumber(B.FNumber), PBigNumber(Result.FNumber)));
{$ENDIF}
end;

(* conversion to integer types is redesigned
class operator BigInteger.Explicit(const Value: BigInteger): TLimb;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(Value.FNumber.ToLimb(Result));
{$ELSE}
  HResCheck(TBigNumber.ToLimb(PBigNumber(Value.FNumber), Result));
{$ENDIF}
end;

class operator BigInteger.Explicit(const Value: BigInteger): TDblLimb;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(Value.FNumber.ToDblLimb(Result));
{$ELSE}
  HResCheck(TBigNumber.ToDblLimb(PBigNumber(Value.FNumber), Result));
{$ENDIF}
end;

class operator BigInteger.Explicit(const Value: BigInteger): TIntLimb;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(Value.FNumber.ToIntLimb(Result));
{$ELSE}
  HResCheck(TBigNumber.ToIntLimb(PBigNumber(Value.FNumber), Result));
{$ENDIF}
end;

class operator BigInteger.Explicit(const Value: BigInteger): TDblIntLimb;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(Value.FNumber.ToDblIntLimb(Result));
{$ELSE}
  HResCheck(TBigNumber.ToDblIntLimb(PBigNumber(Value.FNumber), Result));
{$ENDIF}
end;
*)

class operator BigInteger.Explicit(const Value: BigInteger): TLimb;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(Value.FNumber.GetLimb(Result));
{$ELSE}
  HResCheck(TBigNumber.GetLimb(PBigNumber(Value.FNumber), Result));
{$ENDIF}
end;

class operator BigInteger.Explicit(const Value: BigInteger): TDLimb;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(Value.FNumber.GetDblLimb(Result));
{$ELSE}
  HResCheck(TBigNumber.GetDblLimb(PBigNumber(Value.FNumber), Result));
{$ENDIF}
end;

class operator BigInteger.Explicit(const Value: BigInteger): TIntLimb;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(Value.FNumber.GetLimb(TLimb(Result)));
{$ELSE}
  HResCheck(TBigNumber.GetLimb(PBigNumber(Value.FNumber), TLimb(Result)));
{$ENDIF}
end;

class operator BigInteger.Explicit(const Value: BigInteger): TDIntLimb;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(Value.FNumber.GetDblLimb(TDblLimb(Result)));
{$ELSE}
  HResCheck(TBigNumber.GetDblLimb(PBigNumber(Value.FNumber), TDLimb(Result)));
{$ENDIF}
end;

class operator BigInteger.Implicit(const Value: BigCardinal): BigInteger;
begin
  Result.FNumber:= Value.FNumber;
end;

class operator BigInteger.Explicit(const Value: BigInteger): BigCardinal;
begin
{$IFDEF TFL_INTFCALL}
  if (Value.FNumber.GetSign < 0) then
{$ELSE}
  if (PBigNumber(Value.FNumber).FSign < 0) then
{$ENDIF}
    BigNumberError(TF_E_INVALIDARG);
  Result.FNumber:= Value.FNumber;
end;

class operator BigInteger.Explicit(const Value: string): BigInteger;
begin
{$IFDEF TFL_DLL}
  HResCheck(BigNumberFromPChar(Result.FNumber, Pointer(Value), Length(Value),
                               SizeOf(Char), True, False));
{$ELSE}
//  HResCheck(TBigNumber.FromString(PBigNumber(Result.FNumber), Value));
  HResCheck(BigNumberFromPChar(PBigNumber(Result.FNumber), Pointer(Value), Length(Value),
                              SizeOf(Char), True, False));
{$ENDIF}
end;

class operator BigInteger.Explicit(const Value: TBytes): BigInteger;
begin
{$IFDEF TFL_DLL}
  HResCheck(BigNumberFromPByte(Result.FNumber,
{$ELSE}
  HResCheck(BigNumberFromPByte(PBigNumber(Result.FNumber),
{$ENDIF}
            Pointer(Value), Length(Value), True));
end;

class operator BigInteger.Equal(const A, B: BigInteger): Boolean;
begin
  Result:= Equal_BigInt_BigInt(A, B);
end;

class operator BigInteger.Equal(const A: BigInteger; const B: BigCardinal): Boolean;
begin
  Result:= Equal_BigInt_BigCard(A, B);
end;

class operator BigInteger.Equal(const A: BigCardinal; const B: BigInteger): Boolean;
begin
  Result:= Equal_BigCard_BigInt(A, B);
end;

class operator BigInteger.NotEqual(const A, B: BigInteger): Boolean;
begin
  Result:= not Equal_BigInt_BigInt(A, B);
end;

class operator BigInteger.NotEqual(const A: BigInteger; const B: BigCardinal): Boolean;
begin
  Result:= not Equal_BigInt_BigCard(A, B);
end;

class operator BigInteger.NotEqual(const A: BigCardinal; const B: BigInteger): Boolean;
begin
  Result:= not Equal_BigCard_BigInt(A, B);
end;

class operator BigInteger.GreaterThan(const A, B: BigInteger): Boolean;
begin
  Result:= Compare_BigInt_BigInt(A, B) > 0;
end;

class operator BigInteger.GreaterThan(const A: BigInteger; const B: BigCardinal): Boolean;
begin
  Result:= Compare_BigInt_BigCard(A, B) > 0;
end;

class operator BigInteger.GreaterThan(const A: BigCardinal; const B: BigInteger): Boolean;
begin
  Result:= Compare_BigCard_BigInt(A, B) > 0;
end;

class operator BigInteger.GreaterThanOrEqual(const A, B: BigInteger): Boolean;
begin
  Result:= Compare_BigInt_BigInt(A, B) >= 0;
end;

class operator BigInteger.GreaterThanOrEqual(const A: BigInteger; const B: BigCardinal): Boolean;
begin
  Result:= Compare_BigInt_BigCard(A, B) >= 0;
end;

class operator BigInteger.GreaterThanOrEqual(const A: BigCardinal; const B: BigInteger): Boolean;
begin
  Result:= Compare_BigCard_BigInt(A, B) >= 0;
end;

class operator BigInteger.LessThan(const A, B: BigInteger): Boolean;
begin
  Result:= Compare_BigInt_BigInt(A, B) < 0;
end;

class operator BigInteger.LessThan(const A: BigInteger; const B: BigCardinal): Boolean;
begin
  Result:= Compare_BigInt_BigCard(A, B) < 0;
end;

class operator BigInteger.LessThan(const A: BigCardinal; const B: BigInteger): Boolean;
begin
  Result:= Compare_BigCard_BigInt(A, B) < 0;
end;

class operator BigInteger.LessThanOrEqual(const A, B: BigInteger): Boolean;
begin
  Result:= Compare_BigInt_BigInt(A, B) <= 0;
end;

class operator BigInteger.LessThanOrEqual(const A: BigInteger; const B: BigCardinal): Boolean;
begin
  Result:= Compare_BigInt_BigCard(A, B) <= 0;
end;

class operator BigInteger.LessThanOrEqual(const A: BigCardinal; const B: BigInteger): Boolean;
begin
  Result:= Compare_BigCard_BigInt(A, B) <= 0;
end;

class operator BigInteger.LeftShift(const A: BigInteger; Shift: Cardinal): BigInteger;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(A.FNumber.ShlNumber(Shift, Result.FNumber));
{$ELSE}
  HResCheck(TBigNumber.ShlNumber(PBigNumber(A.FNumber), Shift,
                       PBigNumber(Result.FNumber)));
{$ENDIF}
end;

class operator BigInteger.RightShift(const A: BigInteger; Shift: Cardinal): BigInteger;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(A.FNumber.ShrNumber(Shift, Result.FNumber));
{$ELSE}
  HResCheck(TBigNumber.ShrNumber(PBigNumber(A.FNumber), Shift,
                       PBigNumber(Result.FNumber)));
{$ENDIF}
end;

procedure BigInteger.Free;
begin
  FNumber:= nil;
end;

class operator BigInteger.Implicit(const Value: TLimb): BigInteger;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(BigNumberFromLimb(Result.FNumber, Value));
{$ELSE}
  HResCheck(BigNumberFromLimb(PBigNumber(Result.FNumber), Value));
{$ENDIF}
end;

class operator BigInteger.Implicit(const Value: TDLimb): BigInteger;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(BigNumberFromDblLimb(Result.FNumber, Value));
{$ELSE}
  HResCheck(BigNumberFromDblLimb(PBigNumber(Result.FNumber), Value));
{$ENDIF}
end;

class operator BigInteger.Implicit(const Value: TIntLimb): BigInteger;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(BigNumberFromIntLimb(Result.FNumber, Value));
{$ELSE}
  HResCheck(BigNumberFromIntLimb(PBigNumber(Result.FNumber), Value));
{$ENDIF}
end;

class operator BigInteger.Implicit(const Value: TDIntLimb): BigInteger;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(BigNumberFromDblIntLimb(Result.FNumber, Value));
{$ELSE}
  HResCheck(BigNumberFromDblIntLimb(PBigNumber(Result.FNumber), Value));
{$ENDIF}
end;

class operator BigInteger.Add(const A, B: BigInteger): BigInteger;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(A.FNumber.AddNumber(B.FNumber, Result.FNumber));
{$ELSE}
  HResCheck(TBigNumber.AddNumbers(PBigNumber(A.FNumber),
            PBigNumber(B.FNumber), PBigNumber(Result.FNumber)));
{$ENDIF}
end;

class operator BigInteger.Subtract(const A, B: BigInteger): BigInteger;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(A.FNumber.SubNumber(B.FNumber, Result.FNumber));
{$ELSE}
  HResCheck(TBigNumber.SubNumbers(PBigNumber(A.FNumber),
            PBigNumber(B.FNumber), PBigNumber(Result.FNumber)));
{$ENDIF}
end;

class operator BigInteger.Multiply(const A, B: BigInteger): BigInteger;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(A.FNumber.MulNumber(B.FNumber, Result.FNumber));
{$ELSE}
  HResCheck(TBigNumber.MulNumbers(PBigNumber(A.FNumber),
            PBigNumber(B.FNumber), PBigNumber(Result.FNumber)));
{$ENDIF}
end;

class operator BigInteger.IntDivide(const A, B: BigInteger): BigInteger;
var
  Remainder: IBigNumber;

begin
{$IFDEF TFL_INTFCALL}
  HResCheck(A.FNumber.DivRemNumber(B.FNumber, Result.FNumber, Remainder));
{$ELSE}
  HResCheck(TBigNumber.DivRemNumbers(PBigNumber(A.FNumber),
            PBigNumber(B.FNumber), PBigNumber(Result.FNumber),
            PBigNumber(Remainder)));
{$ENDIF}
end;

class operator BigInteger.Modulus(const A, B: BigInteger): BigInteger;
var
  Quotient: IBigNumber;

begin
{$IFDEF TFL_INTFCALL}
  HResCheck(A.FNumber.DivRemNumber(B.FNumber, Quotient, Result.FNumber));
{$ELSE}
  HResCheck(TBigNumber.DivRemNumbers(PBigNumber(A.FNumber),
            PBigNumber(B.FNumber), PBigNumber(Quotient),
            PBigNumber(Result.FNumber)));
{$ENDIF}
end;


class function BigCardinal.DivRem(const Dividend, Divisor: BigCardinal;
                                  var Remainder: BigCardinal): BigCardinal;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(Dividend.FNumber.DivRemNumberU(Divisor.FNumber,
            Result.FNumber, Remainder.FNumber));
{$ELSE}
  HResCheck(TBigNumber.DivRemNumbersU(PBigNumber(Dividend.FNumber),
            PBigNumber(Divisor.FNumber), PBigNumber(Result.FNumber),
            PBigNumber(Remainder.FNumber)));
{$ENDIF}
end;

class function BigInteger.DivRem(const Dividend, Divisor: BigInteger;
               var Remainder: BigInteger): BigInteger;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(Dividend.FNumber.DivRemNumber(Divisor.FNumber,
            Result.FNumber, Remainder.FNumber));
{$ELSE}
  HResCheck(TBigNumber.DivRemNumbers(PBigNumber(Dividend.FNumber),
            PBigNumber(Divisor.FNumber), PBigNumber(Result.FNumber),
            PBigNumber(Remainder.FNumber)));
{$ENDIF}
end;

class function BigCardinal.DivRem(const Dividend: BigCardinal;
               Divisor: TLimb; var Remainder: TLimb): BigCardinal;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(Dividend.FNumber.DivRemLimbU(Divisor, Result.FNumber, Remainder));
{$ELSE}
  HResCheck(TBigNumber.DivRemLimbU(PBigNumber(Dividend.FNumber), Divisor,
            PBigNumber(Result.FNumber), Remainder));
{$ENDIF}
end;

class function BigCardinal.DivRem(const Dividend: TLimb;
               Divisor: BigCardinal; var Remainder: TLimb): TLimb;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(Divisor.FNumber.DivRemLimbU2(Dividend, Result, Remainder));
{$ELSE}
  HResCheck(TBigNumber.DivRemLimbU2(PBigNumber(Divisor.FNumber), Dividend,
            Result, Remainder));
{$ENDIF}
end;

class function BigCardinal.Sqr(const A: BigCardinal): BigCardinal;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(A.FNumber.SqrNumber(Result.FNumber));
{$ELSE}
  HResCheck(TBigNumber.SqrNumber(PBigNumber(A.FNumber), PBigNumber(Result.FNumber)));
{$ENDIF}
end;

class function BigCardinal.Sqrt(const A: BigCardinal): BigCardinal;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(A.FNumber.SqrtNumber(Result.FNumber));
{$ELSE}
  HResCheck(TBigNumber.SqrtNumber(PBigNumber(A.FNumber), PBigNumber(Result.FNumber)));
{$ENDIF}
end;

class function BigInteger.Sqr(const A: BigInteger): BigInteger;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(A.FNumber.SqrNumber(Result.FNumber));
{$ELSE}
  HResCheck(TBigNumber.SqrNumber(PBigNumber(A.FNumber), PBigNumber(Result.FNumber)));
{$ENDIF}
end;

class function BigInteger.Sqrt(const A: BigInteger): BigInteger;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(A.FNumber.SqrtNumber(Result.FNumber));
{$ELSE}
  HResCheck(TBigNumber.SqrtNumber(PBigNumber(A.FNumber), PBigNumber(Result.FNumber)));
{$ENDIF}
end;

class function BigCardinal.GCD(const A, B: BigCardinal): BigCardinal;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(A.FNumber.GCD(B.FNumber, Result.FNumber));
{$ELSE}
  HResCheck(TBigNumber.GCD(PBigNumber(A.FNumber), PBigNumber(B.FNumber),
            PBigNumber(Result.FNumber)));
{$ENDIF}
end;

class function BigInteger.GCD(const A, B: BigInteger): BigInteger;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(A.FNumber.GCD(B.FNumber, Result.FNumber));
{$ELSE}
  HResCheck(TBigNumber.GCD(PBigNumber(A.FNumber), PBigNumber(B.FNumber),
            PBigNumber(Result.FNumber)));
{$ENDIF}
end;

(*
class function BigInteger.GCD(const A: BigInteger; const B: BigCardinal): BigInteger;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(A.FNumber.GCD(B.FNumber, Result.FNumber));
{$ELSE}
  HResCheck(TBigNumber.GCD(PBigNumber(A.FNumber), PBigNumber(B.FNumber),
            PBigNumber(Result.FNumber)));
{$ENDIF}
end;

class function BigInteger.GCD(const A: BigCardinal; const B: BigInteger): BigInteger;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(A.FNumber.GCD(B.FNumber, Result.FNumber));
{$ELSE}
  HResCheck(TBigNumber.GCD(PBigNumber(A.FNumber), PBigNumber(B.FNumber),
            PBigNumber(Result.FNumber)));
{$ENDIF}
end;
*)

class function BigInteger.LCM(const A, B: BigInteger): BigInteger;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(A.FNumber.LCM(B.FNumber, Result.FNumber));
{$ELSE}
  HResCheck(TBigNumber.LCM(PBigNumber(A.FNumber), PBigNumber(B.FNumber),
            PBigNumber(Result.FNumber)));
{$ENDIF}
end;

class function BigInteger.EGCD(const A, B: BigInteger; var X, Y: BigInteger): BigInteger;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(A.FNumber.EGCD(B.FNumber, Result.FNumber, X.FNumber, Y.FNumber));
{$ELSE}
  HResCheck(TBigNumber.EGCD(PBigNumber(A.FNumber), PBigNumber(B.FNumber),
      PBigNumber(Result.FNumber), PBigNumber(X.FNumber), PBigNumber(Y.FNumber)));
{$ENDIF}
end;

class function BigInteger.ModPow(const BaseValue, ExpValue,
               Modulo: BigInteger): BigInteger;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(BaseValue.FNumber.ModPow(ExpValue.FNumber,
            Modulo.FNumber, Result.FNumber));
{$ELSE}
  HResCheck(TBigNumber.ModPow(PBigNumber(BaseValue.FNumber),
            PBigNumber(ExpValue.FNumber), PBigNumber(Modulo.FNumber),
            PBigNumber(Result.FNumber)));
{$ENDIF}
end;

class function BigCardinal.ModPow(const BaseValue, ExpValue,
  Modulo: BigCardinal): BigCardinal;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(BaseValue.FNumber.ModPow(ExpValue.FNumber,
            Modulo.FNumber, Result.FNumber));
{$ELSE}
  HResCheck(TBigNumber.ModPow(PBigNumber(BaseValue.FNumber),
            PBigNumber(ExpValue.FNumber), PBigNumber(Modulo.FNumber),
            PBigNumber(Result.FNumber)));
{$ENDIF}
end;

class function BigCardinal.ModInverse(const A, Modulo: BigCardinal): BigCardinal;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(A.FNumber.ModInverse(Modulo.FNumber, Result.FNumber));
{$ELSE}
  HResCheck(TBigNumber.ModInverse(PBigNumber(A.FNumber),
            PBigNumber(Modulo.FNumber), PBigNumber(Result.FNumber)));
{$ENDIF}
end;

class function BigInteger.ModInverse(const A, Modulo: BigInteger): BigInteger;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(A.FNumber.ModInverse(Modulo.FNumber, Result.FNumber));
{$ELSE}
  HResCheck(TBigNumber.ModInverse(PBigNumber(A.FNumber),
            PBigNumber(Modulo.FNumber), PBigNumber(Result.FNumber)));
{$ENDIF}
end;

(*
class function BigInteger.ModInverse(const A: BigInteger; const Modulo: BigCardinal): BigInteger;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(A.FNumber.ModInverse(Modulo.FNumber, Result.FNumber));
{$ELSE}
  HResCheck(TBigNumber.ModInverse(PBigNumber(A.FNumber),
            PBigNumber(Modulo.FNumber), PBigNumber(Result.FNumber)));
{$ENDIF}
end;

class function BigInteger.ModInverse(const A: BigCardinal; const Modulo: BigInteger): BigInteger;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(A.FNumber.ModInverse(Modulo.FNumber, Result.FNumber));
{$ELSE}
  HResCheck(TBigNumber.ModInverse(PBigNumber(A.FNumber),
            PBigNumber(Modulo.FNumber), PBigNumber(Result.FNumber)));
{$ENDIF}
end;
*)

class operator BigInteger.Equal(const A: BigInteger; const B: TLimb): Boolean;
begin
  Result:= Equal_BigInt_Limb(A, B);
end;

class operator BigInteger.Equal(const A: TLimb; const B: BigInteger): Boolean;
begin
  Result:= Equal_BigInt_Limb(B, A);
end;

class operator BigInteger.Equal(const A: BigInteger; const B: TIntLimb): Boolean;
begin
  Result:= Equal_BigInt_IntLimb(A, B);
end;

class operator BigInteger.Equal(const A: TIntLimb; const B: BigInteger): Boolean;
begin
  Result:= Equal_BigInt_IntLimb(B, A);
end;

class operator BigInteger.NotEqual(const A: BigInteger; const B: TLimb): Boolean;
begin
  Result:= not Equal_BigInt_Limb(A, B);
end;

class operator BigInteger.NotEqual(const A: TLimb; const B: BigInteger): Boolean;
begin
  Result:= not Equal_BigInt_Limb(B, A);
end;

class operator BigInteger.NotEqual(const A: BigInteger; const B: TIntLimb): Boolean;
begin
  Result:= not Equal_BigInt_IntLimb(A, B);
end;

class operator BigInteger.NotEqual(const A: TIntLimb; const B: BigInteger): Boolean;
begin
  Result:= not Equal_BigInt_IntLimb(B, A);
end;

class operator BigInteger.GreaterThan(const A: BigInteger; const B: TLimb): Boolean;
begin
  Result:= Compare_BigInt_Limb(A, B) > 0;
end;

class operator BigInteger.GreaterThan(const A: TLimb; const B: BigInteger): Boolean;
begin
  Result:= Compare_BigInt_Limb(B, A) < 0;
end;

class operator BigInteger.GreaterThan(const A: BigInteger; const B: TIntLimb): Boolean;
begin
  Result:= Compare_BigInt_IntLimb(A, B) > 0;
end;

class operator BigInteger.GreaterThan(const A: TIntLimb; const B: BigInteger): Boolean;
begin
  Result:= Compare_BigInt_IntLimb(B, A) < 0;
end;

class operator BigInteger.GreaterThanOrEqual(const A: BigInteger; const B: TLimb): Boolean;
begin
  Result:= Compare_BigInt_Limb(A, B) >= 0;
end;

class operator BigInteger.GreaterThanOrEqual(const A: TLimb; const B: BigInteger): Boolean;
begin
  Result:= Compare_BigInt_Limb(B, A) <= 0;
end;

class operator BigInteger.GreaterThanOrEqual(const A: BigInteger; const B: TIntLimb): Boolean;
begin
  Result:= Compare_BigInt_IntLimb(A, B) >= 0;
end;

class operator BigInteger.GreaterThanOrEqual(const A: TIntLimb; const B: BigInteger): Boolean;
begin
  Result:= Compare_BigInt_IntLimb(B, A) <= 0;
end;

class operator BigInteger.LessThan(const A: BigInteger; const B: TLimb): Boolean;
begin
  Result:= Compare_BigInt_Limb(A, B) < 0;
end;

class operator BigInteger.LessThan(const A: TLimb; const B: BigInteger): Boolean;
begin
  Result:= Compare_BigInt_Limb(B, A) > 0;
end;

class operator BigInteger.LessThan(const A: BigInteger; const B: TIntLimb): Boolean;
begin
  Result:= Compare_BigInt_IntLimb(A, B) < 0;
end;

class operator BigInteger.LessThan(const A: TIntLimb; const B: BigInteger): Boolean;
begin
  Result:= Compare_BigInt_IntLimb(B, A) > 0;
end;

class operator BigInteger.LessThanOrEqual(const A: BigInteger; const B: TLimb): Boolean;
begin
  Result:= Compare_BigInt_Limb(A, B) <= 0;
end;

class operator BigInteger.LessThanOrEqual(const A: TLimb; const B: BigInteger): Boolean;
begin
  Result:= Compare_BigInt_Limb(B, A) >= 0;
end;

class operator BigInteger.LessThanOrEqual(const A: BigInteger; const B: TIntLimb): Boolean;
begin
  Result:= Compare_BigInt_IntLimb(A, B) <= 0;
end;

class operator BigInteger.LessThanOrEqual(const A: TIntLimb; const B: BigInteger): Boolean;
begin
  Result:= Compare_BigInt_IntLimb(B, A) >= 0;
end;

class operator BigInteger.Equal(const A: BigInteger; const B: TDLimb): Boolean;
begin
  Result:= Equal_BigInt_DblLimb(A, B);
end;

class operator BigInteger.Equal(const A: TDLimb; const B: BigInteger): Boolean;
begin
  Result:= Equal_BigInt_DblLimb(B, A);
end;

class operator BigInteger.Equal(const A: BigInteger; const B: TDIntLimb): Boolean;
begin
  Result:= Equal_BigInt_DblIntLimb(A, B);
end;

class operator BigInteger.Equal(const A: TDIntLimb; const B: BigInteger): Boolean;
begin
  Result:= Equal_BigInt_DblIntLimb(B, A);
end;

class operator BigInteger.NotEqual(const A: BigInteger; const B: TDLimb): Boolean;
begin
  Result:= not Equal_BigInt_DblLimb(A, B);
end;

class operator BigInteger.NotEqual(const A: TDLimb; const B: BigInteger): Boolean;
begin
  Result:= not Equal_BigInt_DblLimb(B, A);
end;

class operator BigInteger.NotEqual(const A: BigInteger; const B: TDIntLimb): Boolean;
begin
  Result:= not Equal_BigInt_DblIntLimb(A, B);
end;

class operator BigInteger.NotEqual(const A: TDIntLimb; const B: BigInteger): Boolean;
begin
  Result:= not Equal_BigInt_DblIntLimb(B, A);
end;

class operator BigInteger.GreaterThan(const A: BigInteger; const B: TDLimb): Boolean;
begin
  Result:= Compare_BigInt_DblLimb(A, B) > 0;
end;

class operator BigInteger.GreaterThan(const A: TDLimb; const B: BigInteger): Boolean;
begin
  Result:= Compare_BigInt_DblLimb(B, A) < 0;
end;

class operator BigInteger.GreaterThan(const A: BigInteger; const B: TDIntLimb): Boolean;
begin
  Result:= Compare_BigInt_DblIntLimb(A, B) > 0;
end;

class operator BigInteger.GreaterThan(const A: TDIntLimb; const B: BigInteger): Boolean;
begin
  Result:= Compare_BigInt_DblIntLimb(B, A) < 0;
end;

class operator BigInteger.GreaterThanOrEqual(const A: BigInteger; const B: TDLimb): Boolean;
begin
  Result:= Compare_BigInt_DblLimb(A, B) >= 0;
end;

class operator BigInteger.GreaterThanOrEqual(const A: TDLimb; const B: BigInteger): Boolean;
begin
  Result:= Compare_BigInt_DblLimb(B, A) <= 0;
end;

class operator BigInteger.GreaterThanOrEqual(const A: BigInteger; const B: TDIntLimb): Boolean;
begin
  Result:= Compare_BigInt_DblIntLimb(A, B) >= 0;
end;

class operator BigInteger.GreaterThanOrEqual(const A: TDIntLimb; const B: BigInteger): Boolean;
begin
  Result:= Compare_BigInt_DblIntLimb(B, A) <= 0;
end;

class operator BigInteger.LessThan(const A: BigInteger; const B: TDLimb): Boolean;
begin
  Result:= Compare_BigInt_DblLimb(A, B) < 0;
end;

class operator BigInteger.LessThan(const A: TDLimb; const B: BigInteger): Boolean;
begin
  Result:= Compare_BigInt_DblLimb(B, A) > 0;
end;

class operator BigInteger.LessThan(const A: BigInteger; const B: TDIntLimb): Boolean;
begin
  Result:= Compare_BigInt_DblIntLimb(A, B) < 0;
end;

class operator BigInteger.LessThan(const A: TDIntLimb; const B: BigInteger): Boolean;
begin
  Result:= Compare_BigInt_DblIntLimb(B, A) > 0;
end;

class operator BigInteger.LessThanOrEqual(const A: BigInteger; const B: TDLimb): Boolean;
begin
  Result:= Compare_BigInt_DblLimb(A, B) <= 0;
end;

class operator BigInteger.LessThanOrEqual(const A: TDLimb; const B: BigInteger): Boolean;
begin
  Result:= Compare_BigInt_DblLimb(B, A) >= 0;
end;

class operator BigInteger.LessThanOrEqual(const A: BigInteger; const B: TDIntLimb): Boolean;
begin
  Result:= Compare_BigInt_DblIntLimb(A, B) <= 0;
end;

class operator BigInteger.LessThanOrEqual(const A: TDIntLimb; const B: BigInteger): Boolean;
begin
  Result:= Compare_BigInt_DblIntLimb(B, A) >= 0;
end;


// -- arithmetic operations on BigInteger & TLimb --

class operator BigInteger.Add(const A: BigInteger; const B: TLimb): BigInteger;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(A.FNumber.AddLimb(B, Result.FNumber));
{$ELSE}
  HResCheck(TBigNumber.AddLimb(PBigNumber(A.FNumber), B,
            PBigNumber(Result.FNumber)));
{$ENDIF}
end;

class operator BigInteger.Subtract(const A: BigInteger; const B: TLimb): BigInteger;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(A.FNumber.SubLimb(B, Result.FNumber));
{$ELSE}
  HResCheck(TBigNumber.SubLimb(PBigNumber(A.FNumber), B,
            PBigNumber(Result.FNumber)));
{$ENDIF}
end;

class operator BigInteger.Multiply(const A: BigInteger; const B: TLimb): BigInteger;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(A.FNumber.MulLimb(B, Result.FNumber));
{$ELSE}
  HResCheck(TBigNumber.MulLimb(PBigNumber(A.FNumber), B,
            PBigNumber(Result.FNumber)));
{$ENDIF}
end;

class operator BigInteger.IntDivide(const A: BigInteger; const B: TLimb): BigInteger;
var
  Remainder: BigInteger;

begin
{$IFDEF TFL_INTFCALL}
  HResCheck(A.FNumber.DivRemLimb(B, Result.FNumber, Remainder.FNumber));
{$ELSE}
  HResCheck(TBigNumber.DivRemLimb(PBigNumber(A.FNumber), B,
            PBigNumber(Result.FNumber), PBigNumber(Remainder.FNumber)));
{$ENDIF}
end;

class operator BigInteger.Modulus(const A: BigInteger; const B: TLimb): BigInteger;
var
  Quotient: BigInteger;

begin
{$IFDEF TFL_INTFCALL}
  HResCheck(A.FNumber.DivRemLimb(B, Quotient.FNumber, Result.FNumber));
{$ELSE}
  HResCheck(TBigNumber.DivRemLimb(PBigNumber(A.FNumber), B,
            PBigNumber(Quotient.FNumber), PBigNumber(Result.FNumber)));
{$ENDIF}
end;

class function BigInteger.DivRem(const Dividend: BigInteger;
               const Divisor: TLimb; var Remainder: BigInteger): BigInteger;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(Dividend.FNumber.DivRemLimb(Divisor, Result.FNumber, Remainder.FNumber));
{$ELSE}
  HResCheck(TBigNumber.DivRemLimb(PBigNumber(Dividend.FNumber), Divisor,
            PBigNumber(Result.FNumber), PBigNumber(Remainder.FNumber)));
{$ENDIF}
end;

// -- arithmetic operations on TLimb & BigInteger --

class operator BigInteger.Add(const A: TLimb; const B: BigInteger): BigInteger;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(B.FNumber.AddLimb(A, Result.FNumber));
{$ELSE}
  HResCheck(TBigNumber.AddLimb(PBigNumber(B.FNumber), A,
            PBigNumber(Result.FNumber)));
{$ENDIF}
end;

class operator BigInteger.Subtract(const A: TLimb; const B: BigInteger): BigInteger;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(B.FNumber.SubLimb2(A, Result.FNumber));
{$ELSE}
  HResCheck(TBigNumber.SubLimb2(PBigNumber(B.FNumber), A,
            PBigNumber(Result.FNumber)));
{$ENDIF}
end;

class operator BigInteger.Multiply(const A: TLimb; const B: BigInteger): BigInteger;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(B.FNumber.MulLimb(A, Result.FNumber));
{$ELSE}
  HResCheck(TBigNumber.MulLimb(PBigNumber(B.FNumber), A,
            PBigNumber(Result.FNumber)));
{$ENDIF}
end;

class operator BigInteger.IntDivide(const A: TLimb; const B: BigInteger): BigInteger;
var
  Remainder: TLimb;

begin
{$IFDEF TFL_INTFCALL}
  HResCheck(B.FNumber.DivRemLimb2(A, Result.FNumber, Remainder));
{$ELSE}
  HResCheck(TBigNumber.DivRemLimb2(PBigNumber(B.FNumber), A,
            PBigNumber(Result.FNumber), Remainder));
{$ENDIF}
end;

class operator BigInteger.Modulus(const A: TLimb; const B: BigInteger): TLimb;
var
  Quotient: BigInteger;

begin
{$IFDEF TFL_INTFCALL}
  HResCheck(B.FNumber.DivRemLimb2(A, Quotient.FNumber, Result));
{$ELSE}
  HResCheck(TBigNumber.DivRemLimb2(PBigNumber(B.FNumber), A,
            PBigNumber(Quotient.FNumber), Result));
{$ENDIF}
end;

class function BigInteger.DivRem(const Dividend: TLimb;
               const Divisor: BigInteger; var Remainder: TLimb): BigInteger;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(Divisor.FNumber.DivRemLimb2(Dividend, Result.FNumber, Remainder));
{$ELSE}
  HResCheck(TBigNumber.DivRemLimb2(PBigNumber(Divisor.FNumber), Dividend,
            PBigNumber(Result.FNumber), Remainder));
{$ENDIF}
end;

// -- arithmetic operations on BigInteger & TIntLimb --

class operator BigInteger.Add(const A: BigInteger; const B: TIntLimb): BigInteger;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(A.FNumber.AddIntLimb(B, Result.FNumber));
{$ELSE}
  HResCheck(TBigNumber.AddIntLimb(PBigNumber(A.FNumber), B,
            PBigNumber(Result.FNumber)));
{$ENDIF}
end;

class operator BigInteger.Subtract(const A: BigInteger; const B: TIntLimb): BigInteger;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(A.FNumber.SubIntLimb(B, Result.FNumber));
{$ELSE}
  HResCheck(TBigNumber.SubIntLimb(PBigNumber(A.FNumber), B,
            PBigNumber(Result.FNumber)));
{$ENDIF}
end;

class operator BigInteger.Multiply(const A: BigInteger; const B: TIntLimb): BigInteger;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(A.FNumber.MulIntLimb(B, Result.FNumber));
{$ELSE}
  HResCheck(TBigNumber.MulIntLimb(PBigNumber(A.FNumber), B,
            PBigNumber(Result.FNumber)));
{$ENDIF}
end;

class operator BigInteger.IntDivide(const A: BigInteger; const B: TIntLimb): BigInteger;
var
  Remainder: TIntLimb;

begin
{$IFDEF TFL_INTFCALL}
  HResCheck(A.FNumber.DivRemIntLimb(B, Result.FNumber, Remainder));
{$ELSE}
  HResCheck(TBigNumber.DivRemIntLimb(PBigNumber(A.FNumber), B,
            PBigNumber(Result.FNumber), Remainder));
{$ENDIF}
end;

class operator BigInteger.Modulus(const A: BigInteger; const B: TIntLimb): TIntLimb;
var
  Quotient: BigInteger;

begin
{$IFDEF TFL_INTFCALL}
  HResCheck(A.FNumber.DivRemIntLimb(B, Quotient.FNumber, Result));
{$ELSE}
  HResCheck(TBigNumber.DivRemIntLimb(PBigNumber(A.FNumber), B,
            PBigNumber(Quotient.FNumber), Result));
{$ENDIF}
end;

class function BigInteger.DivRem(const Dividend: BigInteger;
               const Divisor: TIntLimb; var Remainder: TIntLimb): BigInteger;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(Dividend.FNumber.DivRemIntLimb(Divisor, Result.FNumber, Remainder));
{$ELSE}
  HResCheck(TBigNumber.DivRemIntLimb(PBigNumber(Dividend.FNumber), Divisor,
            PBigNumber(Result.FNumber), Remainder));
{$ENDIF}
end;

// -- arithmetic operations on TIntLimb & BigInteger --

class operator BigInteger.Add(const A: TIntLimb; const B: BigInteger): BigInteger;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(B.FNumber.AddIntLimb(A, Result.FNumber));
{$ELSE}
  HResCheck(TBigNumber.AddIntLimb(PBigNumber(B.FNumber), A,
            PBigNumber(Result.FNumber)));
{$ENDIF}
end;

class operator BigInteger.Subtract(const A: TIntLimb; const B: BigInteger): BigInteger;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(B.FNumber.SubIntLimb2(A, Result.FNumber));
{$ELSE}
  HResCheck(TBigNumber.SubIntLimb2(PBigNumber(B.FNumber), A,
            PBigNumber(Result.FNumber)));
{$ENDIF}
end;

class operator BigInteger.Multiply(const A: TIntLimb; const B: BigInteger): BigInteger;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(B.FNumber.MulIntLimb(A, Result.FNumber));
{$ELSE}
  HResCheck(TBigNumber.MulIntLimb(PBigNumber(B.FNumber), A,
            PBigNumber(Result.FNumber)));
{$ENDIF}
end;

class operator BigInteger.IntDivide(const A: TIntLimb; const B: BigInteger): TIntLimb;
var
  Remainder: TIntLimb;

begin
{$IFDEF TFL_INTFCALL}
  HResCheck(B.FNumber.DivRemIntLimb2(A, Result, Remainder));
{$ELSE}
  HResCheck(TBigNumber.DivRemIntLimb2(PBigNumber(B.FNumber), A,
                       Result, Remainder));
{$ENDIF}
end;

class operator BigInteger.Modulus(const A: TIntLimb; const B: BigInteger): TIntLimb;
var
  Quotient: TIntLimb;

begin
{$IFDEF TFL_INTFCALL}
  HResCheck(B.FNumber.DivRemIntLimb2(A, Quotient, Result));
{$ELSE}
  HResCheck(TBigNumber.DivRemIntLimb2(PBigNumber(B.FNumber), A,
                       Quotient, Result));
{$ENDIF}
end;

class function BigInteger.DivRem(const Dividend: TIntLimb;
               const Divisor: BigInteger; var Remainder: TIntLimb): TIntLimb;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(Divisor.FNumber.DivRemIntLimb2(Dividend, Result, Remainder));
{$ELSE}
  HResCheck(TBigNumber.DivRemIntLimb2(PBigNumber(Divisor.FNumber), Dividend,
            Result, Remainder));
{$ENDIF}
end;

function BigInteger.Next: BigInteger;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(FNumber.NextNumber(Result.FNumber);
{$ELSE}
  HResCheck(TBigNumber.NextNumber(PBigNumber(FNumber),
                                       PBigNumber(Result.FNumber)));
{$ENDIF}
end;

function BigInteger.Prev: BigInteger;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(FNumber.PrevNumber(Result.FNumber);
{$ELSE}
  HResCheck(TBigNumber.PrevNumber(PBigNumber(FNumber),
                                       PBigNumber(Result.FNumber)));
{$ENDIF}
end;

class operator BigInteger.Negative(const A: BigInteger): BigInteger;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(A.NegateNumber(Result.FNumber);
{$ELSE}
  HResCheck(TBigNumber.NegateNumber(PBigNumber(A.FNumber),
                                    PBigNumber(Result.FNumber)));
{$ENDIF}
end;

class operator BigInteger.Positive(const A: BigInteger): BigInteger;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(A.DuplicateNumber(Result.FNumber);
{$ELSE}
  HResCheck(TBigNumber.DuplicateNumber(PBigNumber(A.FNumber),
                                       PBigNumber(Result.FNumber)));
{$ENDIF}
end;

class operator BigCardinal.Positive(const A: BigCardinal): BigCardinal;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(A.DuplicateNumber(Result.FNumber);
{$ELSE}
  HResCheck(TBigNumber.DuplicateNumber(PBigNumber(A.FNumber),
                                       PBigNumber(Result.FNumber)));
{$ENDIF}
end;

{ TMont }

class function TMont.GetInstance(const Modulus: BigInteger): TMont;
begin
{$IFDEF TFL_DLL}
  HResCheck(GetMontInstance(Result.FInstance, Modulus.FNumber));
{$ELSE}
  HResCheck(GetMontInstance(PMontInstance(Result.FInstance), PBigNumber(Modulus.FNumber)));
{$ENDIF}
end;

function TMont.GetRModulus: BigInteger;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(FInstance.GetRModulus(Result.FNumber));
{$ELSE}
  HResCheck(TMontInstance.GetRModulus(PMontInstance(FInstance),
                                      PBigNumber(Result.FNumber)));
{$ENDIF}
end;

procedure TMont.Free;
begin
  FInstance:= nil;
end;

function TMont.IsAssigned: Boolean;
begin
  Result:= FInstance <> nil;
end;

procedure TMont.Burn;
begin
{$IFDEF TFL_INTFCALL}
  FInstance.Burn;
{$ELSE}
  TMontInstance.Burn(PMontInstance(FInstance));
{$ENDIF}
end;

function TMont.Convert(const A: BigInteger): BigInteger;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(FInstance.Convert(A.FNumber, Result.FNumber));
{$ELSE}
  HResCheck(TMontInstance.Convert(PMontInstance(FInstance),
                 PBigNumber(A.FNumber), PBigNumber(Result.FNumber)));
{$ENDIF}
end;

function TMont.Reduce(const A: BigInteger): BigInteger;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(FInstance.Reduce(A.FNumber, Result.FNumber));
{$ELSE}
  HResCheck(TMontInstance.Reduce(PMontInstance(FInstance),
                 PBigNumber(A.FNumber), PBigNumber(Result.FNumber)));
{$ENDIF}
end;

function TMont.Add(const A, B: BigInteger): BigInteger;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(FInstance.AddNumbers(A.FNumber, B.FNumber, Result.FNumber));
{$ELSE}
  HResCheck(TMontInstance.AddNumbers(PMontInstance(FInstance),
                 PBigNumber(A.FNumber), PBigNumber(B.FNumber),
                 PBigNumber(Result.FNumber)));
{$ENDIF}
end;

function TMont.Multiply(const A, B: BigInteger): BigInteger;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(FInstance.MulNumbers(A.FNumber, B.FNumber, Result.FNumber));
{$ELSE}
  HResCheck(TMontInstance.MulNumbers(PMontInstance(FInstance),
                 PBigNumber(A.FNumber), PBigNumber(B.FNumber),
                 PBigNumber(Result.FNumber)));
{$ENDIF}
end;

function TMont.Subtract(const A, B: BigInteger): BigInteger;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(FInstance.SubNumbers(A.FNumber, B.FNumber, Result.FNumber));
{$ELSE}
  HResCheck(TMontInstance.SubNumbers(PMontInstance(FInstance),
                 PBigNumber(A.FNumber), PBigNumber(B.FNumber),
                 PBigNumber(Result.FNumber)));
{$ENDIF}
end;

function TMont.ModMul(const A, B: BigInteger): BigInteger;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(FInstance.ModMulNumbers(A.FNumber, B.FNumber, Result.FNumber));
{$ELSE}
  HResCheck(TMontInstance.ModMulNumbers(PMontInstance(FInstance),
                 PBigNumber(A.FNumber), PBigNumber(B.FNumber),
                 PBigNumber(Result.FNumber)));
{$ENDIF}
end;

function TMont.ModPow(const Base: BigInteger; Pow: TLimb): BigInteger;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(FInstance.PowLimb(A.FNumber, B, Result.FNumber));
{$ELSE}
  HResCheck(TMontInstance.ModPowLimb(PMontInstance(FInstance),
                 PBigNumber(Base.FNumber), Pow, PBigNumber(Result.FNumber)));
{$ENDIF}
end;

function TMont.ModPow(const Base, Pow: BigInteger): BigInteger;
begin
{$IFDEF TFL_INTFCALL}
  HResCheck(FInstance.PowNumber(A.FNumber, B.FNumber, Result.FNumber));
{$ELSE}
  HResCheck(TMontInstance.ModPowNumber(PMontInstance(FInstance),
                 PBigNumber(Base.FNumber), PBigNumber(Pow.FNumber),
                 PBigNumber(Result.FNumber)));
{$ENDIF}
end;

end.
