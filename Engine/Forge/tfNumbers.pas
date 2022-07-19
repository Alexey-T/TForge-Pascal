{ *********************************************************** }
{ *                     TForge Library                      * }
{ *       Copyright (c) Sergey Kasandrov 1997, 2016         * }
{ *********************************************************** }

unit tfNumbers;

{$I TFL.inc}

{$IFDEF TFL_LOG}
  {.$DEFINE LOG}
{$ENDIF}

{$IFDEF TFL_LIMB32_ASM86}
  {.$DEFINE LIMB32_ASM86}
{$ENDIF}

{$IFDEF TFL_POINTERMATH}
  {$POINTERMATH ON}
{$ENDIF}

{$R-}   // range checking is not allowed

interface

uses {Windows, }SysUtils, tfTypes, tfLimbs
     {$IFDEF LOG}, Loggers{$ENDIF};

type
  PBigNumber = ^TBigNumber;
  PPBigNumber = ^PBigNumber;
  TBigNumber = record
  private const
    FUsedSize = SizeOf(Cardinal); // because SizeOf(FUsed) does not compile
  public type
{$IFDEF DEBUG}
    TLimbArray = array[0..7] of TLimb;
{$ELSE}
    TLimbArray = array[0..0] of TLimb;
{$ENDIF}

  public
    FVTable: Pointer;
    FRefCount: Integer;
    FCapacity: Integer;          // number of limbs allocated
    FSign: Integer;

    FUsed: Integer;               // number of limbs used
    FLimbs: TLimbArray;

// -- IBigNumber implementation

    class procedure Burn(A: PBigNumber);
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function GetHashCode(Inst: PBigNumber): Integer;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function GetLen(Inst: PBigNumber): Integer;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function GetRawData(Inst: PBigNumber): PByte;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;

    class function GetIsEven(Inst: PBigNumber): Boolean;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function GetIsOne(Inst: PBigNumber): Boolean;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function GetIsPowerOfTwo(Inst: PBigNumber): Boolean;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function GetIsZero(Inst: PBigNumber): Boolean;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function GetSign(Inst: PBigNumber): Integer;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function GetSize(Inst: PBigNumber): Integer;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;

    class function CompareNumbers(A, B: PBigNumber): Integer;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function CompareNumbersU(A, B: PBigNumber): Integer;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function EqualNumbers(A, B: PBigNumber): Boolean;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function EqualNumbersU(A, B: PBigNumber): Boolean;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;

    class function AddNumbers(A, B: PBigNumber; var R: PBigNumber): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function AddNumbersU(A, B: PBigNumber; var R: PBigNumber): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function SubNumbers(A, B: PBigNumber; var R: PBigNumber): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function SubNumbersU(A, B: PBigNumber; var R: PBigNumber): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function MulNumbers(A, B: PBigNumber; var R: PBigNumber): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function SqrNumber(A: PBigNumber; var R: PBigNumber): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function MulNumbersU(A, B: PBigNumber; var R: PBigNumber): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function DivRemNumbers(A, B: PBigNumber; var Q, R: PBigNumber): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function DivRemNumbersU(A, B: PBigNumber; var Q, R: PBigNumber): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;

    class function AndNumbers(A, B: PBigNumber; var R: PBigNumber): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function AndNumbersU(A, B: PBigNumber; var R: PBigNumber): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function OrNumbers(A, B: PBigNumber; var R: PBigNumber): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function OrNumbersU(A, B: PBigNumber; var R: PBigNumber): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function XorNumbers(A, B: PBigNumber; var R: PBigNumber): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;

    class function ShlNumber(A: PBigNumber; Shift: Cardinal; var R: PBigNumber): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function ShrNumber(A: PBigNumber; Shift: Cardinal; var R: PBigNumber): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;

    class function AssignNumber(A: PBigNumber; var R: PBigNumber): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function AbsNumber(A: PBigNumber; var R: PBigNumber): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function NegateNumber(A: PBigNumber; var R: PBigNumber): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function DuplicateNumber(A: PBigNumber; var R: PBigNumber): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function Pow(A: PBigNumber; APower: Cardinal; var R: PBigNumber): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function PowU(A: PBigNumber; APower: Cardinal; var R: PBigNumber): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;

    class function SqrtNumber(A: PBigNumber; var R: PBigNumber): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function GCD(A, B: PBigNumber; var G: PBigNumber): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function EGCD(A, B: PBigNumber; var G, X, Y: PBigNumber): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function LCM(A, B: PBigNumber; var G: PBigNumber): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;

    class function ModPow(BaseValue, ExpValue, Modulus: PBigNumber; var R: PBigNumber): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function ModInverse(A, M: PBigNumber; var R: PBigNumber): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;

    class function NextNumber(A: PBigNumber; var R: PBigNumber): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function NextNumberU(A: PBigNumber; var R: PBigNumber): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function PrevNumber(A: PBigNumber; var R: PBigNumber): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function PrevNumberU(A: PBigNumber; var R: PBigNumber): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;

    class function ToPByte(A: PBigNumber; P: PByte; var L: Cardinal): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;

    class function ToDec(A: PBigNumber; P: PByte; var L: Integer): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;

    class function ToHex(A: PBigNumber; P: PByte; var L: Integer;
                               TwoCompl: Boolean): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;

    class function CompareToLimb(A: PBigNumber; B: TLimb): Integer;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function CompareToLimbU(A: PBigNumber; B: TLimb): Integer;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function CompareToIntLimb(A: PBigNumber; B: TIntLimb): Integer;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function CompareToIntLimbU(A: PBigNumber; B: TIntLimb): Integer;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;

    class function CompareToDblLimb(A: PBigNumber; B: TDLimb): Integer;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function CompareToDblLimbU(A: PBigNumber; B: TDLimb): Integer;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function CompareToDblIntLimb(A: PBigNumber; B: TDIntLimb): Integer;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function CompareToDblIntLimbU(A: PBigNumber; B: TDIntLimb): Integer;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;

    class function AddLimb(A: PBigNumber; Limb: TLimb; var R: PBigNumber): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function AddLimbU(A: PBigNumber; Limb: TLimb; var R: PBigNumber): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function AddIntLimb(A: PBigNumber; Limb: TIntLimb; var R: PBigNumber): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
//    class function AddIntLimbU(A: PBigNumber; Limb: TIntLimb; var R: PBigNumber): HResult;
//      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;

//    class function AddDblLimb(A: PBigNumber; B: TDblLimb; var R: PBigNumber): HResult;
//      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;

    class function SubLimb(A: PBigNumber; Limb: TLimb; var R: PBigNumber): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function SubLimb2(A: PBigNumber; Limb: TLimb; var R: PBigNumber): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function SubLimbU(A: PBigNumber; Limb: TLimb; var R: PBigNumber): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
//    class function SubLimbU2(A: PBigNumber; Limb: TLimb; var R: PBigNumber): HResult;
    class function SubLimbU2(A: PBigNumber; Limb: TLimb; var R: TLimb): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function SubIntLimb(A: PBigNumber; Limb: TIntLimb; var R: PBigNumber): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function SubIntLimb2(A: PBigNumber; Limb: TIntLimb; var R: PBigNumber): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
//    class function SubIntLimbU(A: PBigNumber; Limb: TIntLimb; var R: PBigNumber): HResult;
//      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;

    class function MulLimb(A: PBigNumber; Limb: TLimb; var R: PBigNumber): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function MulLimbU(A: PBigNumber; Limb: TLimb; var R: PBigNumber): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function MulIntLimb(A: PBigNumber; Limb: TIntLimb; var R: PBigNumber): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
//    class function MulIntLimbU(A: PBigNumber; Limb: TIntLimb; var R: PBigNumber): HResult;
//      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;

    class function DivRemLimb(A: PBigNumber; Limb: TLimb;
                              var Q, R: PBigNumber): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function DivRemLimb2(A: PBigNumber; Limb: TLimb;
                              var Q: PBigNumber; var R: TLimb): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function DivRemLimbU(A: PBigNumber; Limb: TLimb;
                               var Q: PBigNumber; var R: TLimb): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function DivRemLimbU2(A: PBigNumber; Limb: TLimb;
                               var Q: TLimb; var R: TLimb): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;

    class function DivRemIntLimb(A: PBigNumber; Limb: TIntLimb;
                                 var Q: PBigNumber; var R: TIntLimb): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;
    class function DivRemIntLimb2(A: PBigNumber; Limb: TIntLimb;
                                  var Q: TIntLimb; var R: TIntLimb): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;

// -- end of IBigNumber implementation

// -- conversions from/to BigNumber

    class function FromBytes(var A: PBigNumber; const Bytes: TBytes): TF_RESULT; static;
//    class function FromPAnsiCharHex(var A: PBigNumber; S: PByte; L: Integer;
//                     AllowNegative, TwoCompl: Boolean): HResult; static;
    class function FromPCharHex(var A: PBigNumber; S: PChar; L: Integer;
                     AllowNegative, TwoCompl: Boolean): TF_RESULT; static;

    class function FromString(var A: PBigNumber;
                   const S: string; TwoCompl: Boolean = False): TF_RESULT; static;

    class function ToLimb(A: PBigNumber; var Value: TLimb): TF_RESULT; static;
    class function ToIntLimb(A: PBigNumber; var Value: TIntLimb): TF_RESULT; static;

    class function ToDblLimb(A: PBigNumber; var Value: TDLimb): TF_RESULT; static;
    class function ToDblIntLimb(A: PBigNumber; var Value: TDIntLimb): TF_RESULT; static;

    class function GetLimb(A: PBigNumber; var Value: TLimb): TF_RESULT; static;
    class function GetDblLimb(A: PBigNumber; var Value: TDLimb): TF_RESULT; static;

//    class function ToCardinal(A: PBigNumber; var Value: Cardinal): HResult; static;
//    class function ToInteger(A: PBigNumber; var Value: Integer): HResult; static;

//    class function ToString(A: PBigNumber; var S: string): TF_RESULT; static;
//    class function ToHexString(A: PBigNumber; var S: string; Digits: Integer;
//                   const Prefix: string; TwoCompl: Boolean): TF_RESULT; static;

//    class function ToBytes(A: PBigNumber; var Bytes: TBytes): TF_RESULT; static;

    class procedure Normalize(Inst: PBigNumber); static;

    class function AllocNumber(var A: PBigNumber; NLimbs: Cardinal = 0): TF_RESULT; static;

    class function AllocPowerOfTwo(var A: PBigNumber;
                                   APower: Cardinal): TF_RESULT; static;

    class function CloneNumber(var A: PBigNumber; B: PBigNumber;
                                ASign: Integer = 0): TF_RESULT; static;

    class function AssignCardinal(var A: PBigNumber; const Value: Cardinal;
                                ASign: Integer = 0): TF_RESULT; static;

    class function AssignInteger(var A: PBigNumber; const Value: Integer;
                                ASign: Integer = 0): TF_RESULT; static;

    class function DivModLimbU(A: PBigNumber; Limb: TLimb;
                               var Q: PBigNumber; var R: TLimb): TF_RESULT; stdcall; static;

    class function NumBits(A: PBigNumber): Integer;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;

    class function SetBit(A: PBigNumber; Shift: Cardinal): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;

    class function MaskBits(A: PBigNumber; Shift: Cardinal): TF_RESULT;
      {$IFDEF TFL_STDCALL}stdcall;{$ENDIF} static;

    procedure Free; inline;
    class procedure FreeAndNil(var Inst: PBigNumber); static;

    function IsNegative: Boolean; inline;
    function IsZero: Boolean; inline;

//    function AsString: string;
//    function AsHexString(Digits: Cardinal; TwoCompl: Boolean = False): string;

//    function SelfAddNumber(B: PBigNumber): TF_RESULT;


    function SelfCopy(Inst: PBigNumber): TF_RESULT;
    function SelfAddLimb(Value: TLimb): TF_RESULT;
    function SelfAddLimbU(Value: TLimb): TF_RESULT;

    function SelfSubLimbU(Value: TLimb): TF_RESULT;
    function SelfSubLimb(Value: TLimb): TF_RESULT;

    function SelfMulLimb(Value: TLimb): TF_RESULT;
    function SelfDivModLimbU(Value: TLimb; var Remainder: TLimb): TF_RESULT;
  end;

// -- conversions to BigNumber

function BigNumberFromLimb(var A: PBigNumber; Value: TLimb): TF_RESULT;
  {$IFDEF TFL_STDCALL}stdcall;{$ENDIF}
function BigNumberFromDblLimb(var A: PBigNumber; Value: TDLimb): TF_RESULT;
  {$IFDEF TFL_STDCALL}stdcall;{$ENDIF}

function BigNumberFromIntLimb(var A: PBigNumber; Value: TIntLimb): TF_RESULT;
  {$IFDEF TFL_STDCALL}stdcall;{$ENDIF}
function BigNumberFromDblIntLimb(var A: PBigNumber; Value: TDIntLimb): TF_RESULT;
  {$IFDEF TFL_STDCALL}stdcall;{$ENDIF}

function BigNumberFromPByte(var A: PBigNumber;
             P: PByte; L: Integer; AllowNegative: Boolean): TF_RESULT;
  {$IFDEF TFL_STDCALL}stdcall;{$ENDIF}

function BigNumberFromPChar(var A: PBigNumber; P: PByte; L: Integer;
         CharSize: Integer; AllowNegative: Boolean; TwoCompl: Boolean): TF_RESULT;
  {$IFDEF TFL_STDCALL}stdcall;{$ENDIF}

function BigNumberAlloc(var A: PBigNumber; ASize: Integer): TF_RESULT;
  {$IFDEF TFL_STDCALL}stdcall;{$ENDIF}

function BigNumberPowerOfTwo(var A: PBigNumber; APower: Cardinal): TF_RESULT;
  {$IFDEF TFL_STDCALL}stdcall;{$ENDIF}

procedure SetBigNumberZero(var A: PBigNumber);
  {$IFDEF TFL_STDCALL}stdcall;{$ENDIF}

procedure SetBigNumberOne(var A: PBigNumber);
  {$IFDEF TFL_STDCALL}stdcall;{$ENDIF}

procedure SetBigNumberMinusOne(var A: PBigNumber);
  {$IFDEF TFL_STDCALL}stdcall;{$ENDIF}

(*
  function BigNumberFromPWideChar(var A: PBigNumber;
               P: PWideChar; L: Cardinal; AllowNegative: Boolean): HResult;
    {$IFDEF TFL_STDCALL}stdcall;{$ENDIF}
*)

{$IFDEF DEBUG}
type
  TLimbs = array[0..7] of TLimb;
  PLimbs = ^TLimbs;
{$ENDIF}

implementation

uses tfRecords, tfUtils, arrProcs;

const
  BigNumVTable: array[0..83] of Pointer = (
   @TForgeInstance.QueryIntf,
   @TForgeInstance.Addref,
   @TForgeInstance.Release,
   @TBigNumber.Burn,

   @TBigNumber.GetHashCode,
   @TBigNumber.GetLen,
   @TBigNumber.GetRawData,

   @TBigNumber.GetIsEven,
   @TBigNumber.GetIsOne,
   @TBigNumber.GetIsPowerOfTwo,
   @TBigNumber.GetIsZero,
   @TBigNumber.GetSign,
   @TBigNumber.GetSize,

   @TBigNumber.CompareNumbers,
   @TBigNumber.CompareNumbersU,
   @TBigNumber.EqualNumbers,
   @TBigNumber.EqualNumbersU,

   @TBigNumber.AddNumbers,
   @TBigNumber.AddNumbersU,
   @TBigNumber.SubNumbers,
   @TBigNumber.SubNumbersU,
   @TBigNumber.MulNumbers,
   @TBigNumber.MulNumbersU,
   @TBigNumber.DivRemNumbers,
   @TBigNumber.DivRemNumbersU,

   @TBigNumber.AndNumbers,
   @TBigNumber.AndNumbersU,
   @TBigNumber.OrNumbers,
   @TBigNumber.OrNumbersU,
   @TBigNumber.XorNumbers,

   @TBigNumber.ShlNumber,
   @TBigNumber.ShrNumber,

   @TBigNumber.AssignNumber,
   @TBigNumber.AbsNumber,
   @TBigNumber.NegateNumber,
   @TBigNumber.DuplicateNumber,
   @TBigNumber.Pow,
   @TBigNumber.PowU,

   @TBigNumber.SqrNumber,
   @TBigNumber.SqrtNumber,
   @TBigNumber.GCD,
   @TBigNumber.EGCD,
   @TBigNumber.LCM,
   @TBigNumber.ModPow,
   @TBigNumber.ModInverse,

   @TBigNumber.ToLimb,
   @TBigNumber.ToIntLimb,
   @TBigNumber.ToDec,
   @TBigNumber.ToHex,
   @TBigNumber.ToPByte,

   @TBigNumber.CompareToLimb,
   @TBigNumber.CompareToLimbU,
   @TBigNumber.CompareToIntLimb,
   @TBigNumber.CompareToIntLimbU,

   @TBigNumber.AddLimb,
   @TBigNumber.AddLimbU,
   @TBigNumber.AddIntLimb,

   @TBigNumber.SubLimb,
   @TBigNumber.SubLimb2,
   @TBigNumber.SubLimbU,
   @TBigNumber.SubLimbU2,
   @TBigNumber.SubIntLimb,
   @TBigNumber.SubIntLimb2,

   @TBigNumber.MulLimb,
   @TBigNumber.MulLimbU,
   @TBigNumber.MulIntLimb,

   @TBigNumber.DivRemLimb,
   @TBigNumber.DivRemLimb2,
   @TBigNumber.DivRemLimbU,
   @TBigNumber.DivRemLimbU2,
   @TBigNumber.DivRemIntLimb,
   @TBigNumber.DivRemIntLimb2,

   @TBigNumber.NextNumber,
   @TBigNumber.NextNumberU,
   @TBigNumber.PrevNumber,
   @TBigNumber.PrevNumberU,
                                  // conversion to integer types
   @TBigNumber.GetLimb,
   @TBigNumber.GetDblLimb,
                                  // Double limb support
   @TBigNumber.ToDblLimb,
   @TBigNumber.ToDblIntLimb,
   @TBigNumber.CompareToDblLimb,
   @TBigNumber.CompareToDblLimbU,
   @TBigNumber.CompareToDblIntLimb,
   @TBigNumber.CompareToDblIntLimbU
   );

const
  BigNumZero: TBigNumber = (
    FVTable: @BigNumVTable;
    FRefCount: -1;
    FCapacity: 0;
    FSign: 0;
    FUsed: 1;
{$IFDEF DEBUG}
    FLimbs: (0, 0, 0, 0, 0, 0, 0, 0);
{$ELSE}
    FLimbs: (0);
{$ENDIF}
    );

  BigNumOne: TBigNumber = (
    FVTable: @BigNumVTable;
    FRefCount: -1;
    FCapacity: 0;
    FSign: 0;
    FUsed: 1;
{$IFDEF DEBUG}
    FLimbs: (1, 0, 0, 0, 0, 0, 0, 0);
{$ELSE}
    FLimbs: (1);
{$ENDIF}
    );

  BigNumMinusOne: TBigNumber = (
    FVTable: @BigNumVTable;
    FRefCount: -1;
    FCapacity: 0;
    FSign: -1;
    FUsed: 1;
{$IFDEF DEBUG}
    FLimbs: (1, 0, 0, 0, 0, 0, 0, 0);
{$ELSE}
    FLimbs: (1);
{$ENDIF}
    );

{
function TBigNumber.AsString: string;
begin
  Result:= '';
  ToString(@Self, Result);
end;

function TBigNumber.AsHexString(Digits: Cardinal; TwoCompl: Boolean): string;
begin
  Result:= '';
  ToHexString(@Self, Result, Digits, '$', TwoCompl);
end;
}

class function TBigNumber.CompareNumbers(A, B: PBigNumber): Integer;
begin
  if A.FSign xor B.FSign < 0
    then begin
      if (A.FSign >= 0)
        then Result:= 1
        else Result:= -1;
    end
    else begin
      Result:= A.FUsed - B.FUsed;
      if Result = 0 then
        Result:= arrCmp(@A.FLimbs, @B.FLimbs, A.FUsed);
      if (A.FSign < 0) then Result:= - Result;
    end;
end;

class function TBigNumber.CompareNumbersU(A, B: PBigNumber): Integer;
begin
  Result:= A.FUsed - B.FUsed;
  if Result = 0 then
    Result:= arrCmp(@A.FLimbs, @B.FLimbs, A.FUsed);
end;

class function TBigNumber.EqualNumbers(A, B: PBigNumber): Boolean;
begin
  Result:= (A.FSign xor B.FSign = 0) and (A.FUsed = B.FUsed)
    and CompareMem(@A.FLimbs, @B.FLimbs, A.FUsed);
end;

class function TBigNumber.EqualNumbersU(A, B: PBigNumber): Boolean;
begin
  Result:= (A.FUsed = B.FUsed)
    and CompareMem(@A.FLimbs, @B.FLimbs, A.FUsed);
end;

class function TBigNumber.CompareToIntLimb(A: PBigNumber; B: TIntLimb): Integer;
begin
  Result:= A.FUsed - 1;
  if Result = 0 then begin
    if (A.FSign >= 0) then begin
      if (B < 0) or (A.FLimbs[0] > TLimb(B)) then Result:= 1
      else if A.FLimbs[0] < TLimb(B) then Result:= -1;
    end
    else begin { A < 0 }
      if (B >= 0) or (A.FLimbs[0] > TLimb(-B)) then Result:= -1
      else if A.FLimbs[0] < TLimb(-B) then Result:= 1;
    end;
  end
  else if (A.FSign < 0) then Result:= -1;
end;

class function TBigNumber.CompareToIntLimbU(A: PBigNumber; B: TIntLimb): Integer;
begin
  Result:= A.FUsed - 1;
  if Result = 0 then begin
    if (B < 0) or (A.FLimbs[0] > TLimb(B)) then Result:= 1
    else if (A.FLimbs[0] < TLimb(B)) then Result:= -1;
  end;
end;

class function TBigNumber.CompareToDblIntLimb(A: PBigNumber; B: TDIntLimb): Integer;
var
  Tmp: TDLimb;

begin
  Result:= 2 - A.FUsed;
  if Result = 0 then begin        // A.FUsed = 2
    Tmp:= PDLimb(@A.FLimbs)^;
    if (A.FSign >= 0) then begin
      if (B < 0) or (Tmp > TDLimb(B)) then Result:= 1
      else if Tmp < TDLimb(B) then Result:= -1;
    end
    else if (B >= 0) or (Tmp > TDLimb(-B)) then Result:= -1
    else if (Tmp < TDLimb(-B)) then Result:= 1;
  end
  else if Result > 0 then begin   // A.FUsed = 1
    Tmp:= A.FLimbs[0];
    if (A.FSign >= 0) then begin
      if (B >= 0) then begin
        if (Tmp < TDLimb(B)) then Result:= -1
        else if (Tmp = TDLimb(B)) then Result:= 0;
      end;
    end
    else if (B >= 0) or (Tmp > TDLimb(-B)) then Result:= -1
    else if (Tmp = TDLimb(-B)) then Result:= 0;
  end
  else begin                      // A.FUsed > 2
    if (A.FSign >= 0) then Result:= 1;
  end;
end;

class function TBigNumber.CompareToDblIntLimbU(A: PBigNumber; B: TDIntLimb): Integer;
var
  Tmp: TDLimb;

begin
  if B < 0 then Result:= 1
  else begin
    Result:= 2 - A.FUsed;
    if Result = 0 then begin        // A.FUsed = 2
      Tmp:= PDLimb(@A.FLimbs)^;
      if (Tmp > TDLimb(B)) then Result:= 1
      else if Tmp < TDLimb(B) then Result:= -1;
    end
    else if Result > 0 then begin   // A.FUsed = 1
      Tmp:= A.FLimbs[0];
      if (Tmp < TDLimb(B)) then Result:= -1
      else if (Tmp = TDLimb(B)) then Result:= 0;
    end
  end;
end;

class function TBigNumber.CompareToLimb(A: PBigNumber; B: TLimb): Integer;
begin
  if (A.FSign < 0) then
    Result:= -1
  else begin
    Result:= A.FUsed - 1;
    if Result = 0 then begin
      if (A.FLimbs[0] > B) then Result:= 1
      else if (A.FLimbs[0] < B) then Result:= -1;
    end;
  end;
end;

class function TBigNumber.CompareToDblLimb(A: PBigNumber; B: TDLimb): Integer;
var
  Tmp: TDLimb;

begin
  if (A.FSign < 0) then
    Result:= -1
  else begin
    Result:= A.FUsed - 2;
    if Result = 0 then begin
      Tmp:= PDLimb(@A.FLimbs)^;
      if (Tmp > B) then Result:= 1
      else if (Tmp < B) then Result:= -1;
    end
    else if Result < 0 then begin
      Tmp:= A.FLimbs[0];
      if (Tmp > B) then Result:= 1
      else if (Tmp = B) then Result:= 0;
    end;
  end;
end;

class function TBigNumber.CompareToDblLimbU(A: PBigNumber; B: TDLimb): Integer;
var
  Tmp: TDLimb;

begin
  Result:= A.FUsed - 2;
  if Result = 0 then begin
    Tmp:= PDLimb(@A.FLimbs)^;
    if (Tmp > B) then Result:= 1
    else if (Tmp < B) then Result:= -1;
  end
  else if Result < 0 then begin
    Tmp:= A.FLimbs[0];
    if (Tmp > B) then Result:= 1
    else if (Tmp = B) then Result:= 0;
  end;
end;

class function TBigNumber.CompareToLimbU(A: PBigNumber; B: TLimb): Integer;
begin
  Result:= A.FUsed - 1;
  if Result = 0 then begin
    if (A.FLimbs[0] > B) then Result:= 1
    else if (A.FLimbs[0] < B) then Result:= -1;
  end;
end;

class function TBigNumber.AddNumbers(A, B: PBigNumber; var R: PBigNumber): TF_RESULT;
var
  UsedA, UsedB: Cardinal;
  LimbsA, LimbsB: PLimb;
  Diff: Integer;
  Tmp: PBigNumber;

begin
  UsedA:= A.FUsed;
  UsedB:= B.FUsed;
  LimbsA:= @A.FLimbs;
  LimbsB:= @B.FLimbs;

  if A = B then begin
    Result:= AllocNumber(Tmp, UsedA + 1);
    if Result <> TF_S_OK then Exit;
    Tmp.FUsed:= arrShlOne(@A.FLimbs, @Tmp.FLimbs, UsedA);
{
    if arrShlOne(@A.FLimbs, @Tmp.FLimbs, A.FUsed) <> 0
      then
        Tmp.FUsed:= UsedA + 1
      else
        Tmp.FUsed:= UsedA;
}
    Tmp.FSign:= A.FSign;
    tfFreeInstance(R); // if (R <> nil) then TtfRecord.Release(R);
    R:= Tmp;
  end

  else { A <> B } begin
    if (UsedB = 1) and (LimbsB^ = 0) { B = 0 } then begin
      if R <> A then begin
        tfFreeInstance(R); //if R <> nil then TtfRecord.Release(R);
        R:= A;
        tfAddrefInstance(R); //TtfRecord.AddRef(R);
      end;
      Result:= TF_S_OK;
      Exit;
    end;

    if (UsedA = 1) and (LimbsA^ = 0) { A = 0 } then begin
      if R <> B then begin
        tfFreeInstance(R); //if R <> nil then TtfRecord.Release(R);
        R:= B;
        tfAddrefInstance(R); //TtfRecord.AddRef(R);
      end;
      Result:= TF_S_OK;
      Exit;
    end;

    if A.FSign xor B.FSign >= 0 then begin
// Values have the same sign - ADD lesser to greater

      if UsedA >= UsedB then begin
        Result:= AllocNumber(Tmp, UsedA + 1);
        if Result <> TF_S_OK then Exit;
        if arrAdd(LimbsA, LimbsB, @Tmp.FLimbs, UsedA, UsedB)
          then
            Tmp.FUsed:= UsedA + 1
          else
            Tmp.FUsed:= UsedA;
        Tmp.FSign:= A.FSign;
      end
      else begin
        Result:= AllocNumber(Tmp, UsedB + 1);
        if Result <> TF_S_OK then Exit;
        if arrAdd(LimbsB, LimbsA, @Tmp.FLimbs, UsedB, UsedA)
          then
            Tmp.FUsed:= UsedB + 1
          else
            Tmp.FUsed:= UsedB;
        Tmp.FSign:= B.FSign;
      end;

      tfFreeInstance(R); //if (R <> nil) then TtfRecord.Release(R);
      R:= Tmp;

    end
    else begin
// Values have opposite signs - SUB lesser from greater

      if (UsedA = UsedB) then begin
        Diff:= arrCmp(LimbsA, LimbsB, UsedA);
        if Diff = 0 then begin
          tfFreeInstance(R); //if (R <> nil) then TtfRecord.Release(R);
          R:= @BigNumZero;
          Result:= TF_S_OK;
          Exit;
        end;
      end
      else
        Diff:= Ord(UsedA > UsedB) shl 1 - 1;

      if Diff > 0 then begin
        Result:= AllocNumber(Tmp, UsedA + 1);
        if Result <> TF_S_OK then Exit;
        arrSub(LimbsA, LimbsB, @Tmp.FLimbs, UsedA, UsedB);
        Tmp.FUsed:= UsedA;
        Tmp.FSign:= A.FSign;
        Normalize(Tmp);

        tfFreeInstance(R); //if (R <> nil) then TtfRecord.Release(R);
        R:= Tmp;
      end
      else begin
        Result:= AllocNumber(Tmp, UsedB + 1);
        if Result <> TF_S_OK then Exit;
        arrSub(LimbsB, LimbsA, @Tmp.FLimbs, UsedB, UsedA);

        Tmp.FUsed:= UsedB;
        Tmp.FSign:= B.FSign;
        Normalize(Tmp);

        tfFreeInstance(R); //if (R <> nil) then TtfRecord.Release(R);
        R:= Tmp;
      end;
    end;
  end;
  Result:= TF_S_OK;
end;

class function TBigNumber.AddNumbersU(A, B: PBigNumber; var R: PBigNumber): TF_RESULT;
var
  UsedA, UsedB: Cardinal;
  LimbsA, LimbsB: PLimb;
  Tmp: PBigNumber;

begin
  UsedA:= A.FUsed;
  UsedB:= B.FUsed;
  LimbsA:= @A.FLimbs;
  LimbsB:= @B.FLimbs;

  if A = B then begin
    Result:= AllocNumber(Tmp, UsedA + 1);
    if Result <> TF_S_OK then Exit;
    Tmp.FUsed:= arrShlOne(@A.FLimbs, @Tmp.FLimbs, UsedA);
{
    if arrShlOne(@A.FLimbs, @Tmp.FLimbs, A.FUsed) <> 0
      then
        Tmp.FUsed:= UsedA + 1
      else
        Tmp.FUsed:= UsedA;
}
    tfFreeInstance(R); //if (R <> nil) then TtfRecord.Release(R);
    R:= Tmp;
  end

  else { A <> B } begin

    if (UsedB = 1) and (LimbsB^ = 0) { B = 0 } then begin
      if R <> A then begin
        tfFreeInstance(R); //if R <> nil then TtfRecord.Release(R);
        R:= A;
        tfAddrefInstance(R); //TtfRecord.AddRef(R);
      end;
      Result:= TF_S_OK;
      Exit;
    end;

    if (UsedA = 1) and (LimbsA^ = 0) { A = 0 } then begin
      if R <> B then begin
        tfFreeInstance(R); //if R <> nil then TtfRecord.Release(R);
        R:= B;
        tfAddrefInstance(R); //TtfRecord.AddRef(R);
      end;
      Result:= TF_S_OK;
      Exit;
    end;

    if UsedA >= UsedB then begin
      Result:= AllocNumber(Tmp, UsedA + 1);
      if Result <> TF_S_OK then Exit;
      if arrAdd(LimbsA, LimbsB, @Tmp.FLimbs, UsedA, UsedB)
        then
          Tmp.FUsed:= UsedA + 1
        else
          Tmp.FUsed:= UsedA;

      tfFreeInstance(R); //if (R <> nil) then TtfRecord.Release(R);
      R:= Tmp;

    end
    else begin
      Result:= AllocNumber(Tmp, UsedB + 1);
      if Result <> TF_S_OK then Exit;
      if arrAdd(LimbsB, LimbsA, @Tmp.FLimbs, UsedB, UsedA)
        then
          Tmp.FUsed:= UsedB + 1
        else
          Tmp.FUsed:= UsedB;

      tfFreeInstance(R); //if (R <> nil) then TtfRecord.Release(R);
      R:= Tmp;
    end
  end;
  Result:= TF_S_OK;
end;

class function TBigNumber.SubNumbers(A, B: PBigNumber; var R: PBigNumber): TF_RESULT;
var
  UsedA, UsedB: Cardinal;
  LimbsA, LimbsB: PLimb;
  Diff: Integer;
  Tmp: PBigNumber;

begin
  UsedA:= A.FUsed;
  UsedB:= B.FUsed;
  LimbsA:= @A.FLimbs;
  LimbsB:= @B.FLimbs;

  if A = B then begin
    tfFreeInstance(R); //if (R <> nil) then TtfRecord.Release(R);
    R:= @BigNumZero;
    Result:= TF_S_OK;
    Exit;
  end

  else { A <> B } begin
    if (UsedB = 1) and (LimbsB^ = 0) { B = 0 } then begin
      if R <> A then begin
        tfFreeInstance(R); //if R <> nil then TtfRecord.Release(R);
        R:= A;
        tfAddrefInstance(R); //TtfRecord.AddRef(R);
      end;
      Result:= TF_S_OK;
      Exit;
    end;

    if (UsedA = 1) and (LimbsA^ = 0) { A = 0, B <> 0 } then begin

      Result:= AllocNumber(Tmp, B.FUsed);
      if Result = TF_S_OK then begin
        Move(B.FUsed, Tmp.FUsed, FUsedSize + B.FUsed * SizeOf(TLimb));
        Tmp.FSign:= not B.FSign;
        tfFreeInstance(R); //if (R <> nil) then TtfRecord.Release(R);
        R:= Tmp;
      end;
      Exit;
    end;

    if A.FSign xor B.FSign >= 0 {Sign(A) = Sign(B)} then begin
// Values have the same sign - SUB lesser from greater
      if (UsedA = UsedB) then begin
        Diff:= arrCmp(@A.FLimbs, @B.FLimbs, UsedA);
        if Diff = 0 then begin
          tfFreeInstance(R); //if (R <> nil) then TtfRecord.Release(R);
          R:= @BigNumZero;
          Result:= TF_S_OK;
          Exit;
        end;
      end
      else
        Diff:= Ord(UsedA > UsedB) shl 1 - 1;

      if Diff > 0 { Abs(A) > Abs(B) } then begin
        Result:= AllocNumber(Tmp, UsedA + 1);
        if Result <> TF_S_OK then Exit;
        arrSub(LimbsA, LimbsB, @Tmp.FLimbs, UsedA, UsedB);
        Tmp.FUsed:= UsedA;
        Tmp.FSign:= A.FSign;
        Normalize(Tmp);
      end
      else { Abs(A) < Abs(B) } begin
        Result:= AllocNumber(Tmp, UsedB + 1);
        if Result <> TF_S_OK then Exit;
        arrSub(LimbsB, LimbsA, @Tmp.FLimbs, UsedB, UsedA);

        Tmp.FUsed:= UsedB;
        Tmp.FSign:= not B.FSign;
        Normalize(Tmp);

      end;

      tfFreeInstance(R); //if (R <> nil) then TtfRecord.Release(R);
      R:= Tmp;

    end {Sign(A) = Sign(B)}
    else {Sign(A) <> Sign(B)} begin
// Values have opposite signs - ADD lesser to greater

      if UsedA >= UsedB then begin
        Result:= AllocNumber(Tmp, UsedA + 1);
        if Result <> TF_S_OK then Exit;
        if arrAdd(LimbsA, LimbsB, @Tmp.FLimbs, UsedA, UsedB)
          then
            Tmp.FUsed:= UsedA + 1
          else
            Tmp.FUsed:= UsedA;
      end
      else begin
        Result:= AllocNumber(Tmp, UsedB + 1);
        if Result <> TF_S_OK then Exit;
        if arrAdd(LimbsB, LimbsA, @Tmp.FLimbs, UsedB, UsedA)
          then
            Tmp.FUsed:= UsedB + 1
          else
            Tmp.FUsed:= UsedB;
      end;

// знак разности равен знаку первого операнда
      Tmp.FSign:= A.FSign;

      tfFreeInstance(R); //if (R <> nil) then TtfRecord.Release(R);
      R:= Tmp;

    end {Sign(A) <> Sign(B)};
  end { A <> B };
  Result:= TF_S_OK;
end;

class function TBigNumber.SubNumbersU(A, B: PBigNumber; var R: PBigNumber): TF_RESULT;
var
  UsedA, UsedB: Cardinal;
  LimbsA, LimbsB: PLimb;
  Diff: Integer;
  Tmp: PBigNumber;

begin
  UsedA:= A.FUsed;
  UsedB:= B.FUsed;
  LimbsA:= @A.FLimbs;
  LimbsB:= @B.FLimbs;

  if A = B then begin  { A - B = 0 }
    tfFreeInstance(R); //if (R <> nil) then TtfRecord.Release(R);
    R:= @BigNumZero;
    Result:= TF_S_OK;
    Exit;
  end

  else { A <> B } begin
    if (UsedB = 1) and (LimbsB^ = 0) { B = 0 } then begin
      if R <> A then begin
        tfFreeInstance(R); //if R <> nil then TtfRecord.Release(R);
        R:= A;
        tfAddrefInstance(R); //TtfRecord.AddRef(R);
      end;
      Result:= TF_S_OK;
      Exit;
    end;

    if (UsedA = 1) and (LimbsA^ = 0) { A = 0, B <> 0 } then begin
//      Result:= TFL_E_INVALIDSUB;
      Result:= TF_E_INVALIDARG;
      Exit;
    end;

// Subtract lesser from greater
    if (UsedA = UsedB) then begin
      Diff:= arrCmp(@A.FLimbs, @B.FLimbs, UsedA);
      if Diff = 0 then begin
        tfFreeInstance(R); //if (R <> nil) then TtfRecord.Release(R);
        R:= @BigNumZero;
        Result:= TF_S_OK;
        Exit;
      end;
    end
    else
      Diff:= Ord(UsedA > UsedB) shl 1 - 1;

    if Diff > 0 { A > B } then begin
      Result:= AllocNumber(Tmp, UsedA + 1);
      if Result <> TF_S_OK then Exit;
      arrSub(LimbsA, LimbsB, @Tmp.FLimbs, UsedA, UsedB);
      Tmp.FUsed:= UsedA;
      Normalize(Tmp);
      tfFreeInstance(R); //if (R <> nil) then TtfRecord.Release(R);
      R:= Tmp;
    end
    else { A < B } begin
//      Result:= TFL_E_INVALIDSUB;
      Result:= TF_E_INVALIDARG;
      Exit;
    end;
  end;
  Result:= TF_S_OK;
end;

class function TBigNumber.MulNumbers(A, B: PBigNumber; var R: PBigNumber): TF_RESULT;
var
  UsedA, UsedB, Used: Cardinal;
  Tmp: PBigNumber;

begin
  if A.IsZero or B.IsZero then begin
    tfFreeInstance(R); //if (R <> nil) then TtfRecord.Release(R);
    R:= @BigNumZero;
    Result:= TF_S_OK;
  end
  else begin
    Tmp:= nil;

    UsedA:= A^.FUsed;
    UsedB:= B^.FUsed;
    Used:= UsedA + UsedB;

    Result:= AllocNumber(Tmp, Used);
    if Result <> TF_S_OK then Exit;

    if UsedA >= UsedB
      then
        arrMul(@A.FLimbs, @B.FLimbs, @Tmp.FLimbs, UsedA, UsedB)
      else
        arrMul(@B.FLimbs, @A.FLimbs, @Tmp.FLimbs, UsedB, UsedA);

    Tmp.FSign:= A.FSign xor B.FSign;
    Tmp.FUsed:= Used;
    Normalize(Tmp);
    tfFreeInstance(R); //if (R <> nil) then TtfRecord.Release(R);
    R:= Tmp;
  end;
end;

class function TBigNumber.SqrNumber(A: PBigNumber; var R: PBigNumber): TF_RESULT;
var
  UsedA, UsedB, Used: Cardinal;
  Tmp: PBigNumber;

begin
  if A.IsZero then begin
    tfFreeInstance(R); //if (R <> nil) then TtfRecord.Release(R);
    R:= @BigNumZero;
    Result:= TF_S_OK;
  end
  else begin
    Tmp:= nil;

    UsedA:= A^.FUsed;
    Used:= UsedA shl 1;

    Result:= AllocNumber(Tmp, Used);
    if Result <> TF_S_OK then Exit;

    arrSqr(@A.FLimbs, @Tmp.FLimbs, UsedA);

    Tmp.FUsed:= Used;
    Normalize(Tmp);
    tfFreeInstance(R); //if (R <> nil) then TtfRecord.Release(R);
    R:= Tmp;
  end;
end;

class function TBigNumber.MulNumbersU(A, B: PBigNumber; var R: PBigNumber): TF_RESULT;
var
  UsedA, UsedB, Used: Cardinal;
  Tmp: PBigNumber;

begin
  if A.IsZero or B.IsZero then begin
    tfFreeInstance(R); //if (R <> nil) then TtfRecord.Release(R);
    R:= @BigNumZero;
    Result:= TF_S_OK;
  end
  else begin
    Tmp:= nil;

    UsedA:= A^.FUsed;
    UsedB:= B^.FUsed;
    Used:= UsedA + UsedB;

    Result:= AllocNumber(Tmp, Used);
    if Result <> TF_S_OK then Exit;

    if UsedA >= UsedB
      then
        arrMul(@A.FLimbs, @B.FLimbs, @Tmp.FLimbs, UsedA, UsedB)
      else
        arrMul(@B.FLimbs, @A.FLimbs, @Tmp.FLimbs, UsedB, UsedA);

    Tmp.FUsed:= Used;
    Normalize(Tmp);
    tfFreeInstance(R); //if (R <> nil) then TtfRecord.Release(R);
    R:= Tmp;
  end;
end;

function SeniorBit(Value: TLimb): Integer;
{$IFDEF LIMB32_ASM86}
asm
        OR    EAX,EAX
        JZ    @@Done
        BSR   EAX,EAX
        INC   EAX
@@Done:
end;
{$ELSE}
begin
  Result:= 0;
  while Value <> 0 do begin
    Value:= Value shr 1;
    Inc(Result);
  end;
end;
{$ENDIF}

class function TBigNumber.DivModLimbU(A: PBigNumber; Limb: TLimb;
                          var Q: PBigNumber; var R: TLimb): TF_RESULT;
var
  Used: Cardinal;
  Tmp: PBigNumber;

begin
  Used:= A.FUsed;
  Result:= AllocNumber(Tmp, Used);
  if Result = TF_S_OK then begin
    R:= arrDivModLimb(@A.FLimbs, @Tmp.FLimbs, Used, Limb);
    if Tmp.FLimbs[Used - 1] = 0 then Dec(Used);
    Tmp.FUsed:= Used;
    tfFreeInstance(Q); //if (Q <> nil) then TtfRecord.Release(Q);
    Q:= Tmp;
  end;
end;

class function TBigNumber.DivRemNumbers(A, B: PBigNumber;
                                        var Q, R: PBigNumber): TF_RESULT;
var
  Cond: Boolean;
  Diff: Integer;
  Dividend, Divisor: PBigNumber;
  Quotient, Remainder: PBigNumber;
  Limb: TLimb;
  UsedA, UsedB, UsedD, UsedQ: Cardinal;
  Shift: Integer;

begin
  if B.IsZero then begin
//    Result:= TFL_E_ZERODIVIDE;
    Result:= TF_E_INVALIDARG;
    Exit;
  end;

// Cond = Abs(A) < Abs(B)
  Cond:= A.IsZero;

  if not Cond then begin
    UsedA:= A.FUsed;
    UsedB:= B.FUsed;
    Cond:= (UsedA < UsedB);
    if not Cond and (UsedA = UsedB) then begin
      Diff:= arrCmp(@A.FLimbs, @B.FLimbs, UsedB);

// if Abs(dividend A) = Abs(divisor B) then Q:= +/-1, R:= 0;
      if Diff = 0 then begin
        tfFreeInstance(R); //if (R <> nil) then TtfRecord.Release(R);
        R:= @BigNumZero;
        tfFreeInstance(Q); //if (Q <> nil) then TtfRecord.Release(Q);
        if A.FSign xor B.FSign < 0
          then Q:= @BigNumMinusOne
          else Q:= @BigNumOne;
        Result:= TF_S_OK;
        Exit;
      end
      else if Diff < 0 then Cond:= True;
    end;
  end;

// if dividend (A) < divisor (B) then Q:= 0, R:= A
  if Cond then begin
    tfFreeInstance(Q); //if (Q <> nil) then TtfRecord.Release(Q);
    Q:= @BigNumZero;
    if (R <> A) then begin
      tfFreeInstance(R); //if (R <> nil) then TtfRecord.Release(R);
      R:= A;
      tfAddrefInstance(R); //TtfRecord.AddRef(R);
    end;
    Result:= TF_S_OK;
    Exit;
  end;

  Result:= AllocNumber(Quotient, UsedA - UsedB + 1);
  if Result <> TF_S_OK then Exit;

  Result:= AllocNumber(Remainder, UsedB);
  if Result <> TF_S_OK then Exit;

// divisor (B) has only 1 limb
  if (UsedB = 1) then begin
    if (UsedA = 1) then begin
      Quotient.FLimbs[0]:= A.FLimbs[0] div B.FLimbs[0];
      Remainder.FLimbs[0]:= A.FLimbs[0] mod B.FLimbs[0];
    end
    else begin
      Remainder.FLimbs[0]:= arrDivModLimb(@A.FLimbs, @Quotient.FLimbs, UsedA, B.FLimbs[0]);
      if Quotient.FLimbs[UsedA - 1] = 0 then Dec(UsedA);
    end;

    Quotient.FUsed:= UsedA;
    Remainder.FUsed:= 1;

//  a mod b = a - b * (a div b)
//  ---------------------------
// -5 div 2 = -2, -5 mod 2 = -1
//  5 div -2 = -2, 5 mod -2 = 1
// -5 div -2 = 2, -5 mod -2 = -1

    if A.FSign xor B.FSign >= 0
//   or ((UsedA = 1) and (Q.FData[1] = 0)) never happens
//      since dividend > divisor here
      then
// dividend and divisor have the same sign
        Quotient.FSign:= 0
      else
        Quotient.FSign:= -1;

// remainder has the same sign as dividend if nonzero
    if (A.FSign >= 0) or (Remainder.FLimbs[0] = 0)
      then
        Remainder.FSign:= 0
      else
        Remainder.FSign:= -1;

    tfFreeInstance(Q); //if (Q <> nil) then TtfRecord.Release(Q);
    Q:= Quotient;

    tfFreeInstance(R); //if (R <> nil) then TtfRecord.Release(R);
    R:= Remainder;

    Exit;
  end;

// Now the real thing - big number division of length (used) > 1

// create normalized divisor by shifting the divisor B left
  Limb:= B.FLimbs[UsedB - 1];
  Shift:= TLimbInfo.BitSize - SeniorBit(Limb);

  Result:= AllocNumber(Divisor, UsedB);
  if Result <> TF_S_OK then Exit;

  Divisor.FUsed:= UsedB;
  arrShlShort(@B.FLimbs, @Divisor.FLimbs, UsedB, Shift);

// create normalized dividend (same shift as divisor)

  Result:= AllocNumber(Dividend, UsedA + 1);
  if Result <> TF_S_OK then Exit;
  UsedD:= arrShlShort(@A.FLimbs, @Dividend.FLimbs, UsedA, Shift);

// normalized dividend is 1 limb longer than non-normalized one (A);
//   if it is actually not longer, just zero senior limb
  if UsedD = UsedA then
    Dividend.FLimbs[UsedA]:= 0;
  Dividend.FUsed:= UsedA + 1;

  UsedQ:= UsedA - UsedB + 1;

// perform normalized division and shift the remaider right
  arrNormDivMod(@Dividend.FLimbs, @Divisor.FLimbs, @Quotient.FLimbs,
                UsedA + 1, UsedB);
  Remainder.FUsed:=
    arrShrShort(@Dividend.FLimbs, @Remainder.FLimbs, UsedB, Shift);

  tfReleaseInstance(Dividend); //TtfRecord.Release(Dividend);
  tfReleaseInstance(Divisor);  //TtfRecord.Release(Divisor);

  Quotient.FUsed:= UsedQ;
//  Remainder.FUsed:= UsedB;

  if A.FSign xor B.FSign >= 0
    then Quotient.FSign:= 0
    else Quotient.FSign:= -1;

// remainder has the same sign as dividend if nonzero
  if (A.FSign >= 0) or ((Remainder.FUsed = 0) and (Remainder.FLimbs[0] = 0))
    then Remainder.FSign:= 0
    else Remainder.FSign:= -1;

  Normalize(Quotient);
  Normalize(Remainder);

  tfFreeInstance(Q); //if (Q <> nil) then TtfRecord.Release(Q);
  Q:= Quotient;

  tfFreeInstance(R); //if (R <> nil) then TtfRecord.Release(R);
  R:= Remainder;
end;

class function TBigNumber.DivRemNumbersU(A, B: PBigNumber; var Q, R: PBigNumber): TF_RESULT;
var
  Cond: Boolean;
  Diff: Integer;
  Dividend, Divisor: PBigNumber;
  Quotient, Remainder: PBigNumber;
  Limb: TLimb;
  UsedA, UsedB, UsedD, UsedQ: Cardinal;
  Shift: Integer;

begin
  if B.IsZero then begin
//    Result:= TFL_E_ZERODIVIDE;
    Result:= TF_E_INVALIDARG;
    Exit;
  end;

// Cond = Abs(A) < Abs(B)
  Cond:= A.IsZero;

  if not Cond then begin
    UsedA:= A.FUsed;
    UsedB:= B.FUsed;
    Cond:= (UsedA < UsedB);
    if not Cond and (UsedA = UsedB) then begin
      Diff:= arrCmp(@A.FLimbs, @B.FLimbs, UsedB);

// if Abs(dividend A) = Abs(divisor B) then Q:= 1, R:= 0;
      if Diff = 0 then begin
        tfFreeInstance(R); //if (R <> nil) then TtfRecord.Release(R);
        R:= @BigNumZero;
        tfFreeInstance(Q); //if (Q <> nil) then TtfRecord.Release(Q);
        Q:= @BigNumOne;
        Result:= TF_S_OK;
        Exit;
      end
      else if Diff < 0 then Cond:= True;
    end;
  end;

// if dividend (A) < divisor (B) then Q:= 0, R:= A
  if Cond then begin
    tfFreeInstance(Q); //if (Q <> nil) then TtfRecord.Release(Q);
    Q:= @BigNumZero;
    if (R <> A) then begin
      tfFreeInstance(R); //if (R <> nil) then TtfRecord.Release(R);
      R:= A;
      tfAddrefInstance(R); //TtfRecord.AddRef(R);
    end;
    Result:= TF_S_OK;
    Exit;
  end;

// divisor (B) has only 1 limb
  if (UsedB = 1) then begin

    Result:= AllocNumber(Quotient, UsedA);
    if Result <> TF_S_OK then Exit;

    Result:= AllocNumber(Remainder, 1);
    if Result <> TF_S_OK then begin
      tfReleaseInstance(Quotient); //TtfRecord.Release(Quotient);
      Exit;
    end;

    if (UsedA = 1) then begin
      Quotient.FLimbs[0]:= A.FLimbs[0] div B.FLimbs[0];
      Remainder.FLimbs[0]:= A.FLimbs[0] mod B.FLimbs[0];
    end
    else begin
      Remainder.FLimbs[0]:= arrDivModLimb(@A.FLimbs, @Quotient.FLimbs, UsedA, B.FLimbs[0]);
      if Quotient.FLimbs[UsedA - 1] = 0 then Dec(UsedA);
    end;

    Quotient.FUsed:= UsedA;
    Remainder.FUsed:= 1;

    tfFreeInstance(Q); //if (Q <> nil) then TtfRecord.Release(Q);
    Q:= Quotient;

    tfFreeInstance(R); //if (R <> nil) then TtfRecord.Release(R);
    R:= Remainder;

    Exit;
  end;

// Now the real thing - big number division of length (used) > 1

  Result:= AllocNumber(Quotient, UsedA - UsedB + 1);
  if Result <> TF_S_OK then Exit;

  Result:= AllocNumber(Remainder, UsedB);
  if Result <> TF_S_OK then begin
    tfReleaseInstance(Quotient); //TtfRecord.Release(Quotient);
    Exit;
  end;

// create normalized divisor by shifting the divisor B left
  Limb:= B.FLimbs[UsedB - 1];
  Shift:= TLimbInfo.BitSize - SeniorBit(Limb);

  Result:= AllocNumber(Divisor, UsedB);
  if Result <> TF_S_OK then begin
    tfReleaseInstance(Remainder); //TtfRecord.Release(Remainder);
    tfReleaseInstance(Quotient); //TtfRecord.Release(Quotient);
    Exit;
  end;

  Divisor.FUsed:= UsedB;
  arrShlShort(@B.FLimbs, @Divisor.FLimbs, UsedB, Shift);

// create normalized dividend (same shift as divisor)

  Result:= AllocNumber(Dividend, UsedA + 1);
  if Result <> TF_S_OK then begin
    tfReleaseInstance(Divisor);   //TtfRecord.Release(Divisor);
    tfReleaseInstance(Remainder); //TtfRecord.Release(Remainder);
    tfReleaseInstance(Quotient);  //TtfRecord.Release(Quotient);
    Exit;
  end;

  UsedD:= arrShlShort(@A.FLimbs, @Dividend.FLimbs, UsedA, Shift);

// normalized dividend is 1 limb longer than non-normalized one (A);
//   if it is actually not longer, just zero senior limb
  if UsedD = UsedA then
    Dividend.FLimbs[UsedA]:= 0;
  Dividend.FUsed:= UsedA + 1;

  UsedQ:= UsedA - UsedB + 1;

// perform normalized division and shift the remainder right
  arrNormDivMod(@Dividend.FLimbs, @Divisor.FLimbs, @Quotient.FLimbs,
                UsedA + 1, UsedB);
  Remainder.FUsed:=
    arrShrShort(@Dividend.FLimbs, @Remainder.FLimbs, UsedB, Shift);

  tfReleaseInstance(Dividend); //TtfRecord.Release(Dividend);
  tfReleaseInstance(Divisor);  //TtfRecord.Release(Divisor);

  Quotient.FUsed:= UsedQ;
//  Remainder.FUsed:= UsedB;

  Normalize(Quotient);
  Normalize(Remainder);

  tfFreeInstance(Q); //if (Q <> nil) then TtfRecord.Release(Q);
  Q:= Quotient;

  tfFreeInstance(R); //if (R <> nil) then TtfRecord.Release(R);
  R:= Remainder;
end;

class function TBigNumber.GCD(A, B: PBigNumber; var G: PBigNumber): TF_RESULT;
var
  TmpA, TmpB: PBigNumber;
  TmpQ, TmpR: PBigNumber;
  Diff: Integer;

begin
{
  if A.IsZero and B.IsZero then begin
    if (G <> nil) then TtfRecord.Release(G);
    G:= @BigNumZero;
    Result:= TF_S_OK;
    Exit;
  end;
}

  Diff:= CompareNumbersU(A, B);
  if Diff = 0 then begin
    if A.IsZero then begin
      Result:= TF_E_INVALIDARG;
      Exit;
    end;

    tfFreeInstance(G); //if (G <> nil) then TtfRecord.Release(G);
    G:= A;
    tfAddrefInstance(A); //TtfRecord.Addref(A);
    Result:= TF_S_OK;
    Exit;
  end;

  if Diff > 0 then begin
    TmpA:= A;
    TmpB:= B;
  end
  else begin
    TmpA:= B;
    TmpB:= A;
  end;

  tfAddrefInstance(TmpA); //TtfRecord.Addref(TmpA);

  if TmpB.IsZero then begin
    tfFreeInstance(G); //if (G <> nil) then TtfRecord.Release(G);
    G:= TmpA;
    Result:= TF_S_OK;
    Exit;
  end;

  tfAddrefInstance(TmpB); //TtfRecord.Addref(TmpB);
  TmpQ:= nil;
  TmpR:= nil;

  repeat
// Q:= A div B, R:= A mod B;
    Result:= DivRemNumbersU(TmpA, TmpB, TmpQ, TmpR);
    tfReleaseInstance(TmpA); //TtfRecord.Release(TmpA);

    if Result <> TF_S_OK then begin
      tfReleaseInstance(TmpB); //TtfRecord.Release(TmpB);
      tfFreeInstance(TmpQ); //if TmpQ <> nil then TtfRecord.Release(TmpQ);
      tfFreeInstance(TmpR); //if TmpR <> nil then TtfRecord.Release(TmpR);
      Exit;
    end;

    tfReleaseInstance(TmpQ); //TtfRecord.Release(TmpQ);
    TmpQ:= nil;

    if TmpR.IsZero then begin
      tfReleaseInstance(TmpR); //TtfRecord.Release(TmpR);
      tfFreeInstance(G); //if (G <> nil) then TtfRecord.Release(G);
      G:= TmpB;
      Exit;
    end;

    TmpA:= TmpB;
    TmpB:= TmpR;
    TmpR:= nil;
  until False;
end;

class function TBigNumber.LCM(A, B: PBigNumber; var G: PBigNumber): TF_RESULT;
var
  Tmp1, Tmp2: PBigNumber;

begin
  if A.IsZero then begin
    if B.IsZero then begin
      Result:= TF_E_INVALIDARG;
    end
    else begin
      tfAddrefInstance(B); //TtfRecord.AddRef(B);
      tfFreeInstance(G); //if (G <> nil) then TtfRecord.Release(G);
      G:= B;
      Result:= TF_S_OK;
    end;
    Exit;
  end;
  if B.IsZero then begin
    tfAddrefInstance(A); //TtfRecord.AddRef(A);
    tfFreeInstance(G); //if (G <> nil) then TtfRecord.Release(G);
    G:= A;
    Result:= TF_S_OK;
  end;

  Tmp1:= nil;
  Result:= GCD(A, B, Tmp1);
  if Result <> TF_S_OK then Exit;

  Tmp2:= nil;
  Result:= DivRemNumbersU(A, Tmp1, Tmp1, Tmp2);
  if Result <> TF_S_OK then begin
    tfReleaseInstance(Tmp1); //TtfRecord.Release(Tmp1);
    Exit;
  end;

  tfReleaseInstance(Tmp2); //TtfRecord.Release(Tmp2);
  Result:= MulNumbersU(B, Tmp1, Tmp1);
  if Result <> TF_S_OK then begin
    tfReleaseInstance(Tmp1); //TtfRecord.Release(Tmp1);
    Exit;
  end;

  tfFreeInstance(G); //if (G <> nil) then TtfRecord.Release(G);
  G:= Tmp1;
end;

{
class function TBigNumber.GCD(A, B: PBigNumber; var G: PBigNumber): TF_RESULT;
var
  TmpQ, TmpR: PBigNumber;

procedure CleanUp;
begin
  TtfRecord.Release(A);
  TtfRecord.Release(B);
  if TmpQ <> nil then TtfRecord.Release(TmpQ);
  if TmpR <> nil then TtfRecord.Release(TmpR);
end;

begin
// interface refs' initialization
  TtfRecord.Addref(A);
  TtfRecord.Addref(B);

  TmpQ:= nil;
  TmpR:= nil;

  while not A.IsZero do begin

// Q:= B div A, R: B mod A;
    Result:= DivRemNumbers(B, A, TmpQ, TmpR);
    if Result <> TF_S_OK then begin
      CleanUp;
      Exit;
    end;
    TtfRecord.Release(A);
    A:= B;
    B:= TmpR;
    TmpR:= nil;
    TtfRecord.Release(TmpQ);
    TmpQ:= nil;
  end;

  if (G <> nil) then TtfRecord.Release(G);
  G:= B;
  TtfRecord.Addref(G);

  CleanUp;
  Result:= TF_S_OK;
end;
}
class function TBigNumber.EGCD(A, B: PBigNumber; var G, X, Y: PBigNumber): TF_RESULT;
var
  TmpX, TmpY, TmpU, TmpV, TmpQ, TmpR, TmpM, TmpN: PBigNumber;

procedure CleanUp;
begin
  tfReleaseInstance(A); //TtfRecord.Release(A);
  tfReleaseInstance(B); //TtfRecord.Release(B);
  tfFreeInstance(TmpX); //if TmpX <> nil then TtfRecord.Release(TmpX);
  tfFreeInstance(TmpY); //if TmpY <> nil then TtfRecord.Release(TmpY);
  tfFreeInstance(TmpU); //if TmpU <> nil then TtfRecord.Release(TmpU);
  tfFreeInstance(TmpV); //if TmpV <> nil then TtfRecord.Release(TmpV);
  tfFreeInstance(TmpQ); //if TmpQ <> nil then TtfRecord.Release(TmpQ);
  tfFreeInstance(TmpR); //if TmpR <> nil then TtfRecord.Release(TmpR);
  tfFreeInstance(TmpM); //if TmpM <> nil then TtfRecord.Release(TmpM);
  tfFreeInstance(TmpN); //if TmpN <> nil then TtfRecord.Release(TmpN);
end;

begin
// interface refs' initialization
  tfAddrefInstance(A); //TtfRecord.Addref(A);
  tfAddrefInstance(B); //TtfRecord.Addref(B);

  TmpX:= nil;
  TmpY:= nil;
  TmpU:= nil;
  TmpV:= nil;
  TmpQ:= nil;
  TmpR:= nil;
  TmpM:= nil;
  TmpN:= nil;

// TmpX:= 0
  Result:= TBigNumber.AllocNumber(TmpX, 1);
  if Result <> TF_S_OK then begin
    CleanUp;
    Exit;
  end;

// TmpY:= 1
  Result:= TBigNumber.AllocNumber(TmpY, 1);
  if Result <> TF_S_OK then begin
    CleanUp;
    Exit;
  end;
  TmpY.FLimbs[0]:= 1;

// TmpU:= 1
  Result:= TBigNumber.AllocNumber(TmpU, 1);
  if Result <> TF_S_OK then begin
    CleanUp;
    Exit;
  end;
  TmpU.FLimbs[0]:= 1;

// TmpV:= 0
  Result:= TBigNumber.AllocNumber(TmpV, 1);
  if Result <> TF_S_OK then begin
    CleanUp;
    Exit;
  end;

  while not A.IsZero do begin

// Q:= B div A, R: B mod A;
    Result:= DivRemNumbers(B, A, TmpQ, TmpR);
    if Result <> TF_S_OK then begin
      CleanUp;
      Exit;
    end;

// M:= X - U * Q
    Result:= MulNumbers(TmpU, TmpQ, TmpM);
    if Result <> TF_S_OK then begin
      CleanUp;
      Exit;
    end;
    Result:= SubNumbers(TmpX, TmpM, TmpM);
    if Result <> TF_S_OK then begin
      CleanUp;
      Exit;
    end;

// N:= Y - V * Q
    Result:= MulNumbers(TmpV, TmpQ, TmpN);
    if Result <> TF_S_OK then begin
      CleanUp;
      Exit;
    end;
    Result:= SubNumbers(TmpY, TmpN, TmpN);
    if Result <> TF_S_OK then begin
      CleanUp;
      Exit;
    end;

    tfReleaseInstance(B); //TtfRecord.Release(B);
    B:= A;
//    TmpB.AddRef;
//    TmpA.TtfRecord.Release(;
    A:= TmpR;
    TmpR:= nil;

    tfReleaseInstance(TmpX); //TtfRecord.Release(TmpX);
    TmpX:= TmpU;

    tfReleaseInstance(TmpY); //TtfRecord.Release(TmpY);
    TmpY:= TmpV;

    TmpU:= TmpM;
    TmpV:= TmpN;

    TmpM:= nil;
    TmpN:= nil;
  end;

  tfFreeInstance(G); //if (G <> nil) then TtfRecord.Release(G);
  G:= B;
  tfAddrefInstance(G); //TtfRecord.Addref(G);

  tfFreeInstance(X); //if (X <> nil) then TtfRecord.Release(X);
  X:= TmpX;
  tfAddrefInstance(X); //TtfRecord.Addref(X);

  tfFreeInstance(Y); //if (Y <> nil) then TtfRecord.Release(Y);
  Y:= TmpY;
  tfAddrefInstance(Y); //TtfRecord.Addref(Y);

  CleanUp;
  Result:= TF_S_OK;
end;

class function TBigNumber.ModInverse(A, M: PBigNumber; var R: PBigNumber): TF_RESULT;
var
  TmpG, TmpX, TmpY, TmpQ, TmpR: PBigNumber;

begin
  TmpG:= nil;
  TmpX:= nil;
  TmpY:= nil;
  Result:= EGCD(A, M, TmpG, TmpX, TmpY);
  if Result <> TF_S_OK then Exit;

  tfReleaseInstance(TmpY); //TtfRecord.Release(TmpY);
// if GCD <> 1
  if (TmpG.FUsed <> 1) or (TmpG.FLimbs[0] <> 1) then begin
    tfReleaseInstance(TmpG); //TtfRecord.Release(TmpG);
    tfReleaseInstance(TmpX); //TtfRecord.Release(TmpX);
    Result:= TF_E_INVALIDARG;
    Exit;
  end;

  tfReleaseInstance(TmpG); //TtfRecord.Release(TmpG);

  Result:= TBigNumber.AddNumbers(TmpX, M, TmpX);
  if Result <> TF_S_OK then begin
    tfReleaseInstance(TmpX); //TtfRecord.Release(TmpX);
    Exit;
  end;

  TmpQ:= nil;
  TmpR:= nil;

  Result:= TBigNumber.DivRemNumbers(TmpX, M, TmpQ, TmpR);
  tfReleaseInstance(TmpX); //TtfRecord.Release(TmpX);

  if Result <> TF_S_OK then begin
    Exit;
  end;

  tfReleaseInstance(TmpQ); //TtfRecord.Release(TmpQ);
//  tfFreeInstance(TmpR);    //if (R <> nil) then TtfRecord.Release(TmpR);
  tfFreeInstance(R);    //if (R <> nil) then TtfRecord.Release(R);
  R:= TmpR;
end;

class function TBigNumber.AbsNumber(A: PBigNumber; var R: PBigNumber): TF_RESULT;
var
  Tmp: PBigNumber;

begin
  if A.FSign >= 0 then begin
    if R <> A then begin
      tfFreeInstance(R); //if R <> nil then TtfRecord.Release(R);
      R:= A;
      tfAddrefInstance(R); //TtfRecord.AddRef(R);
    end;
    Result:= TF_S_OK;
  end
  else begin
    Result:= AllocNumber(Tmp, A.FUsed);
    if Result = TF_S_OK then begin
      Move(A.FUsed, Tmp.FUsed, A.FUsed * SizeOf(TLimb) + FUsedSize);
      tfFreeInstance(R); //if R <> nil then TtfRecord.Release(R);
      R:= Tmp;
    end;
  end;
end;

class function TBigNumber.CloneNumber(var A: PBigNumber; B: PBigNumber;
                                       ASign: Integer = 0): TF_RESULT;
var
  Used: Cardinal;
  Tmp: PBigNumber;

begin
  Used:= B.FUsed;
  Result:= AllocNumber(Tmp, Used);
  if Result = TF_S_OK then begin
    Move(B.FUsed, Tmp.FUsed, FUsedSize + Used * SizeOf(TLimb));
    if ASign = 0 then
      Tmp.FSign:= B.FSign
// to avoid negative zero
    else if (ASign < 0) and ((Used > 1) or (Tmp.FLimbs[0] <> 0)) then
      Tmp.FSign:= -1
    else Tmp.FSign:= 0;
    tfFreeInstance(A); //if A <> nil then TtfRecord.Release(A);
    A:= Tmp;
  end;
end;

class function TBigNumber.DuplicateNumber(A: PBigNumber; var R: PBigNumber): TF_RESULT;
var
  Tmp: PBigNumber;

begin
  if A.IsZero then begin
    tfFreeInstance(R); //if R <> nil then TtfRecord.Release(R);
    R:= @BigNumZero;
    Result:= TF_S_OK;
  end
  else begin
    Result:= AllocNumber(Tmp, A.FUsed);
    if Result = TF_S_OK then begin
// Copy FSign
      Tmp.FSign:= A.FSign;
// Copy FUsed and FData fields:
      Move(A.FUsed, Tmp.FUsed, A.FUsed * SizeOf(TLimb) + FUsedSize);
      tfFreeInstance(R); //if R <> nil then TtfRecord.Release(R);
      R:= Tmp;
    end;
  end;
end;

class function TBigNumber.NegateNumber(A: PBigNumber; var R: PBigNumber): TF_RESULT;
var
  Tmp: PBigNumber;

begin
  if A.IsZero then begin
    tfFreeInstance(R); //if R <> nil then TtfRecord.Release(R);
    R:= @BigNumZero;
    Result:= TF_S_OK;
  end
  else begin
    Result:= AllocNumber(Tmp, A.FUsed);
    if Result = TF_S_OK then begin
// Copy FUsed and FData fields:
      Move(A.FUsed, Tmp.FUsed, A.FUsed * SizeOf(TLimb) + FUsedSize);
// A <> 0 here
      if A.FSign >= 0 then Tmp.FSign:= -1;
//      else Tmp.FSign:= 0;
      tfFreeInstance(R); //if R <> nil then TtfRecord.Release(R);
      R:= Tmp;
    end;
  end;
end;

class function TBigNumber.AssignNumber(A: PBigNumber; var R: PBigNumber): TF_RESULT;
begin
  tfFreeInstance(R); //if R <> nil then TtfRecord.Release(R);
  R:= A;
  tfAddrefInstance(A); //if A <> nil then TtfRecord.AddRef(A);
  Result:= TF_S_OK;
end;

class procedure TBigNumber.Burn(A: PBigNumber);
begin
// todo:
end;

class function TBigNumber.AddIntLimb(A: PBigNumber; Limb: TIntLimb;
                                     var R: PBigNumber): TF_RESULT;
var
  UsedA: Cardinal;
  AbsLimb: TLimb;
  Tmp: PBigNumber;

begin
  UsedA:= A.FUsed;
  AbsLimb:= Abs(Limb);
  Result:= AllocNumber(Tmp, UsedA + 1);
  if Result = TF_S_OK then begin
    if A.FSign xor Integer(Limb) >= 0 then begin
      if arrAddLimb(@A.FLimbs, AbsLimb, @Tmp.FLimbs, UsedA)
        then Tmp.FUsed:= UsedA + 1
        else Tmp.FUsed:= UsedA;
      Tmp.FSign:= A.FSign;
    end
    else begin
      if A.FUsed = 1 then begin
// Assert(Tmp.FUsed = 1)
        if A.FLimbs[0] < AbsLimb then begin
          Tmp.FLimbs[0]:= AbsLimb - A.FLimbs[0];
          Tmp.FSign:= not A.FSign;
        end
        else begin
          Tmp.FLimbs[0]:= A.FLimbs[0] - AbsLimb;
          if Tmp.FLimbs[0] <> 0
            then Tmp.FSign:= A.FSign;
        end;
      end
      else begin { UsedA > 1 }
        arrSubLimb(@A.FLimbs, AbsLimb, @Tmp.FLimbs, UsedA);
        if Tmp.FLimbs[UsedA - 1] = 0
          then Tmp.FUsed:= UsedA - 1
          else Tmp.FUsed:= UsedA;
        Tmp.FSign:= A.FSign;
      end;
    end;
    tfFreeInstance(R); //if (R <> nil) then TtfRecord.Release(R);
    R:= Tmp;
  end;
end;
{
class function TBigNumber.AddIntLimbU(A: PBigNumber; Limb: TIntLimb;
                                      var R: PBigNumber): HResult;
var
  UsedA: Cardinal;
  AbsLimb: TLimb;
  Tmp: PBigNumber;

begin
  UsedA:= A.FUsed;
  AbsLimb:= Abs(Limb);
  if Limb >= 0 then begin
    Result:= AllocNumber(Tmp, UsedA + 1);
    if Result = TFL_S_OK then begin
      if arrAddLimb(@A.FLimbs, AbsLimb, @Tmp.FLimbs, UsedA)
        then Tmp.FUsed:= UsedA + 1
        else Tmp.FUsed:= UsedA;
    end;
  end
  else if (A.FUsed = 1) then begin
    if A.FLimbs[0] >= AbsLimb then begin
      Result:= AllocNumber(Tmp, 1);
      if Result = TFL_S_OK then begin
        Tmp.FLimbs[0]:= A.FLimbs[0] - AbsLimb;
//        Tmp.FUsed:= 1;
      end
    end
    else
      Result:= TFL_E_INVALIDSUB;
  end
  else begin
    Result:= AllocNumber(Tmp, UsedA);
    if Result = TFL_S_OK then begin
      arrSubLimb(@A.FLimbs, AbsLimb, @Tmp.FLimbs, UsedA);
      if Tmp.FLimbs[UsedA - 1] = 0
        then Tmp.FUsed:= UsedA - 1
        else Tmp.FUsed:= UsedA;
    end;
  end;
  if Result = TFL_S_OK then begin
    if (R <> nil) then TtfRecord.Release((R);
    R:= Tmp;
  end;
end;
}

class function TBigNumber.AddLimb(A: PBigNumber; Limb: TLimb;
                                  var R: PBigNumber): TF_RESULT;
var
  UsedA: Cardinal;
  Tmp: PBigNumber;

begin
  UsedA:= A.FUsed;
  Result:= AllocNumber(Tmp, UsedA + 1);
  if Result = TF_S_OK then begin
    if A.FSign >= 0 then begin
      if arrAddLimb(@A.FLimbs, Limb, @Tmp.FLimbs, UsedA)
        then Tmp.FUsed:= UsedA + 1
        else Tmp.FUsed:= UsedA;
    end
    else begin                               // A.FSign < 0
      if UsedA = 1 then begin
        if A.FLimbs[0] <= Limb then begin
          Tmp.FLimbs[0]:= Limb - A.FLimbs[0];
        end
        else begin
          Tmp.FLimbs[0]:= A.FLimbs[0] - Limb;
          Tmp.FSign:= -1;
        end;
      end
      else begin { UsedA > 1 }
        arrSubLimb(@A.FLimbs, Limb, @Tmp.FLimbs, UsedA);
        if Tmp.FLimbs[UsedA - 1] = 0
          then Tmp.FUsed:= UsedA - 1
          else Tmp.FUsed:= UsedA;
        Tmp.FSign:= -1;
      end;
    end;
    tfFreeInstance(R); //if (R <> nil) then TtfRecord.Release(R);
    R:= Tmp;
  end;
end;

class function TBigNumber.NextNumber(A: PBigNumber; var R: PBigNumber): TF_RESULT;
var
  Tmp: PBigNumber;
  UsedA: Cardinal;

begin
  UsedA:= A.FUsed;
  Result:= AllocNumber(Tmp, UsedA + 1);
  if Result = TF_S_OK then begin
    if A.FSign >= 0 then begin
      if arrInc(@A.FLimbs, @Tmp.FLimbs, A.FUsed)
        then Tmp.FUsed:= UsedA + 1
        else Tmp.FUsed:= UsedA;
    end
    else begin            // A < 0
      if UsedA = 1 then begin
        if A.FLimbs[0] = 1 then begin
          Tmp.FLimbs[0]:= 0;
        end
        else begin
          Tmp.FLimbs[0]:= A.FLimbs[0] - 1;
          Tmp.FSign:= -1;
        end;
      end
      else begin { UsedA > 1 }
        arrDec(@A.FLimbs, @Tmp.FLimbs, UsedA);
        if Tmp.FLimbs[UsedA - 1] = 0
          then Tmp.FUsed:= UsedA - 1
          else Tmp.FUsed:= UsedA;
        Tmp.FSign:= -1;
      end;
    end;
    tfFreeInstance(R); //if R <> nil then TtfRecord.Release(R);
    R:= Tmp;
  end;
end;

class function TBigNumber.NextNumberU(A: PBigNumber;
  var R: PBigNumber): TF_RESULT;
var
  Tmp: PBigNumber;
  UsedA: Cardinal;

begin
  UsedA:= A.FUsed;
  Result:= AllocNumber(Tmp, UsedA + 1);
  if Result = TF_S_OK then begin
    if arrInc(@A.FLimbs, @Tmp.FLimbs, A.FUsed)
      then Tmp.FUsed:= UsedA + 1
      else Tmp.FUsed:= UsedA;
    tfFreeInstance(R); //if R <> nil then TtfRecord.Release(R);
    R:= Tmp;
  end;
end;

(*
class function TBigNumber.AddDblLimb(A: PBigNumber; B: TDblLimb;
                                     var R: PBigNumber): HResult;
var
  UsedA: Integer;
  Tmp: PBigNumber;

begin
  UsedA:= A.FUsed;
  Result:= AllocNumber(Tmp, UsedA + 2);
  if Result = TFL_S_OK then begin
    if A.FSign >= 0 then begin
      if arrAddLimb(@A.FLimbs, Limb, @Tmp.FLimbs, UsedA)
        then Tmp.FUsed:= UsedA + 1
        else Tmp.FUsed:= UsedA;
    end
    else begin                               // A.FSign < 0
      if UsedA = 1 then begin
        if A.FLimbs[0] <= Limb then begin
          Tmp.FLimbs[0]:= Limb - A.FLimbs[0];
        end
        else begin
          Tmp.FLimbs[0]:= A.FLimbs[0] - Limb;
          Tmp.FSign:= -1;
        end;
      end
      else begin { UsedA > 1 }
        arrSubLimb(@A.FLimbs, Limb, @Tmp.FLimbs, UsedA);
        if Tmp.FLimbs[UsedA - 1] = 0
          then Tmp.FUsed:= UsedA - 1
          else Tmp.FUsed:= UsedA;
        Tmp.FSign:= -1;
      end;
    end;
    if (R <> nil) then TtfRecord.Release((R);
    R:= Tmp;
  end;
end;
*)
class function TBigNumber.AddLimbU(A: PBigNumber; Limb: TLimb;
                                   var R: PBigNumber): TF_RESULT;
var
  UsedA: Cardinal;
  Tmp: PBigNumber;

begin
  UsedA:= A.FUsed;
  Result:= AllocNumber(Tmp, UsedA + 1);
  if Result = TF_S_OK then begin
    if arrAddLimb(@A.FLimbs, Limb, @Tmp.FLimbs, UsedA)
      then Tmp.FUsed:= UsedA + 1
      else Tmp.FUsed:= UsedA;

    tfFreeInstance(R); //if (R <> nil) then TtfRecord.Release(R);
    R:= Tmp;
  end;
end;

function TBigNumber.SelfCopy(Inst: PBigNumber): TF_RESULT;
begin
  if FCapacity <= Inst.FUsed then
    Result:= TF_E_NOMEMORY
  else begin
    Move(Inst.FSign, FSign, Inst.FUsed * SizeOf(TLimb) + 2 * FUsedSize);
    Result:= TF_S_OK;
  end;
end;

function TBigNumber.SelfDivModLimbU(Value: TLimb;
                                    var Remainder: TLimb): TF_RESULT;
var
  Used: Cardinal;

begin
  Used:= FUsed;
  Remainder:= arrSelfDivModLimb(@FLimbs, Used, Value);
  if (Used > 1) and (FLimbs[Used - 1] = 0) then
    FUsed:= Used - 1;
  Result:= TF_S_OK;
end;

function TBigNumber.SelfMulLimb(Value: TLimb): TF_RESULT;
begin
  if Value = 0 then begin
    FUsed:= 1;
    FSign:= 0;
    FLimbs[0]:= 0;
    Result:= TF_S_OK;
  end
  else if FCapacity <= FUsed
    then Result:= TF_E_NOMEMORY
  else begin
    if arrSelfMulLimb(@FLimbs, Value, FUsed) then Inc(FUsed);
    Result:= TF_S_OK;
  end;
end;

function TBigNumber.SelfAddLimb(Value: TLimb): TF_RESULT;
var
  Used: Integer;
//  Minus: Boolean;

begin
  Used:= FUsed;
  if FCapacity <= Used then
    Result:= TF_E_NOMEMORY
  else begin
    if (FSign >= 0) then begin
      if arrSelfAddLimb(@FLimbs, Value, Used) then
        FUsed:= Used + 1;
    end
    else if (Used > 1) then begin
  // sign = minus, used > 1
      arrSelfSubLimb(@FLimbs, Value, Used);
      if FLimbs[Used - 1] = 0 then begin
        FUsed:= Used - 1;
      end;
    end
    else begin
  // sign = minus, used = 1
      if FLimbs[0] > Value then begin
        Dec(FLimbs[0], Value);
      end
      else begin
        FLimbs[0]:= Value - FLimbs[0];
        FSign:= 0;     // sign changed to plus
      end;
    end;
    Result:= TF_S_OK;
  end;
end;

function TBigNumber.SelfAddLimbU(Value: TLimb): TF_RESULT;
var
  Used: Integer;

begin
  Used:= FUsed;
  if FCapacity <= Used then
    Result:= TF_E_NOMEMORY
  else begin
    if arrSelfAddLimb(@FLimbs, Value, Used) then
      FUsed:= Used + 1;
    Result:= TF_S_OK;
  end;
end;
(*
function TBigNumber.SelfAddNumber(B: PBigNumber): TF_RESULT;
var
  UsedA, UsedB: Cardinal;
  LimbsA, LimbsB: PLimb;
  Diff: Integer;
  Tmp: PBigNumber;

begin
  UsedA:= FUsed;
  UsedB:= B.FUsed;
  LimbsA:= @FLimbs;
  LimbsB:= @B.FLimbs;

{
  if @Self = B then begin
    Result:= AllocNumber(Tmp, UsedA + 1);
    if Result <> TF_S_OK then Exit;
    Tmp.FUsed:= arrShlOne(@A.FLimbs, @Tmp.FLimbs, UsedA);
    Tmp.FSign:= A.FSign;
    if (R <> nil) then TtfRecord.Release(R);
    R:= Tmp;
  end
}

  else { A <> B } begin
    if (UsedB = 1) and (LimbsB^ = 0) { B = 0 } then begin
      if R <> A then begin
        if R <> nil then TtfRecord.Release(R);
        R:= A;
        TtfRecord.AddRef(R);
      end;
      Result:= TF_S_OK;
      Exit;
    end;

    if (UsedA = 1) and (LimbsA^ = 0) { A = 0 } then begin
      if R <> B then begin
        if R <> nil then TtfRecord.Release(R);
        R:= B;
        TtfRecord.AddRef(R);
      end;
      Result:= TF_S_OK;
      Exit;
    end;

    if A.FSign xor B.FSign >= 0 then begin
// Values have the same sign - ADD lesser to greater

      if UsedA >= UsedB then begin
        Result:= AllocNumber(Tmp, UsedA + 1);
        if Result <> TF_S_OK then Exit;
        if arrAdd(LimbsA, LimbsB, @Tmp.FLimbs, UsedA, UsedB)
          then
            Tmp.FUsed:= UsedA + 1
          else
            Tmp.FUsed:= UsedA;
        Tmp.FSign:= A.FSign;
      end
      else begin
        Result:= AllocNumber(Tmp, UsedB + 1);
        if Result <> TF_S_OK then Exit;
        if arrAdd(LimbsB, LimbsA, @Tmp.FLimbs, UsedB, UsedA)
          then
            Tmp.FUsed:= UsedB + 1
          else
            Tmp.FUsed:= UsedB;
        Tmp.FSign:= B.FSign;
      end;

      if (R <> nil) then TtfRecord.Release(R);
      R:= Tmp;

    end
    else begin
// Values have opposite signs - SUB lesser from greater

      if (UsedA = UsedB) then begin
        Diff:= arrCmp(LimbsA, LimbsB, UsedA);
        if Diff = 0 then begin
          if (R <> nil) then TtfRecord.Release(R);
          R:= @BigNumZero;
          Result:= TF_S_OK;
          Exit;
        end;
      end
      else
        Diff:= Ord(UsedA > UsedB) shl 1 - 1;

      if Diff > 0 then begin
        Result:= AllocNumber(Tmp, UsedA + 1);
        if Result <> TF_S_OK then Exit;
        arrSub(LimbsA, LimbsB, @Tmp.FLimbs, UsedA, UsedB);
        Tmp.FUsed:= UsedA;
        Tmp.FSign:= A.FSign;
        Normalize(Tmp);

        if (R <> nil) then TtfRecord.Release(R);
        R:= Tmp;
      end
      else begin
        Result:= AllocNumber(Tmp, UsedB + 1);
        if Result <> TF_S_OK then Exit;
        arrSub(LimbsB, LimbsA, @Tmp.FLimbs, UsedB, UsedA);

        Tmp.FUsed:= UsedB;
        Tmp.FSign:= B.FSign;
        Normalize(Tmp);

        if (R <> nil) then TtfRecord.Release(R);
        R:= Tmp;
      end;
    end;
  end;
  Result:= TF_S_OK;
end;
*)

function TBigNumber.SelfSubLimbU(Value: TLimb): TF_RESULT;
var
  Used: Cardinal;

begin
  Used:= FUsed;
  if (Used > 1) then begin
    arrSelfSubLimb(@FLimbs, Value, Used);
    if FLimbs[Used - 1] = 0 then begin
      FUsed:= Used - 1;
    end;
    Result:= TF_S_OK;
  end
  else begin
    if FLimbs[0] >= Value then begin
      Dec(FLimbs[0], Value);
      Result:= TF_S_OK;
    end
    else
//      Result:= TFL_E_INVALIDSUB;
      Result:= TF_E_INVALIDARG;
  end;
end;

function TBigNumber.SelfSubLimb(Value: TLimb): TF_RESULT;
var
  Used: Integer;

begin
  Used:= FUsed;

  if FSign < 0 then begin
    if FCapacity <= Used then
      Result:= TF_E_NOMEMORY
    else begin
      if arrSelfAddLimb(@FLimbs, Value, Used) then
        FUsed:= Used + 1;
      Result:= TF_S_OK;
    end;
  end
  else begin
    if (Used > 1) then begin
// sign = plus, used > 1
      arrSelfSubLimb(@FLimbs, Value, Used);
      if FLimbs[Used - 1] = 0 then begin
        FUsed:= Used - 1;
      end;
    end
    else begin
// sign = plus, used = 1
      if FLimbs[0] >= Value then begin
        Dec(FLimbs[0], Value);
      end
      else begin
        FLimbs[0]:= Value - FLimbs[0];
        FSign:= -1;
      end;
    end;
    Result:= TF_S_OK;
  end;
end;

class function TBigNumber.SubLimb(A: PBigNumber; Limb: TLimb;
                                  var R: PBigNumber): TF_RESULT;
var
  UsedA: Cardinal;
  Tmp: PBigNumber;

begin
  UsedA:= A.FUsed;
  Result:= AllocNumber(Tmp, UsedA + 1);
  if Result = TF_S_OK then begin
    if (A.FSign < 0) then begin
      if arrAddLimb(@A.FLimbs, Limb, @Tmp.FLimbs, UsedA)
        then Tmp.FUsed:= UsedA + 1
        else Tmp.FUsed:= UsedA;
      Tmp.FSign:= -1;
    end
    else begin
      if (UsedA > 1) then begin                   // A.FSign >= 0
        arrSubLimb(@A.FLimbs, Limb, @Tmp.FLimbs, UsedA);
        if Tmp.FLimbs[UsedA - 1] = 0
          then Tmp.FUsed:= UsedA - 1
          else Tmp.FUsed:= UsedA;
      end
      else begin
        if (A.FLimbs[0] >= Limb) then begin    // A.FSign >= 0, A.FUsed = 1
           Tmp.FLimbs[0]:= A.FLimbs[0] - Limb;
        end
        else begin
          Tmp.FLimbs[0]:= Limb - A.FLimbs[0];
          Tmp.FSign:= -1;
        end;
        Tmp.FUsed:= 1;
      end;
    end;
    tfFreeInstance(R); //if (R <> nil) then TtfRecord.Release(R);
    R:= Tmp;
  end;
end;

class function TBigNumber.PrevNumber(A: PBigNumber; var R: PBigNumber): TF_RESULT;
var
  Tmp: PBigNumber;
  UsedA: Cardinal;

begin
  UsedA:= A.FUsed;
  Result:= AllocNumber(Tmp, UsedA + 1);
  if Result = TF_S_OK then begin
    if A.FSign < 0 then begin
      if arrInc(@A.FLimbs, @Tmp.FLimbs, A.FUsed)
        then Tmp.FUsed:= UsedA + 1
        else Tmp.FUsed:= UsedA;
      Tmp.FSign:= -1;
    end
    else begin            // A >= 0
      if UsedA > 1 then begin
        arrDec(@A.FLimbs, @Tmp.FLimbs, UsedA);
        if Tmp.FLimbs[UsedA - 1] = 0
          then Tmp.FUsed:= UsedA - 1
          else Tmp.FUsed:= UsedA;
      end
      else begin { UsedA = 1 }
        if A.FLimbs[0] > 0 then begin
          Tmp.FLimbs[0]:= A.FLimbs[0] - 1;
        end
        else begin
          Tmp.FLimbs[0]:= 1;
          Tmp.FSign:= -1;
        end;
      end;
    end;
    tfFreeInstance(R); //if R <> nil then TtfRecord.Release(R);
    R:= Tmp;
  end;
end;

class function TBigNumber.PrevNumberU(A: PBigNumber;
  var R: PBigNumber): TF_RESULT;
var
  Tmp: PBigNumber;
  UsedA: Cardinal;

begin
  UsedA:= A.FUsed;
  if UsedA > 1 then begin
    Result:= AllocNumber(Tmp, UsedA);
    if Result = TF_S_OK then begin
      arrDec(@A.FLimbs, @Tmp.FLimbs, UsedA);
      if Tmp.FLimbs[UsedA - 1] = 0
        then Tmp.FUsed:= UsedA - 1
        else Tmp.FUsed:= UsedA;
    end
  end
  else begin { UsedA = 1 }
    if A.FLimbs[0] = 0 then begin
      Result:= TF_E_INVALIDARG;
    end
    else begin
      Result:= AllocNumber(Tmp, 1);
      if Result = TF_S_OK then begin
        Tmp.FLimbs[0]:= A.FLimbs[0] - 1;
      end
    end;
  end;
  if Result = TF_S_OK then begin
    tfFreeInstance(R); //if R <> nil then TtfRecord.Release(R);
    R:= Tmp;
  end;
end;

// R:= Limb - A
class function TBigNumber.SubLimb2(A: PBigNumber; Limb: TLimb;
                                  var R: PBigNumber): TF_RESULT;
var
  UsedA: Cardinal;
  Tmp: PBigNumber;

begin
  UsedA:= A.FUsed;
  Result:= AllocNumber(Tmp, UsedA + 1);
  if Result = TF_S_OK then begin
    if (A.FSign < 0) then begin
      if arrAddLimb(@A.FLimbs, Limb, @Tmp.FLimbs, UsedA)
        then Tmp.FUsed:= UsedA + 1
        else Tmp.FUsed:= UsedA;
    end
    else begin
      if (UsedA > 1) then begin                   // A.FSign >= 0
        arrSubLimb(@A.FLimbs, Limb, @Tmp.FLimbs, UsedA);
        if Tmp.FLimbs[UsedA - 1] = 0
          then Tmp.FUsed:= UsedA - 1
          else Tmp.FUsed:= UsedA;
        Tmp.FSign:= -1;
      end
      else begin
        if (A.FLimbs[0] > Limb) then begin    // A.FSign >= 0, A.FUsed = 1
          Tmp.FLimbs[0]:= A.FLimbs[0] - Limb;
          Tmp.FSign:= -1;
        end
        else begin
          Tmp.FLimbs[0]:= Limb - A.FLimbs[0];
        end;
        Tmp.FUsed:= 1;
      end;
    end;
    tfFreeInstance(R); //if (R <> nil) then TtfRecord.Release(R);
    R:= Tmp;
  end;
end;

// R:= A - Limb
class function TBigNumber.SubLimbU(A: PBigNumber; Limb: TLimb;
                                   var R: PBigNumber): TF_RESULT;
var
  UsedA: Cardinal;
  Tmp: PBigNumber;

begin
  UsedA:= A.FUsed;
  if (UsedA = 1) then begin
    if A.FLimbs[0] >= Limb then begin
      Result:= AllocNumber(Tmp, 1);
      if Result = TF_S_OK then begin
        Tmp.FUsed:= 1;
        Tmp.FLimbs[0]:= A.FLimbs[0] - Limb;
        tfFreeInstance(R); //if (R <> nil) then TtfRecord.Release(R);
        R:= Tmp;
      end;
    end
    else begin { A < Limb }
//      Result:= TFL_E_INVALIDSUB;
      Result:= TF_E_INVALIDARG;
    end;
  end
  else begin { UsedA > 1 }
    Result:= AllocNumber(Tmp, UsedA);
    if Result = TF_S_OK then begin
      arrSubLimb(@A.FLimbs, Limb, @Tmp.FLimbs, UsedA);
      if Tmp.FLimbs[UsedA - 1] = 0
        then Tmp.FUsed:= UsedA - 1
        else Tmp.FUsed:= UsedA;
      tfFreeInstance(R); //if (R <> nil) then TtfRecord.Release(R);
      R:= Tmp;
    end;
  end;
end;

(*
class function TBigNumber.SubLimbU2(A: PBigNumber; Limb: TLimb;
                                    var R: PBigNumber): HResult;
var
  UsedA: Cardinal;
  Tmp: PBigNumber;

begin
  UsedA:= A.FUsed;
  if (UsedA = 1) and (A.FLimbs[0] <= Limb) then begin
    Result:= AllocNumber(Tmp, 1);
    if Result = TFL_S_OK then begin
      Tmp.FUsed:= 1;
      Tmp.FLimbs[0]:= Limb - A.FLimbs[0];
      if (R <> nil) then TtfRecord.Release((R);
      R:= Tmp;
    end;
  end
  else { A > Limb }
    Result:= TFL_E_INVALIDSUB;
end;
*)

// R:= Limb - A
class function TBigNumber.SubLimbU2(A: PBigNumber; Limb: TLimb;
                                    var R: TLimb): TF_RESULT;
var
  UsedA: Cardinal;

begin
  UsedA:= A.FUsed;
  if (UsedA = 1) and (A.FLimbs[0] <= Limb) then begin
    R:= Limb - A.FLimbs[0];
    Result:= TF_S_OK;
  end
  else { A > Limb }
//    Result:= TFL_E_INVALIDSUB;
    Result:= TF_E_INVALIDARG;
end;

class function TBigNumber.SubIntLimb(A: PBigNumber; Limb: TIntLimb;
                                     var R: PBigNumber): TF_RESULT;
var
  UsedA: Cardinal;
  AbsLimb: TLimb;
  Tmp: PBigNumber;

begin
  UsedA:= A.FUsed;
  AbsLimb:= Abs(Limb);
  Result:= AllocNumber(Tmp, UsedA + 1);
  if Result = TF_S_OK then begin
    if A.FSign xor Integer(Limb) < 0 then begin
      if arrAddLimb(@A.FLimbs, AbsLimb, @Tmp.FLimbs, UsedA)
        then Tmp.FUsed:= UsedA + 1
        else Tmp.FUsed:= UsedA;
      Tmp.FSign:= A.FSign;
    end
    else begin
      if A.FUsed = 1 then begin
// Assert(Tmp.FUsed = 1)
        if A.FLimbs[0] < AbsLimb then begin
          Tmp.FLimbs[0]:= AbsLimb - A.FLimbs[0];
          Tmp.FSign:= not A.FSign;
        end
        else begin
          Tmp.FLimbs[0]:= A.FLimbs[0] - AbsLimb;
          if Tmp.FLimbs[0] <> 0
            then Tmp.FSign:= A.FSign;
        end;
      end
      else begin { UsedA > 1 }
        arrSubLimb(@A.FLimbs, AbsLimb, @Tmp.FLimbs, UsedA);
        if Tmp.FLimbs[UsedA - 1] = 0
          then Tmp.FUsed:= UsedA - 1
          else Tmp.FUsed:= UsedA;
        Tmp.FSign:= A.FSign;
      end;
    end;
    tfFreeInstance(R); //if (R <> nil) then TtfRecord.Release(R);
    R:= Tmp;
  end;
end;

// R:= Limb - A
class function TBigNumber.SubIntLimb2(A: PBigNumber; Limb: TIntLimb;
                                      var R: PBigNumber): TF_RESULT;
var
  UsedA: Cardinal;
  AbsLimb: TLimb;
  Tmp: PBigNumber;

begin
  UsedA:= A.FUsed;
  AbsLimb:= Abs(Limb);
  Result:= AllocNumber(Tmp, UsedA + 1);
  if Result = TF_S_OK then begin
    if A.FSign xor Integer(Limb) < 0 then begin
// Abs(Tmp) = Abs(A) + Abs(Limb)
      if arrAddLimb(@A.FLimbs, AbsLimb, @Tmp.FLimbs, UsedA)
        then Tmp.FUsed:= UsedA + 1
        else Tmp.FUsed:= UsedA;
      if (Limb < 0) then Tmp.FSign:= -1;
    end
    else begin
      if A.FUsed = 1 then begin
// Assert(Tmp.FUsed = 1)
        if A.FLimbs[0] < AbsLimb then begin
          Tmp.FLimbs[0]:= AbsLimb - A.FLimbs[0];
          Tmp.FSign:= A.FSign;
        end
        else begin
          Tmp.FLimbs[0]:= A.FLimbs[0] - AbsLimb;
          if (Tmp.FLimbs[0] <> 0)
            then Tmp.FSign:= not A.FSign;
        end;
      end
      else begin { UsedA > 1 }
        arrSubLimb(@A.FLimbs, AbsLimb, @Tmp.FLimbs, UsedA);
        if Tmp.FLimbs[UsedA - 1] = 0
          then Tmp.FUsed:= UsedA - 1
          else Tmp.FUsed:= UsedA;
        Tmp.FSign:= not A.FSign;
      end;
    end;
    tfFreeInstance(R); //if (R <> nil) then TtfRecord.Release(R);
    R:= Tmp;
  end;
end;

(*
class function TBigNumber.SubIntLimbU(A: PBigNumber; Limb: TIntLimb;
                                      var R: PBigNumber): HResult;
var
  UsedA: Cardinal;
  AbsLimb: TLimb;
  Tmp: PBigNumber;

begin
  UsedA:= A.FUsed;
  AbsLimb:= Abs(Limb);
  if Limb < 0 then begin
    Result:= AllocNumber(Tmp, UsedA + 1);
    if Result = TFL_S_OK then begin
      if arrAddLimb(@A.FLimbs, AbsLimb, @Tmp.FLimbs, UsedA)
        then Tmp.FUsed:= UsedA + 1
        else Tmp.FUsed:= UsedA;
      if (R <> nil) then TtfRecord.Release((R);
      R:= Tmp;
    end;
  end
  else if (UsedA = 1) then begin
    if A.FLimbs[0] >= AbsLimb then begin
      Result:= AllocNumber(Tmp, 1);
      if Result = TFL_S_OK then begin
        Tmp.FUsed:= 1;
        Tmp.FLimbs[0]:= A.FLimbs[0] - AbsLimb;
        if (R <> nil) then TtfRecord.Release((R);
        R:= Tmp;
      end;
    end
    else begin { A < Limb }
      Result:= TFL_E_INVALIDSUB;
    end;
  end
  else begin { UsedA > 1 }
    Result:= AllocNumber(Tmp, UsedA);
    if Result = TFL_S_OK then begin
      arrSubLimb(@A.FLimbs, AbsLimb, @Tmp.FLimbs, UsedA);
      if Tmp.FLimbs[UsedA - 1] = 0
        then Tmp.FUsed:= UsedA - 1
        else Tmp.FUsed:= UsedA;
      if (R <> nil) then TtfRecord.Release((R);
      R:= Tmp;
    end;
  end;
end;
*)
class function TBigNumber.AssignCardinal(var A: PBigNumber;
               const Value: Cardinal; ASign: Integer = 0): TF_RESULT;
const
  CardSize = SizeOf(Cardinal) div SizeOf(TLimb);

var
  Tmp: PBigNumber;

begin
{$IF CardSize = 0}
  Result:= TFL_E_NOTIMPL;
{$ELSE}
  Result:= AllocNumber(Tmp, CardSize);
  if Result <> TF_S_OK then Exit;
  {$IF CardSize = 1}
    Tmp.FLimbs[0]:= Value;
  {$ELSE}
    Move(Value, Tmp.FLimbs, SizeOf(Cardinal));
    Tmp.FUsed:= CardSize;
    Normalize(Tmp);
  {$IFEND}
  if ASign < 0 then Tmp.FSign:= -1;
  tfFreeInstance(A); //if (A <> nil) then TtfRecord.Release(A);
  A:= Tmp;
{$IFEND}
end;

class function TBigNumber.AssignInteger(var A: PBigNumber;
               const Value: Integer; ASign: Integer = 0): TF_RESULT;

const
  IntSize = SizeOf(Integer) div SizeOf(TLimb);

var
  Tmp: PBigNumber;
{$IF IntSize <> 1}
  AbsValue: Integer;
{$IFEND}

begin
{$IF IntSize = 0}
  Result:= TFL_E_NOTIMPL;
{$ELSE}
  Result:= AllocNumber(Tmp, IntSize);
  if Result <> S_OK then Exit;
  {$IF IntSize = 1}
    Tmp.FLimbs[0]:= Abs(Value);
  {$ELSE}
    AbsValue:= Abs(Value);
    Move(AbsValue, Tmp.FLimbs, SizeOf(Integer));
    Tmp.FUsed:= IntSize;
    Normalize(Tmp);
  {$IFEND}
  if (ASign <= 0) and ((Value < 0) or (ASign < 0)) then Tmp.FSign:= -1;
  tfFreeInstance(A); //if (A <> nil) then TtfRecord.Release(A);
  A:= Tmp;
  Result:= S_OK;
{$IFEND}
end;

class function TBigNumber.ToPByte(A: PBigNumber; P: PByte; var L: Cardinal): TF_RESULT;
var
  BytesUsed: Cardinal;
  BytesReq: Cardinal;
  Limb: TLimb;
  NeedExtraByte: Boolean;
  P1: PByte;
  Carry: Boolean;
  I: Integer;

begin
  BytesUsed:= (A.FUsed - 1) * SizeOf(TLimb);
  Limb:= A.FLimbs[A.FUsed - 1];
  while Limb <> 0 do begin
    Inc(BytesUsed);
    Limb:= Limb shr 8;
  end;
  if BytesUsed = 0 then BytesUsed:= 1;
  NeedExtraByte:= PByte(@A.FLimbs)[BytesUsed - 1] >= $80;
  if (A.FSign >= 0) then begin
    BytesReq:= BytesUsed + Cardinal(NeedExtraByte);
    if (P <> nil) and (L >= BytesReq) then begin
      Move(A.FLimbs, P^, BytesUsed);
      if NeedExtraByte then P[BytesUsed]:= 0;
      Result:= TF_S_OK;
    end
    else begin
      Result:= TF_E_INVALIDARG;
    end;
    L:= BytesReq;
  end
  else begin
    if (PByte(@A.FLimbs)[BytesUsed - 1] = $80) then begin
      NeedExtraByte:= False;
      for I:= 0 to Integer(BytesUsed) - 2 do begin
        if PByte(@A.FLimbs)[I] <> 0 then begin
          NeedExtraByte:= True;
          Break;
        end;
      end;
    end;
    BytesReq:= BytesUsed + Cardinal(NeedExtraByte);
    if (P <> nil) and (L >= BytesReq) then begin
      P1:= @A.FLimbs;
      Carry:= True;
      while BytesUsed > 0 do begin
        P^:= not P1^;
        if Carry then begin
          Inc(P^);
          Carry:= (P^ = 0);
        end;
        Inc(P);
        Inc(P1);
        Dec(BytesUsed);
      end;
      if NeedExtraByte then P^:= $FF;
      Result:= TF_S_OK;
    end
    else begin
      Result:= TF_E_INVALIDARG;
    end;
    L:= BytesReq;
  end;
end;
(*
class function TBigNumber.ToBytes(A: PBigNumber; var Bytes: TBytes): TF_RESULT;
var
  L: Cardinal;

begin
  Result:= ToPByte(A, nil, L);
  if Result = TF_E_INVALIDARG then begin
    SetLength(Bytes, L);
    Result:= ToPByte(A, @Bytes[0], L);
  end;
end;
*)
(*
class function TBigNumber.ToCardinal(A: PBigNumber; var Value: Cardinal): HResult;
const
  CardSize = SizeOf(Cardinal) div SizeOf(TLimb);

begin
{$IF CardSize = 0}
  Result:= TFL_E_NOTIMPL;
{$ELSIF CardSize = 1}
  if (A.FUsed = 1) and (A.FSign >= 0) then begin
    Value:= A.FLimbs[0];
    Result:= TFL_S_OK;
  end
  else
    Result:= TFL_E_INVALIDARG;
{$ELSE}
  if (A.FUsed <= CardSize) and (A.FSign >= 0) then begin
    Value:= 0;
    Move(A.FLimbs, Value, A.FUsed * SizeOf(TLimb));
    Result:= TFL_S_OK;
  end
  else
    Result:= TFL_E_INVALIDARG;
{$IFEND}
end;

class function TBigNumber.ToInteger(A: PBigNumber; var Value: Integer): HResult;
const
  IntSize = SizeOf(Integer) div SizeOf(TLimb);

{$IF IntSize > 1}
var
  Tmp: Integer;
{$IFEND}

begin
{$IF IntSize <= 0}
  Result:= TFL_E_NOTIMPL;
{$ELSIF IntSize = 1}
  if (A.FUsed = 1) then begin
    if FSign >= 0 then begin
      if (A.FLimbs[0] <= Cardinal(MaxInt)) then begin
        Value:= A.FLimbs[0];
        Result:= TFL_S_OK;
      end
      else
        Result:= TFL_E_INVALIDARG;
    end
    else begin
      if (A.FLimbs[0] <= Cardinal(MaxInt)) then begin
        Value:= - Integer(A.FLimbs[0]);
        Result:= TFL_S_OK;
      end
      else if (A.FLimbs[0] = Cardinal(MinInt)) then begin
        Cardinal(Value):= A.FLimbs[0];
        Result:= TFL_S_OK;
      else
        Result:= TFL_E_INVALIDARG;
    end
  end
  else
    Result:= TFL_E_INVALIDARG;
{$ELSEIF IntSize > 1}
  if (A.FUsed <= IntSize) then begin
    Tmp:= 0;
    Move(A.FLimbs, Tmp, A.FUsed * SizeOf(TLimb));
    if (A.FSign >= 0)
      then Value:= Tmp
      else Value:= -Tmp;
    Result:= TFL_S_OK;
  end
  else
    Result:= TFL_E_INVALIDARG;
{$IFEND}
end;
*)

class function TBigNumber.ToIntLimb(A: PBigNumber; var Value: TIntLimb): TF_RESULT;
const
  MaxValue = TLimb(TLimb(TLimbInfo.MaxLimb shr 1) + TLimb(1));

var
  Tmp: TLimb;

begin
  Tmp:= A.FLimbs[0];
  if (A.FUsed > 1) or
    (Tmp > MaxValue) or ((Tmp = MaxValue) and (A.FSign >= 0))
  then
    Result:= TF_E_INVALIDARG
  else begin
    if A.FSign >= 0 then Value:= TIntLimb(Tmp)
    else Value:= -TIntLimb(Tmp);
    Result:= TF_S_OK;
  end;
end;

class function TBigNumber.ToDblIntLimb(A: PBigNumber; var Value: TDIntLimb): TF_RESULT;
const
  MaxValue = TDLimb(TLimbInfo.MaxDblIntLimb) + TDLimb(1);

var
  Tmp: TDLimb;

begin
  if A.FUsed = 1 then begin
    if A.FSign >= 0 then
      Value:= TDIntLimb(A.FLimbs[0])
    else
      Value:= -TDIntLimb(A.FLimbs[0]);
    Result:= TF_S_OK;
  end
  else if (A.FUsed = 2) then begin
    Tmp:= PDLimb(@A.FLimbs)^;
    if (Tmp > MaxValue) or ((Tmp = MaxValue) and (A.FSign >= 0)) then
      Result:= TF_E_INVALIDARG
    else begin
      if A.FSign >= 0 then Value:= TDIntLimb(Tmp)
      else Value:= -TDIntLimb(Tmp);
      Result:= TF_S_OK;
    end;
  end
  else
    Result:= TF_E_INVALIDARG;
end;

class function TBigNumber.ToLimb(A: PBigNumber; var Value: TLimb): TF_RESULT;
begin
  if (A.FUsed > 1) or (A.FSign < 0) then
    Result:= TF_E_INVALIDARG
  else begin
    Value:= A.FLimbs[0];
    Result:= TF_S_OK;
  end;
end;

class function TBigNumber.GetLimb(A: PBigNumber; var Value: TLimb): TF_RESULT;
begin
  if A.FSign >= 0 then begin
    Value:= A.FLimbs[0];
  end
  else begin
    Value:= TLimb(-TIntLimb(A.FLimbs[0]));
  end;
  Result:= TF_S_OK;
end;

class function TBigNumber.GetDblLimb(A: PBigNumber; var Value: TDLimb): TF_RESULT;
var
  Tmp: TDLimb;

begin
  if A.FUsed > 1 then begin
    Tmp:= PDLimb(@A.FLimbs)^;
  end
  else begin
    Tmp:= 0;
    PLimb(@Tmp)^:= A.FLimbs[0];
  end;

  if A.FSign >= 0 then begin
    Value:= Tmp;
  end
  else begin
    Value:= TDLimb(-TDIntLimb(Tmp));
  end;

  Result:= TF_S_OK;
end;

class function TBigNumber.ToDblLimb(A: PBigNumber; var Value: TDLimb): TF_RESULT;
begin
  if (A.FUsed > 2) or (A.FSign < 0) then
    Result:= TF_E_INVALIDARG
  else begin
    Value:= PDLimb(@A.FLimbs)^;
    Result:= TF_S_OK;
  end;
end;

{ TNumber --> string conversions }

class function TBigNumber.ToHex(A: PBigNumber; P: PByte; var L: Integer;
                          TwoCompl: Boolean): TF_RESULT;
const
  ZERO_OFFSET = 48;   // Ord('0');
  A_OFFSET = 65;      // Ord('A');

var
  BytesUsed: Integer;
  NibblesUsed: Integer;
  Limb: TLimb;
  I, N: Integer;
  P1: PByte;
  B, Nibble: Byte;
  HiNibble: Boolean;
  Carry: Boolean;

begin
// last limb can hold zero nibbles
  NibblesUsed:= (A.FUsed - 1) * SizeOf(TLimb) * 2;

  Limb:= A.FLimbs[A.FUsed - 1];
  repeat
    Inc(NibblesUsed);
    Limb:= Limb shr 4;
  until Limb = 0;

  BytesUsed:= (NibblesUsed + 1) shr 1;
  P1:= @A.FLimbs;
  Nibble:= P1[BytesUsed - 1];
  if not Odd(NibblesUsed) then Nibble:= Nibble shr 4;
  Nibble:= Nibble and $0F;
  N:= NibblesUsed;
  if TwoCompl then begin
    if ((A.FSign >= 0) and (Nibble >= 8))
      or ((A.FSign < 0) and (Nibble > 8))
        then Inc(N);
  end;

  if (P = nil) or (N > L) then begin
    Result:= TF_E_INVALIDARG;
  end
  else begin
//    if TwoCompl
//      then Inc(P, L)
//      else
    Inc(P, N);
    HiNibble:= False;
    if (A.FSign >= 0) or not TwoCompl then begin
      I:= 0;
      while I < NibblesUsed do begin
        if HiNibble then begin
          Nibble:= B shr 4;
          Inc(P1);
        end
        else begin
          B:= P1^;
          Nibble:= B and $0F;
        end;
        Dec(P);
        if Nibble < 10
          then P^:= Nibble + ZERO_OFFSET
          else P^:= Nibble + A_OFFSET - 10;
        HiNibble:= not HiNibble;
        Inc(I);
      end;
// Two's complement leading zero
      if I < N then begin
        Dec(P);
        P^:= ZERO_OFFSET;
      end;
// Two complement leading zeros
{      if TwoCompl then while I < L do begin
        Dec(P);
        P^:= ZERO_OFFSET;
        Inc(I);
      end; }
    end
    else begin    // A < 0, two compl format
      Carry:= True;
      I:= 0;
      while I < NibblesUsed do begin
        if HiNibble then begin
          Nibble:= B shr 4;
          Inc(P1);
        end
        else begin
          B:= not P1^;
          if Carry then begin
            Inc(B);
            Carry:= B = 0;
          end;
          Nibble:= B and $0F;
        end;
        if (P <> nil) and (I < L) then begin
          Dec(P);
          if Nibble < 10
            then P^:= Nibble + ZERO_OFFSET
            else P^:= Nibble + A_OFFSET - 10;
        end;
        HiNibble:= not HiNibble;
        Inc(I);
      end;
// Two's complement leading 'F'
      if I < N then begin
        Dec(P);
        P^:= 15 + A_OFFSET - 10;    // 'F'
      end;
// Two complement leading 'F's
{      while I < L do begin
        Dec(P);
        P^:= 15 + A_OFFSET - 10;    // 'F'
        Inc(I);
      end; }
    end;
    Result:= TF_S_OK;
  end;
  L:= N;
end;
{
class function TBigNumber.ToHexString(A: PBigNumber; var S: string;
               Digits: Integer; const Prefix: string; TwoCompl: Boolean): TF_RESULT;
const
  ASCII_8 = 56;   // Ord('8')

var
  L, L1: Integer;
  P, P1: PByte;
  Filler: Char;
  I: Integer;

begin
  if TBigNumber.ToHex(A, nil, L, TwoCompl) = TF_E_INVALIDARG then begin
    GetMem(P, L);
    try
      L1:= L;
      Result:= TBigNumber.ToHex(A, P, L1, TwoCompl);
      if Result = TF_S_OK then begin
        if Digits < L1 then Digits:= L1;
        I:= 1;
        if (A.FSign < 0) and not TwoCompl then begin
          Inc(I);
          SetLength(S, Digits + Length(Prefix) + 1);
          S[1]:= '-';
        end
        else
          SetLength(S, Digits + Length(Prefix));
        Move(Pointer(Prefix)^, S[I], Length(Prefix) * SizeOf(Char));
        Inc(I, Length(Prefix));
        if Digits > L1 then begin
          if TwoCompl and (P[L1] >= ASCII_8) then Filler:= 'F'
          else Filler:= '0';
          while I + L1 <= Length(S) do begin
            S[I]:= Filler;
            Inc(I);
          end;
        end;
        P1:= P;
        while I <= Length(S) do begin
          S[I]:= Char(P1^);
          Inc(I);
          Inc(P1);
        end;
      end;
    finally
      FreeMem(P);
    end;
  end
  else
    Result:= TF_E_UNEXPECTED;
end;
}
(*
class function TBigNumber.ToHexString(A: PBigNumber; var S: string;
                 Digits: Cardinal; TwoCompl: Boolean): TF_RESULT;
var
  BytesUsed: Cardinal;
{$IF SizeOf(TLimb) <> 1}
  Limb: TLimb;
{$IFEND}
//  NeedExtraByte: Boolean;
  L: Cardinal;
  P: PByte;
  P1: PChar;
  I: Cardinal;
  Tmp: string;
  B: Byte;
  Carry: Boolean;

begin
{$IF SizeOf(TLimb) = 1}
  BytesUsed:= A.FUsed;
{$ELSE}
  BytesUsed:= (A.FUsed - 1) * SizeOf(TLimb);
  Limb:= A.FLimbs[A.FUsed - 1];
  repeat
    Inc(BytesUsed);
    Limb:= Limb shr 8;
  until Limb = 0;
{$IFEND}

  P:= @A.FLimbs;
  if A.FSign >= 0 then begin
    L:= BytesUsed * 2 - 1;
    if (P[BytesUsed - 1] >= $10) then Inc(L);
    if TwoCompl and (P[BytesUsed - 1] >= $80) then Inc(L);
    if L < Digits then L:= Digits;
    SetLength(S, L);
    P1:= @S[L - 1];
    for I:= 1 to BytesUsed - 1 do begin
      Tmp:= IntToHex(P^, 2);
      Move(Pointer(Tmp)^, P1^, 2 * SizeOf(Char));
      Inc(P);
      Dec(P1, 2);
    end;
    Tmp:= IntToHex(P^, 1);
    if Length(Tmp) < 2 then Inc(P1);
    Move(Pointer(Tmp)^, P1^, Length(Tmp) * SizeOf(Char));
    while (P1 <> @S[1]) do begin
      Dec(P1);
      P1^:= '0';
    end;
  end
  else if not TwoCompl then begin
    L:= BytesUsed * 2;
    if (P[BytesUsed - 1] >= $10) then Inc(L);
    if L < Digits then L:= Digits;
    SetLength(S, L);
    S[1]:= '-';
    P1:= @S[L - 1];
    for I:= 1 to BytesUsed - 1 do begin
      Tmp:= IntToHex(P^, 2);
      Move(Pointer(Tmp)^, P1^, 2 * SizeOf(Char));
      Inc(P);
      Dec(P1, 2);
    end;
    Tmp:= IntToHex(P^, 1);
    if Length(Tmp) < 2 then Inc(P1);
    Move(Pointer(Tmp)^, P1^, Length(Tmp) * SizeOf(Char));
    while (P1 <> @S[2]) do begin
      Dec(P1);
      P1^:= '0';
    end;
  end
  else begin
    L:= BytesUsed * 2 + 1;
//    if (P[BytesUsed - 1] >= $10) then Inc(L);
//    if (P[BytesUsed - 1] >= $80) then Inc(L);
    if L < Digits then L:= Digits;
    SetLength(S, L);
    P1:= @S[L - 1];
    Carry:= True;
    for I:= 1 to BytesUsed - 1 do begin
      B:= not P^;
      if Carry then begin
        Inc(B);
        Carry:= B = 0;
      end;
      Tmp:= IntToHex(B, 2);
      Move(Pointer(Tmp)^, P1^, 2 * SizeOf(Char));
      Inc(P);
      Dec(P1, 2);
    end;
    B:= not P^;
    if Carry then begin
      Inc(B);
    end;
    Tmp:= IntToHex(B, 1);
{    if Length(Tmp) < 2 then Inc(P1)
    else begin
      if (Tmp[1] = 'F') and (Tmp[2] >= '8') then begin
        Tmp:= Tmp[2];
      end;
    end;}
    Move(Pointer(Tmp)^, P1^, Length(Tmp) * SizeOf(Char));
    while (P1 <> @S[1]) do begin
      Dec(P1);
      P1^:= 'F';
    end;
    while (Cardinal(Length(S)) > Digits) and (Length(S) >= 2)
              and (S[1] = 'F') and (S[2] >= '8') do
      S:= Copy(S, 2, Length(S) - 1);
  end;
  Result:= TF_S_OK;
end;
*)

class function TBigNumber.ToDec(A: PBigNumber; P: PByte;
                                      var L: Integer): TF_RESULT;
const
  ZERO_OFFSET = 48;  // Ord('0');

var
  Tmp: PBigNumber;
  Used: Integer;
  I: Integer;
  Digit: Byte;
  B: Byte;
  P1: PByte;

begin
  Used:= A.FUsed;
  Result:= AllocNumber(Tmp, A.FUsed);
  if Result = TF_S_OK then begin
    Move(A.FLimbs, Tmp.FLimbs, A.FUsed * SizeOf(TLimb));
    I:= 0;
    P1:= P;
    Used:= A.FUsed;

    repeat
      Digit:= arrSelfDivModLimb(@Tmp.FLimbs, Used, 10);
      if (P1 <> nil) and (I < L) then begin
        P1^:= Digit + ZERO_OFFSET;
        Inc(P1);
      end;
      Inc(I);
      if (Tmp.FLimbs[Used - 1] = 0) then begin
        if (Used > 1) then
          Dec(Used)
        else
          Break;
      end;
    until False;

    tfReleaseInstance(Tmp); //TtfRecord.Release(Tmp);
    L:= I;
    if (P <> nil) and (L >= I) then begin
// swap digits' string
      I:= I shr 1;
      while I > 0 do begin
        Dec(P1);
        B:= P1^;
        P1^:= P^;
        P^:= B;
        Inc(P);
        Dec(I);
      end;
//      Result:= TFL_S_OK;
    end
    else
      Result:= TF_E_INVALIDARG;
  end;
end;

(*
class function TBigNumber.ToString(A: PBigNumber; var S: string): TF_RESULT;
var
  Tmp: PBigNumber;
  Used: Integer;
  I, J: Integer;
  Digits: array of Byte;

begin
  S:= '';

// log(256) approximated from above by 41/17
  SetLength(Digits, (GetSize(A) * 41) div 17 + 1);

  Result:= AllocNumber(Tmp, A.FUsed);
  if Result = TF_S_OK then begin
    Move(A.FLimbs, Tmp.FLimbs, A.FUsed * SizeOf(TLimb));
    I:= 0;
    Used:= A.FUsed;
    repeat
      Digits[I]:= arrSelfDivModLimb(@Tmp.FLimbs, Used, 10);
      Inc(I);
      if (Tmp.FLimbs[Used - 1] = 0) then begin
        if (Used > 1) then
          Dec(Used)
        else
          Break;
      end;
    until False;

    TtfRecord.Release(Tmp);

    if A.FSign < 0 then begin
      Inc(I);
      SetLength(S, I);
      S[1]:= '-';
      J:= 2;
    end
    else begin
      SetLength(S, I);
      J:= 1;
    end;

    while J <= I do begin
      S[J]:= Chr(Ord('0') + Digits[I - J]);
      Inc(J);
    end;
  end;
end;
*)
(*
class function TBigNumber.ToWideHexString(A: PBigNumber; var S: WideString;
                 Digits: Cardinal; TwoCompl: Boolean): HResult;
var
  Tmp: string;

begin
  Result:= ToHexString(A, Tmp, Digits, TwoCompl);
  if Result = TFL_S_OK then
    S:= WideString(Tmp);
end;

class function TBigNumber.ToWideString(A: PBigNumber; var S: WideString): HResult;
var
  Tmp: string;

begin
  Result:= ToString(A, Tmp);
  if Result = TFL_S_OK then
    S:= WideString(Tmp);
end;
*)

const
  BigNumPrefixSize = SizeOf(TBigNumber) - SizeOf(TBigNumber.TLimbArray);

class function TBigNumber.AllocNumber(var A: PBigNumber;
                                       NLimbs: Cardinal): TF_RESULT;
var
  BytesRequired: Cardinal;

begin
  if NLimbs >= TLimbInfo.MaxCapacity then begin
    Result:= TF_E_NOMEMORY;
    Exit;
  end;
  if NLimbs = 0 then NLimbs:= 1;
  BytesRequired:= NLimbs * SizeOf(TLimb) + BigNumPrefixSize;
  BytesRequired:= (BytesRequired + 7) and not 7;
  try
    GetMem(A, BytesRequired);
    A^.FVTable:= @BigNumVTable;
    A^.FRefCount:= 1;
    A^.FCapacity:= (BytesRequired - BigNumPrefixSize) div SizeOf(TLimb);
    A^.FUsed:= 1;
    A^.FSign:= 0;
    A^.FLimbs[0]:= 0;
    Result:= TF_S_OK;
  except
    Result:= TF_E_OUTOFMEMORY;
  end;
end;

class function TBigNumber.AllocPowerOfTwo(var A: PBigNumber;
                                          APower: Cardinal): TF_RESULT;
var
  NLimbs: Cardinal;

begin
  NLimbs:= APower shr TLimbInfo.BitShift + 1;
  Result:= AllocNumber(A, NLimbs);
  if Result = TF_S_OK then begin
    FillChar(A^.FLimbs, NLimbs * SizeOf(TLimb), 0);
    A^.FUsed:= NLimbs;
    A^.FLimbs[NLimbs - 1]:= 1 shl (APower and TLimbInfo.BitShiftMask);
  end;
end;

class function TBigNumber.FromString(var A: PBigNumber;
               const S: string; TwoCompl: Boolean): TF_RESULT;
begin
//  Result:= BigNumberFromPWideChar(A, PWideChar(Pointer(S)), Length(S), True);
  Result:= BigNumberFromPChar(A, Pointer(S), Length(S),
                              SizeOf(Char), True, TwoCompl);
end;

class function TBigNumber.GetHashCode(Inst: PBigNumber): Integer;
var
  Limb: TLimb;
  L: Integer;

begin
  L:= (Inst.FUsed - 1) * SizeOf(TLimb);
  Limb:= Inst.FLimbs[Inst.FUsed - 1];
  while Limb <> 0 do begin
    Inc(L);
    Limb:= Limb shr 8;
  end;
  if L = 0 then L:= 1;
  Result:= TJenkins1.Hash(Inst.FLimbs, L);
  if Inst.FSign < 0 then Result:= - Result;
end;

class function TBigNumber.GetIsEven(Inst: PBigNumber): Boolean;
begin
  Result:= not Odd(Inst.FLimbs[0]);
end;

class function TBigNumber.GetIsOne(Inst: PBigNumber): Boolean;
begin
  Result:= (Inst.FUsed = 1) and (Inst.FLimbs[0] = 1) and (Inst.FSign >= 0);
end;

class function TBigNumber.GetIsPowerOfTwo(Inst: PBigNumber): Boolean;
var
  P: PLimb;
  Count: Cardinal;

begin
  Result:= Inst.FSign >= 0;
  if Result then begin
    Count:= Inst.FUsed - 1;
    P:= @Inst.FLimbs;
    while Count > 0 do begin
      Result:= P^ = 0;
      if not Result then Exit;
      Inc(P);
      Dec(Count);
    end;
    Result:= P^ and (P^ - 1) = 0;
  end;
end;

class function TBigNumber.GetIsZero(Inst: PBigNumber): Boolean;
begin
  Result:= (Inst.FUsed = 1) and (Inst.FLimbs[0] = 0);
end;

class function TBigNumber.GetLen(Inst: PBigNumber): Integer;
var
  Limb: TLimb;

begin
  Result:= (Inst.FUsed - 1) * SizeOf(TLimb);
  Limb:= Inst.FLimbs[Inst.FUsed - 1];
  while Limb <> 0 do begin
    Inc(Result);
    Limb:= Limb shr 8;
  end;
  if Result = 0 then Result:= 1;
end;

class function TBigNumber.GetRawData(Inst: PBigNumber): PByte;
begin
  Result:= @Inst.FLimbs;
end;

class function TBigNumber.GetSign(Inst: PBigNumber): Integer;
begin
  if (Inst.FUsed = 1) and (Inst.FLimbs[0] = 0) then Result:= 0
  else if Inst.FSign >= 0 then Result:= 1
  else Result:= -1;
end;

class function TBigNumber.GetSize(Inst: PBigNumber): Integer;
var
  Limb: TLimb;

begin
  Result:= (Inst.FUsed - 1) * SizeOf(TLimb);
  Limb:= Inst.FLimbs[Inst.FUsed - 1];
  repeat
    Inc(Result);
    Limb:= Limb shr 8;
  until Limb = 0;
end;

class function TBigNumber.FromBytes(var A: PBigNumber; const Bytes: TBytes): TF_RESULT;
begin
  Result:= BigNumberFromPByte(A, PByte(Bytes), Length(Bytes), True);
end;

class function TBigNumber.FromPCharHex(var A: PBigNumber; S: PChar; L: Integer;
                 AllowNegative, TwoCompl: Boolean): TF_RESULT;
const
{$IF SizeOf(TLimb) = 8}         // 16 hex digits per uint64 limb
   LIMB_SHIFT = 4;
{$ELSEIF SizeOf(TLimb) = 4}     // 8 hex digits per uint32 limb
   LIMB_SHIFT = 3;
{$ELSEIF SizeOf(TLimb) = 2}     // 4 hex digits per word limb
   LIMB_SHIFT = 2;
{$ELSE}                         // 2 hex digits per byte limb
   LIMB_SHIFT = 1;
{$IFEND}

var
  IsMinus: Boolean;
  I, N: Integer;
  Limb: TLimb;
  Carry: Boolean;
  Digit: Cardinal;
  Ch: Char;
  LimbsRequired: Cardinal;
  Tmp: PBigNumber;

begin
  if L <= 0 then begin
    Result:= TF_E_INVALIDARG;
    Exit;
  end;
  I:= 0;
                            // S is zero-based PChar
  if TwoCompl then begin
    IsMinus:= (S[0] >= '8');
    TwoCompl:= TwoCompl and IsMinus;
  end
  else begin
    IsMinus:= S[0] = '-';
    if IsMinus then Inc(I);
  end;

  if (L <= I) or (IsMinus and not AllowNegative) then begin
    Result:= TF_E_INVALIDARG;
    Exit;
  end;

  N:= L - I;                // number of hex digits;
                            //   1 limb holds 2 * SizeOf(TLimb) hex digits

  LimbsRequired:= (N + 2 * SizeOf(TLimb) - 1) shr LIMB_SHIFT;
  Result:= AllocNumber(Tmp, LimbsRequired);
  if Result <> TF_S_OK then Exit;

  N:= 0;
  Limb:= 0;
  Carry:= True;

  repeat
                    // moving from end of string
    Ch:= S[L - N - 1];
    case Ch of
        '0'..'9': Digit:= Ord(Ch) - Ord('0');
        'A'..'F': Digit:= 10 + Ord(Ch) - Ord('A');
        'a'..'f': Digit:= 10 + Ord(Ch) - Ord('a');
    else
        tfReleaseInstance(Tmp); //TtfRecord.Release(Tmp);
        Result:= TF_E_INVALIDARG;
        Exit;
    end;
                      // shift digit to its position in a limb
    Limb:= Limb + (Digit shl ((N and (2 * SizeOf(TLimb) - 1)) shl 2));

    Inc(N);
    if N and (2 * SizeOf(TLimb) - 1) = 0 then begin

      if TwoCompl then begin
        Limb:= not Limb;
        if Carry then begin
          Inc(Limb);
          Carry:= Limb = 0;
        end;
      end;

      Tmp^.FLimbs[N shr LIMB_SHIFT - 1]:= Limb;
      Limb:= 0;
    end;
  until I + N >= L;

  if N and (2 * SizeOf(TLimb) - 1) <> 0 then begin
    if TwoCompl then begin
      Limb:= TLimb((-1) shl ((N and (2 * SizeOf(TLimb) - 1)) * 4)) or Limb;
      Limb:= not Limb;
      if Carry then Inc(Limb);
    end;
    Tmp^.FLimbs[N shr LIMB_SHIFT]:= Limb;
  end;

  N:= (N + 2 * SizeOf(TLimb) - 1) shr LIMB_SHIFT;
  Tmp^.FUsed:= N;

  Normalize(Tmp);
  if IsMinus and ((Tmp.FUsed > 1) or (Tmp.FLimbs[0] <> 0))
    then Tmp.FSign:= -1;
  tfFreeInstance(A); //if A <> nil then TtfRecord.Release(A);
  A:= Tmp;
end;

function TBigNumber.IsNegative: Boolean;
begin
  Result:= FSign < 0;
end;

function TBigNumber.IsZero: Boolean;
begin
  Result:= (FUsed = 1) and (FLimbs[0] = 0);
end;

class function TBigNumber.ShlNumber(A: PBigNumber; Shift: Cardinal; var R: PBigNumber): TF_RESULT;
var
  UsedA, UsedR: Cardinal;
  Tmp: PBigNumber;
  LimbShift, BitShift: Cardinal;

begin
  if Shift = 0 then begin
    if R <> A then begin
      tfFreeInstance(R); //if R <> nil then TtfRecord.Release(R);
      R:= A;
      tfAddrefInstance(R); //TtfRecord.AddRef(R);
    end;
    Result:= TF_S_OK;
  end
  else begin
    UsedA:= A.FUsed;
    UsedR:= UsedA + (Shift + TLimbInfo.BitSize - 1) div TLimbInfo.BitSize;
    Result:= AllocNumber(Tmp, UsedR);
    if Result = TF_S_OK then begin
      if Shift < TLimbInfo.BitSize then begin
        Tmp.FUsed:= arrShlShort(@A.FLimbs, @Tmp.FLimbs, UsedA, Shift);
      end
      else begin
        LimbShift:= Shift div TLimbInfo.BitSize;
        BitShift:= Shift mod TLimbInfo.BitSize;
        FillChar(Tmp.FLimbs, LimbShift * SizeOf(TLimb), 0);
        Tmp.FUsed:= LimbShift +
          arrShlShort(@A.FLimbs, @Tmp.FLimbs[LimbShift], UsedA, BitShift);
      end;
//      if (Tmp.FUsed > 1) or (Tmp.FLimbs[0] <> 0) then
      Tmp.FSign:= A.FSign;
      tfFreeInstance(R); //if R <> nil then TtfRecord.Release(R);
      R:= Tmp;
    end;
  end;
end;

class function TBigNumber.ShrNumber(A: PBigNumber; Shift: Cardinal; var R: PBigNumber): TF_RESULT;
var
  UsedA, UsedR: Cardinal;
  Tmp: PBigNumber;
  LimbShift, BitShift: Cardinal;

begin
  if Shift = 0 then begin
    if R <> A then begin
      tfFreeInstance(R); //if R <> nil then TtfRecord.Release(R);
      R:= A;
      tfAddrefInstance(R); //TtfRecord.AddRef(R);
    end;
    Result:= TF_S_OK;
  end
  else begin
    UsedA:= A.FUsed;
    LimbShift:= Shift shr TLimbInfo.BitShift;
    if LimbShift >= UsedA then begin
      tfFreeInstance(R); //if R <> nil then TtfRecord.Release(R);
      if A.FSign < 0
        then R:= @BigNumMinusOne
        else R:= @BigNumZero;
      Result:= TF_S_OK;
    end
    else begin
      UsedR:= UsedA - LimbShift;
      Result:= AllocNumber(Tmp, UsedR);
      if Result = TF_S_OK then begin
        BitShift:= Shift and TLimbInfo.BitShiftMask;
        Tmp.FUsed:=
          arrShrShort(@A.FLimbs[LimbShift], @Tmp.FLimbs, UsedR, BitShift);
        if Tmp.FUsed = 0 then Tmp.FUsed:= 1;

        Tmp.FSign:= A.FSign;
        if (Tmp.FSign < 0) and (Tmp.FUsed = 1) and (Tmp.FLimbs[0] = 0) then
          Tmp.FLimbs[0]:= 1;

        tfFreeInstance(R); //if R <> nil then TtfRecord.Release(R);
        R:= Tmp;
      end;
    end;
  end;
end;

class function TBigNumber.SqrtNumber(A: PBigNumber; var R: PBigNumber): TF_RESULT;
var
  Tmp: PBigNumber;
  L: Cardinal;

begin
  if A.FSign < 0 then begin
    Result:= TF_E_INVALIDARG;
  end
  else begin
    Result:= AllocNumber(Tmp, (A.FUsed + 1) shr 1);
    if Result = TF_S_OK then begin
      L:= arrSqrt(@A.FLimbs, @Tmp.FLimbs, A.FUsed);
      if L = 0 then begin
        tfReleaseInstance(Tmp); //TtfRecord.Release(Tmp);
        Result:= TF_E_OUTOFMEMORY;
      end
      else begin
        Tmp.FUsed:= L;
        tfFreeInstance(R); //if R <> nil then TtfRecord.Release(R);
        R:= Tmp;
      end;
    end;
  end;
end;

// R:= A * Limb
class function TBigNumber.MulIntLimb(A: PBigNumber; Limb: TIntLimb; var R: PBigNumber): TF_RESULT;
var
  Tmp: PBigNumber;
  UsedA: Cardinal;
  AbsLimb: TLimb;

begin
  if (Limb = 0) or ((A.FUsed = 1) and (A.FLimbs[0] = 0)) then begin
    tfFreeInstance(R);  //if (R <> nil) then TtfRecord.Release(R);
    R:= @BigNumZero;
    Result:= TF_S_OK;
  end
  else begin            // Limb <> 0, A <> 0
    UsedA:= A.FUsed;
    Result:= AllocNumber(Tmp, UsedA + 1);
    if Result = TF_S_OK then begin
      AbsLimb:= Abs(Limb);
      if arrMulLimb(@A.FLimbs, AbsLimb, @Tmp.FLimbs, UsedA)
        then Tmp.FUsed:= UsedA + 1
        else Tmp.FUsed:= UsedA;

      if A.FSign xor Integer(Limb) < 0 then
        Tmp.FSign:= -1;

      tfFreeInstance(R);  //if (R <> nil) then TtfRecord.Release(R);
      R:= Tmp;
    end;
  end;
end;
(*
class function TBigNumber.MulIntLimbU(A: PBigNumber; Limb: TIntLimb; var R: PBigNumber): HResult;
var
  Tmp: PBigNumber;
  UsedA: Cardinal;
  AbsLimb: TLimb;

begin
  if (Limb = 0) then begin
    if (R <> nil) then TtfRecord.Release((R);
    R:= @BigNumZero;
    Result:= TFL_S_OK;
    Exit;
  end
  else if (Limb > 0) then begin
    UsedA:= A.FUsed;
    Result:= AllocNumber(Tmp, UsedA + 1);
    if Result = TFL_S_OK then begin
      AbsLimb:= Abs(Limb);
      if arrMulLimb(@A.FLimbs, AbsLimb, @Tmp.FLimbs, UsedA)
        then Tmp.FUsed:= UsedA + 1
        else Tmp.FUsed:= UsedA;
      if (R <> nil) then TtfRecord.Release((R);
      R:= Tmp;
    end;
  end
  else                          // Limb < 0
    Result:= TFL_E_INVALIDARG;
end;
*)

class function TBigNumber.MulLimb(A: PBigNumber; Limb: TLimb; var R: PBigNumber): TF_RESULT;
var
  Tmp: PBigNumber;
  UsedA: Cardinal;

begin
  if (Limb = 0) then begin
    tfFreeInstance(R);  //if (R <> nil) then TtfRecord.Release(R);
    R:= @BigNumZero;
    Result:= TF_S_OK;
  end
  else begin              // Limb <> 0
    UsedA:= A.FUsed;
    Result:= AllocNumber(Tmp, UsedA + 1);
    if Result = TF_S_OK then begin

      if arrMulLimb(@A.FLimbs, Limb, @Tmp.FLimbs, UsedA)
        then Tmp.FUsed:= UsedA + 1
        else Tmp.FUsed:= UsedA;

      Tmp.FSign:= A.FSign;

      tfFreeInstance(R);  //if (R <> nil) then TtfRecord.Release(R);
      R:= Tmp;
    end;
  end;
end;

class function TBigNumber.MulLimbU(A: PBigNumber; Limb: TLimb; var R: PBigNumber): TF_RESULT;
var
  Tmp: PBigNumber;
  UsedA: Cardinal;

begin
  if (Limb = 0) then begin
    tfFreeInstance(R);  //if (R <> nil) then TtfRecord.Release(R);
    R:= @BigNumZero;
    Result:= TF_S_OK;
  end
  else begin              // Limb <> 0
    UsedA:= A.FUsed;
    Result:= AllocNumber(Tmp, UsedA + 1);
    if Result = TF_S_OK then begin

      if arrMulLimb(@A.FLimbs, Limb, @Tmp.FLimbs, UsedA)
        then Tmp.FUsed:= UsedA + 1
        else Tmp.FUsed:= UsedA;

      tfFreeInstance(R);  //if (R <> nil) then TtfRecord.Release(R);
      R:= Tmp;
    end;
  end;
end;

// Q:= A div Limb, R:= A mod Limb
class function TBigNumber.DivRemLimb(A: PBigNumber; Limb: TLimb;
                                     var Q, R: PBigNumber): TF_RESULT;
var
  TmpQ, TmpR: PBigNumber;
  UsedA: Cardinal;

begin
  if (Limb = 0) then begin
//    Result:= TFL_E_ZERODIVIDE;
    Result:= TF_E_INVALIDARG;
    Exit;
  end;
                          // Limb > 0
  UsedA:= A.FUsed;
  Result:= AllocNumber(TmpQ, UsedA);
  if Result <> TF_S_OK then Exit;

  Result:= AllocNumber(TmpR, 1);
  if Result <> TF_S_OK then begin
    tfReleaseInstance(TmpQ);  //TtfRecord.Release(TmpQ);
    Exit;
  end;

  if UsedA = 1 then begin
    TmpQ.FLimbs[0]:= A.FLimbs[0] div Limb;
    TmpR.FLimbs[0]:= A.FLimbs[0] mod Limb;
    if TmpQ.FLimbs[0] <> 0
      then TmpQ.FSign:= A.FSign;
  end
  else begin
    TmpR.FLimbs[0]:= arrDivModLimb(@A.FLimbs, @TmpQ.FLimbs, UsedA, Limb);
    if (TmpQ.FLimbs[UsedA - 1] = 0)
      then TmpQ.FUsed:= UsedA - 1
      else TmpQ.FUsed:= UsedA;
    TmpQ.FSign:= A.FSign;
  end;
  if TmpR.FLimbs[0] <> 0
    then TmpR.FSign:= A.FSign;
  tfFreeInstance(Q);  //if (Q <> nil) then TtfRecord.Release(Q);
  Q:= TmpQ;
  tfFreeInstance(R);  //if (R <> nil) then TtfRecord.Release(R);
  R:= TmpR;
end;

// Q:= Limb div A; R:= Limb mod A;
class function TBigNumber.DivRemLimb2(A: PBigNumber; Limb: TLimb;
                                      var Q: PBigNumber; var R: TLimb): TF_RESULT;
var
  TmpQ: PBigNumber;
  UsedA: Cardinal;

begin
  UsedA:= A.FUsed;
  if (UsedA = 1) then begin
    if (A.FLimbs[0] = 0) then begin
//      Result:= TFL_E_ZERODIVIDE;
      Result:= TF_E_INVALIDARG;
      Exit;
    end
    else begin
      Result:= AllocNumber(TmpQ, 1);
      if Result <> TF_S_OK then Exit;
      TmpQ.FLimbs[0]:= Limb div A.FLimbs[0];
      if TmpQ.FLimbs[0] <> 0
        then TmpQ.FSign:= A.FSign;
      R:= Limb mod A.FLimbs[0];
    end
  end
  else begin
    Result:= AllocNumber(TmpQ, UsedA);
    if Result <> TF_S_OK then Exit;
    TmpQ.FLimbs[0]:= 0;
    R:= Limb;
  end;
  tfFreeInstance(Q);  //if (Q <> nil) then TtfRecord.Release(Q);
  Q:= TmpQ;
end;

class function TBigNumber.DivRemLimbU(A: PBigNumber; Limb: TLimb;
                                      var Q: PBigNumber; var R: TLimb): TF_RESULT;
var
  Tmp: PBigNumber;
  UsedA: Cardinal;

begin
  if (Limb = 0) then begin
//    Result:= TFL_E_ZERODIVIDE;
    Result:= TF_E_INVALIDARG;
    Exit;
  end;
                          // Limb > 0
  UsedA:= A.FUsed;
  Result:= AllocNumber(Tmp, UsedA);
  if Result = TF_S_OK then begin
    if UsedA = 1 then begin
      Tmp.FLimbs[0]:= A.FLimbs[0] div Limb;
      R:= A.FLimbs[0] mod Limb;
    end
    else begin
      R:= arrDivModLimb(@A.FLimbs, @Tmp.FLimbs, UsedA, Limb);
      if (Tmp.FLimbs[UsedA - 1] = 0)
        then Tmp.FUsed:= UsedA - 1
        else Tmp.FUsed:= UsedA;
    end;
    tfFreeInstance(Q);  //if (Q <> nil) then TtfRecord.Release(Q);
    Q:= Tmp;
  end;
end;

// Q:= Limb div A; R:= Limb mod A;
class function TBigNumber.DivRemLimbU2(A: PBigNumber; Limb: TLimb;
                                      var Q: TLimb; var R: TLimb): TF_RESULT;
begin
  if (A.FUsed = 1) then begin
    if (A.FLimbs[0] = 0) then begin
//      Result:= TFL_E_ZERODIVIDE;
      Result:= TF_E_INVALIDARG;
      Exit;
    end
    else begin
      Q:= Limb div A.FLimbs[0];
      R:= Limb mod A.FLimbs[0];
    end
  end
  else begin
    Q:= 0;
    R:= Limb;
  end;
  Result:= TF_S_OK;
end;

class function TBigNumber.DivRemIntLimb(A: PBigNumber; Limb: TIntLimb;
                                       var Q: PBigNumber; var R: TIntLimb): TF_RESULT;
var
  Tmp: PBigNumber;
  UsedA: Cardinal;

begin
  if (Limb = 0) then begin
//    Result:= TFL_E_ZERODIVIDE;
    Result:= TF_E_INVALIDARG;
    Exit;
  end;
                          // Limb > 0
  UsedA:= A.FUsed;
  Result:= AllocNumber(Tmp, UsedA);
  if Result = TF_S_OK then begin

    if UsedA = 1 then begin
      Tmp.FLimbs[0]:= A.FLimbs[0] div TLimb(Abs(Limb));
      R:= A.FLimbs[0] mod TLimb(Abs(Limb));
    end
    else begin
      R:= arrDivModLimb(@A.FLimbs, @Tmp.FLimbs, UsedA, TLimb(Abs(Limb)));
      if (Tmp.FLimbs[UsedA - 1] = 0)
        then Tmp.FUsed:= UsedA - 1
        else Tmp.FUsed:= UsedA;
    end;

    if A.FSign xor Integer(Limb) < 0 then
// dividend and divisor have opposite sign
      if (Tmp.FUsed > 1) or (Tmp.FLimbs[0] <> 0) then Tmp.FSign:= -1;

// remainder has the same sign as dividend if nonzero
    if (A.FSign < 0) then R:= -R;

    tfFreeInstance(Q);  //if (Q <> nil) then TtfRecord.Release(Q);
    Q:= Tmp;
  end;
end;

// Q:= Limb div A, R:= Limb mod A
class function TBigNumber.DivRemIntLimb2(A: PBigNumber; Limb: TIntLimb;
                                        var Q: TIntLimb; var R: TIntLimb): TF_RESULT;
begin
  if (A.FUsed = 1) then begin
    if (A.FLimbs[0] = 0) then begin
//      Result:= TFL_E_ZERODIVIDE;
      Result:= TF_E_INVALIDARG;
      Exit;
    end
    else begin
      Q:= TLimb(Abs(Limb)) div A.FLimbs[0];
      R:= TLimb(Abs(Limb)) mod A.FLimbs[0];

// -5 div 2 = -2, -5 mod 2 = -1
//  5 div -2 = -2, 5 mod -2 = 1
// -5 div -2 = 2, -5 mod -2 = -1

// remainder has the same sign as dividend
      if Limb < 0 then
        R:= -R;

      if Integer(Limb) xor A.FSign < 0 then
        Q:= -Q;
    end;
  end
  else begin
    Q:= 0;
    R:= Limb;
  end;
  Result:= TF_S_OK;
end;

class procedure TBigNumber.Normalize(Inst: PBigNumber);
var
  Used: Cardinal;

begin
  Used:= Inst.FUsed;
  while (Used > 0) and (Inst.FLimbs[Used - 1] = 0) do
    Dec(Used);
  if Used = 0 then begin
    Inst.FUsed:= 1;
    Inst.FSign:= 0;     // to avoid negative zero
  end
  else Inst.FUsed:= Used;
end;

// OpenSSL: BN_num_bits.
class function TBigNumber.NumBits(A: PBigNumber): Integer;
var
  N: Integer;

begin
  N:= A.FUsed - 1;
  Result:= N * SizeOf(TLimb) * 8 + SeniorBit(A.FLimbs[N]);
end;

// OpenSSL: BN_set_bit expands the number A if necessary, SetBit not.
class function TBigNumber.SetBit(A: PBigNumber; Shift: Cardinal): TF_RESULT;
var
  N: Integer;

begin
  if Shift >= A.FUsed * TLimbInfo.BitSize then begin
    Result:= TF_E_INVALIDARG;
    Exit;
  end;
  N:= Shift shr TLimbInfo.BitShift;
  A.FLimbs[N]:= A.FLimbs[N] or (1 shl (Shift - N shl TLimbInfo.BitShift));
  Result:= TF_S_OK;
end;

class function TBigNumber.MaskBits(A: PBigNumber; Shift: Cardinal): TF_RESULT;
var
  N: Integer;
  LimbShift: Integer;

begin
  if Shift >= A.FUsed * TLimbInfo.BitSize then begin
    Result:= TF_S_FALSE;
    Exit;
  end;
  N:= Shift shr TLimbInfo.BitShift;
  LimbShift:= Shift and TLimbInfo.BitShiftMask;
  if LimbShift = 0 then begin
    A.FUsed:= N;
  end
  else begin
    A.FLimbs[N]:= A.FLimbs[N] and
      (TLimbInfo.MaxLimb shr (TLimbInfo.BitSize - LimbShift));
//      (TLimbInfo.MaxLimb shr (TLimbInfo.BitSize - (Shift - N shl TLimbInfo.BitShift)));
    A.FUsed:= N + 1;
  end;
  Normalize(A);
  Result:= TF_S_OK;
end;

class function TBigNumber.AndNumbers(A, B: PBigNumber; var R: PBigNumber): TF_RESULT;
var
  UsedA, UsedB, UsedR: Cardinal;
  Tmp: PBigNumber;

begin
  UsedA:= A.FUsed;
  UsedB:= B.FUsed;
  if A.FSign >= 0 then begin
    if B.FSign >= 0 then begin
      if UsedA >= UsedB
        then UsedR:= UsedB
        else UsedR:= UsedA;
      Result:= AllocNumber(Tmp, UsedR);
      if Result = TF_S_OK then
        arrAnd(@A.FLimbs, @B.FLimbs, @Tmp.FLimbs, UsedR);
    end
    else begin
      UsedR:= UsedA;
      Result:= AllocNumber(Tmp, UsedR);
      if Result = TF_S_OK then
        arrAndTwoCompl(@A.FLimbs, @B.FLimbs, @Tmp.FLimbs, UsedA, UsedB);
    end
  end
  else begin
    if B.FSign >= 0 then begin
      UsedR:= UsedB;
      Result:= AllocNumber(Tmp, UsedR);
      if Result = TF_S_OK then
        arrAndTwoCompl(@B.FLimbs, @A.FLimbs, @Tmp.FLimbs, UsedB, UsedA);
    end
    else begin
      if UsedA >= UsedB then begin
        UsedR:= UsedA;
        Result:= AllocNumber(Tmp, UsedR + 1);
        if Result = TF_S_OK then begin
          if arrAndTwoCompl2(@A.FLimbs, @B.FLimbs, @Tmp.FLimbs, UsedA, UsedB)
            then Inc(UsedR);
        end;
      end
      else begin
        UsedR:= UsedB;
        Result:= AllocNumber(Tmp, UsedR + 1);
        if Result = TF_S_OK then begin
          if arrAndTwoCompl2(@B.FLimbs, @A.FLimbs, @Tmp.FLimbs, UsedB, UsedA)
            then Inc(UsedR);
        end;
      end;
      Tmp.FSign:= -1;
    end;
  end;
  if Result = TF_S_OK then begin
    Tmp.FUsed:= UsedR;
    Normalize(Tmp);
    tfFreeInstance(R);  //if R <> nil then TtfRecord.Release(R);
    R:= Tmp;
  end;
end;

class function TBigNumber.AndNumbersU(A, B: PBigNumber; var R: PBigNumber): TF_RESULT;
var
  UsedA, UsedB, UsedR: Cardinal;
  Tmp: PBigNumber;

begin
  UsedA:= A.FUsed;
  UsedB:= B.FUsed;
  if UsedA >= UsedB
    then UsedR:= UsedB
    else UsedR:= UsedA;
  Result:= AllocNumber(Tmp, UsedR);
  if Result = TF_S_OK then begin
    arrAnd(@A.FLimbs, @B.FLimbs, @Tmp.FLimbs, UsedR);
    Tmp.FUsed:= UsedR;
    Normalize(Tmp);
    tfFreeInstance(R);  //if R <> nil then TtfRecord.Release(R);
    R:= Tmp;
  end;
end;

class function TBigNumber.OrNumbers(A, B: PBigNumber;
  var R: PBigNumber): TF_RESULT;
var
  UsedA, UsedB, UsedR: Cardinal;
  Tmp: PBigNumber;

begin
  UsedA:= A.FUsed;
  UsedB:= B.FUsed;

  if A.FSign >= 0 then begin
    if B.FSign >= 0 then begin
                                      // A >= 0, B >= 0
      if UsedA >= UsedB
        then UsedR:= UsedA
        else UsedR:= UsedB;
      Result:= AllocNumber(Tmp, UsedR);
      if Result = TF_S_OK then begin
        arrOr(@A.FLimbs, @B.FLimbs, @Tmp.FLimbs, UsedA, UsedB);
      end;
    end
    else begin
                                      // A >= 0, B < 0
      UsedR:= UsedB;
      Result:= AllocNumber(Tmp, UsedR);
      if Result = TF_S_OK then begin
        arrOrTwoCompl(@A.FLimbs, @B.FLimbs, @Tmp.FLimbs, UsedA, UsedB);
        Tmp.FSign:= -1;
      end;
    end
  end
  else begin
    if B.FSign >= 0 then begin
                                      // A < 0, B >= 0
      UsedR:= UsedA;
      Result:= AllocNumber(Tmp, UsedR);
      if Result = TF_S_OK then begin
        arrOrTwoCompl(@B.FLimbs, @A.FLimbs, @Tmp.FLimbs, UsedB, UsedA);
        Tmp.FSign:= -1;
      end;
    end
    else begin
                                      // A < 0, B < 0
      if UsedA >= UsedB
        then UsedR:= UsedB
        else UsedR:= UsedA;
      Result:= AllocNumber(Tmp, UsedR);
      if Result = TF_S_OK then begin
        arrOrTwoCompl2(@A.FLimbs, @B.FLimbs, @Tmp.FLimbs, UsedA, UsedB);
        Tmp.FSign:= -1;
      end
    end;
  end;
  if Result = TF_S_OK then begin
    Tmp.FUsed:= UsedR;
    Normalize(Tmp);
    tfFreeInstance(R);  //if R <> nil then TtfRecord.Release(R);
    R:= Tmp;
  end;
end;

class function TBigNumber.OrNumbersU(A, B: PBigNumber; var R: PBigNumber): TF_RESULT;
var
  UsedA, UsedB: Cardinal;
  Tmp: PBigNumber;

begin
  UsedA:= A.FUsed;
  UsedB:= B.FUsed;
  if UsedA >= UsedB then begin
    Result:= AllocNumber(Tmp, UsedA);
    if Result = TF_S_OK then begin
      arrOr(@A.FLimbs, @B.FLimbs, @Tmp.FLimbs, UsedA, UsedB);
      Tmp.FUsed:= UsedA;
      tfFreeInstance(R);  //if R <> nil then TtfRecord.Release(R);
      R:= Tmp;
    end;
  end
  else begin
    Result:= AllocNumber(Tmp, UsedB);
    if Result = TF_S_OK then begin
      arrOr(@B.FLimbs, @A.FLimbs, @Tmp.FLimbs, UsedB, UsedA);
      Tmp.FUsed:= UsedB;
      tfFreeInstance(R);  //if R <> nil then TtfRecord.Release(R);
      R:= Tmp;
    end;
  end;
end;

class function TBigNumber.XorNumbers(A, B: PBigNumber; var R: PBigNumber): TF_RESULT;
var
  UsedA, UsedB, UsedR: Cardinal;
  Tmp: PBigNumber;

begin
  UsedA:= A.FUsed;
  UsedB:= B.FUsed;

  if A.FSign >= 0 then begin
    if B.FSign >= 0 then begin
                                      // A >= 0, B >= 0
      if UsedA >= UsedB
        then UsedR:= UsedA
        else UsedR:= UsedB;
      Result:= AllocNumber(Tmp, UsedR);
      if Result = TF_S_OK then begin
        arrXor(@A.FLimbs, @B.FLimbs, @Tmp.FLimbs, UsedA, UsedB);
      end;
    end
    else begin
                                      // A >= 0, B < 0
      if UsedA >= UsedB
        then UsedR:= UsedA
        else UsedR:= UsedB;
      Result:= AllocNumber(Tmp, UsedR);
      if Result = TF_S_OK then begin
        arrXorTwoCompl(@A.FLimbs, @B.FLimbs, @Tmp.FLimbs, UsedA, UsedB);
        Tmp.FSign:= -1;
      end;
    end
  end
  else begin
    if B.FSign >= 0 then begin
                                      // A < 0, B >= 0
      if UsedA >= UsedB
        then UsedR:= UsedA
        else UsedR:= UsedB;
      Result:= AllocNumber(Tmp, UsedR);
      if Result = TF_S_OK then begin
        arrXorTwoCompl(@B.FLimbs, @A.FLimbs, @Tmp.FLimbs, UsedB, UsedA);
        Tmp.FSign:= -1;
      end;
    end
    else begin
                                      // A < 0, B < 0
      if UsedA >= UsedB
        then UsedR:= UsedA
        else UsedR:= UsedB;
      Result:= AllocNumber(Tmp, UsedR);
      if Result = TF_S_OK then begin
        arrXorTwoCompl2(@A.FLimbs, @B.FLimbs, @Tmp.FLimbs, UsedA, UsedB);
      end
    end;
  end;
  if Result = TF_S_OK then begin
    Tmp.FUsed:= UsedR;
    Normalize(Tmp);
    tfFreeInstance(R);  //if R <> nil then TtfRecord.Release(R);
    R:= Tmp;
  end;
end;

(*
  float power(float x, unsigned int n) {
    float aux = 1.0;
    while (n > 0) {
      if (n & 1) {    \\ odd?
        aux *= x;
        if (n == 1) return aux;
      }
      x *= x;
      n /= 2;
    }
    return aux;
  }
*)

class function TBigNumber.Pow(A: PBigNumber; APower: Cardinal; var R: PBigNumber): TF_RESULT;
var
  Tmp, TmpR: PBigNumber;

begin
  if APower = 0 then begin
    tfFreeInstance(R);  //if R <> nil then TtfRecord.Release(R);
//    if A.IsZero then R:= @BigNumZero
//    else R:= @BigNumOne;
    R:= @BigNumOne;
    Result:= TF_S_OK;
    Exit;
  end;

  TmpR:= @BigNumOne;
  Tmp:= A;
  tfAddrefInstance(Tmp);  //TtfRecord.AddRef(Tmp);

  Result:= TF_S_OK;
  while APower > 0 do begin
    if Odd(APower) then begin
      Result:= MulNumbers(Tmp, TmpR, TmpR);
      if Result <> TF_S_OK then Break;
      if APower = 1 then Break;
    end;
    Result:= MulNumbers(Tmp, Tmp, Tmp);
    if Result <> TF_S_OK then Break;
    APower:= APower shr 1;
  end;
  if Result = TF_S_OK then begin
    tfFreeInstance(R);  //if (R <> nil) then TtfRecord.Release(R);
    R:= TmpR;
  end
  else
    tfReleaseInstance(TmpR);  //TtfRecord.Release(TmpR);
  tfReleaseInstance(Tmp);  //TtfRecord.Release(Tmp);
end;

class function TBigNumber.PowU(A: PBigNumber; APower: Cardinal; var R: PBigNumber): TF_RESULT;
var
  Tmp, TmpR: PBigNumber;

begin
  if APower = 0 then begin
    tfFreeInstance(R);  //if R <> nil then TtfRecord.Release(R);
//    if A.IsZero then R:= @BigNumZero
//    else R:= @BigNumOne;
    R:= @BigNumOne;
    Result:= TF_S_OK;
    Exit;
  end;

  TmpR:= @BigNumOne;
  Tmp:= A;
  tfAddrefInstance(Tmp);  // TtfRecord.AddRef(Tmp);

  Result:= TF_S_OK;
  while APower > 0 do begin
    if Odd(APower) then begin
      Result:= MulNumbersU(Tmp, TmpR, TmpR);
      if Result <> TF_S_OK then Break;
      if APower = 1 then Break;
    end;
    Result:= MulNumbersU(Tmp, Tmp, Tmp);
    if Result <> TF_S_OK then Break;
    APower:= APower shr 1;
  end;
  if Result = TF_S_OK then begin
    tfFreeInstance(R);  //if (R <> nil) then TtfRecord.Release(R);
    R:= TmpR;
  end
  else
    tfReleaseInstance(TmpR);  //TtfRecord.Release(TmpR);
  tfReleaseInstance(Tmp);    //TtfRecord.Release(Tmp);
end;

class function TBigNumber.ModPow(BaseValue, ExpValue, Modulus: PBigNumber; var R: PBigNumber): TF_RESULT;
var
  Tmp, TmpR, Q: PBigNumber;
  Used, I: Cardinal;
  Limb: TLimb;
  P, Sentinel: PLimb;

begin
                                  // ExpValue = 0
  if ExpValue.IsZero then begin
    tfFreeInstance(R);  //if R <> nil then TtfRecord.Release(R);
//    if BaseValue.IsZero then R:= @BigNumZero
//    else
    R:= @BigNumOne;
    Result:= TF_S_OK;
    Exit;
  end;
                                  // Assert( ExpValue > 0 )
  TmpR:= @BigNumOne;
  Tmp:= BaseValue;
  tfAddrefInstance(Tmp);  //TtfRecord.Addref(Tmp);
  Q:= nil;

  Used:= ExpValue.FUsed;
  P:= @ExpValue.FLimbs;
  Sentinel:= P + Used;
  Result:= TF_S_OK;
  while P <> Sentinel do begin
    I:= 0;
    Limb:= P^;
    while Limb > 0 do begin
      if Odd(Limb) then begin
                                              // TmpR:= Tmp * TmpR
        Result:= MulNumbers(Tmp, TmpR, TmpR);
        if Result = S_OK then
                                              // TmpR:= TmpR mod Modulo
          Result:= DivRemNumbersU(TmpR, Modulus, Q, TmpR);
        if Result <> TF_S_OK then begin
          tfReleaseInstance(Tmp);  //TtfRecord.Release(Tmp);
          tfReleaseInstance(TmpR);  //TtfRecord.Release(TmpR);
          tfFreeInstance(Q);       //if Q <> nil then TtfRecord.Release(Q);
          Exit;
        end;
        if Limb = 1 then Break;
      end;
      Result:= MulNumbers(Tmp, Tmp, Tmp);
      if Result = TF_S_OK then
        Result:= DivRemNumbersU(Tmp, Modulus, Q, Tmp);
      if Result <> TF_S_OK then begin
        tfReleaseInstance(Tmp);  //TtfRecord.Release(Tmp);
        tfReleaseInstance(TmpR);  //TtfRecord.Release(TmpR);
        tfFreeInstance(Q);       //if Q <> nil then TtfRecord.Release(Q);
        Exit;
      end;
      Limb:= Limb shr 1;
      Inc(I);
    end;
    Inc(P);
    if P = Sentinel then Break;
    while I < TLimbInfo.BitSize do begin
      Result:= MulNumbers(Tmp, Tmp, Tmp);
      if Result = TF_S_OK then
        Result:= DivRemNumbersU(Tmp, Modulus, Q, Tmp);
      if Result <> TF_S_OK then begin
        tfReleaseInstance(Tmp);  //TtfRecord.Release(Tmp);
        tfReleaseInstance(TmpR);  //TtfRecord.Release(TmpR);
        tfFreeInstance(Q);       //if Q <> nil then TtfRecord.Release(Q);
        Exit;
      end;
      Inc(I);
    end;
  end;
  tfReleaseInstance(Tmp);  //TtfRecord.Release(Tmp);
  tfFreeInstance(Q);       //if Q <> nil then TtfRecord.Release(Q);
  tfFreeInstance(R);       //if R <> nil then TtfRecord.Release(R);
  R:= TmpR;
end;

procedure TBigNumber.Free;
begin
  tfFreeInstance(@Self);   //  if @Self <> nil then TtfRecord.Release(@Self);
end;

class procedure TBigNumber.FreeAndNil(var Inst: PBigNumber);
var
  Tmp: PBigNumber;

begin
  if Inst <> nil then begin
    Tmp:= Inst;
    Inst:= nil;
    tfReleaseInstance(Tmp);  //TtfRecord.Release(Tmp);
  end;
end;

// ------------------------------------------------------------- //

function BigNumberPowerOfTwo(var A: PBigNumber; APower: Cardinal): TF_RESULT;
var
  Tmp: PBigNumber;

begin
  Result:= TBigNumber.AllocPowerOfTwo(Tmp, APower);
  if Result = TF_S_OK then begin
    tfFreeInstance(A);  //if (A <> nil) then TtfRecord.Release(A);
    A:= Tmp;
  end;
end;

function BigNumberFromLimb(var A: PBigNumber; Value: TLimb): TF_RESULT;
var
  Tmp: PBigNumber;

begin
  Result:= TBigNumber.AllocNumber(Tmp, 1);
  if Result = TF_S_OK then begin
    Tmp.FLimbs[0]:= Value;
    tfFreeInstance(A);  //if (A <> nil) then TtfRecord.Release(A);
    A:= Tmp;
  end;
end;

function BigNumberFromIntLimb(var A: PBigNumber; Value: TIntLimb): TF_RESULT;
var
  Tmp: PBigNumber;

begin
  Result:= TBigNumber.AllocNumber(Tmp, 1);
  if Result = TF_S_OK then begin
    Tmp.FLimbs[0]:= Abs(Value);
    if Value < 0 then Tmp.FSign:= -1;
    tfFreeInstance(A);  //if (A <> nil) then TtfRecord.Release(A);
    A:= Tmp;
  end;
end;

function BigNumberFromDblLimb(var A: PBigNumber; Value: TDLimb): TF_RESULT;
type
  TLimb2 = array[0..1] of TLimb;
  PLimb2 = ^TLimb2;

var
  Tmp: PBigNumber;
  P: PLimb2;

begin
  Result:= TBigNumber.AllocNumber(Tmp, 2);
  if Result = TF_S_OK then begin
    P:= @Tmp.FLimbs;
    PDLimb(P)^:= Value;
    if P[1] <> 0 then Tmp.FUsed:= 2;
    tfFreeInstance(A);  //if (A <> nil) then TtfRecord.Release(A);
    A:= Tmp;
  end;
end;

function BigNumberFromDblIntLimb(var A: PBigNumber; Value: TDIntLimb): TF_RESULT;
type
  TLimb2 = array[0..1] of TLimb;
  PLimb2 = ^TLimb2;

var
  Tmp: PBigNumber;
  P: PLimb2;

begin
  Result:= TBigNumber.AllocNumber(Tmp, 2);
  if Result = TF_S_OK then begin
    P:= @Tmp.FLimbs;
    PDLimb(P)^:= Abs(Value);
    if P[1] <> 0 then Tmp.FUsed:= 2;
    if Value < 0 then Tmp.FSign:= -1;
    tfFreeInstance(A);  //if (A <> nil) then TtfRecord.Release(A);
    A:= Tmp;
  end;
end;

(*
function BigNumberFromInteger(var A: PBigNumber; Value: Integer): HResult;
const
  DataSize = SizeOf(Integer) div SizeOf(TLimb);

var
  Tmp: PBigNumber;
{$IF DataSize <> 1}
  TmpValue: Integer;
{$IFEND}

begin
{$IF DataSize = 0}
  Result:= TFL_E_NOTIMPL;
{$ELSE}
  Result:= TBigNumber.AllocNumber(Tmp, DataSize);
  if Result <> TFL_S_OK then Exit;
  {$IF DataSize = 1}
    Tmp.FLimbs[0]:= Abs(Value);
  {$ELSE}
    TmpValue:= Abs(Value);
    Move(TmpValue, Tmp.FLimbs, SizeOf(Integer));
    Tmp.FUsed:= DataSize;
    TBigNumber.Normalize(Tmp);
  {$IFEND}
  if Value < 0 then Tmp.FSign:= -1;
  if (A <> nil) then TBigNumber.TtfRecord.Release((A);
  A:= Tmp;
{$IFEND}
end;
*)
function BigNumberFromPByte(var A: PBigNumber;
               P: PByte; L: Integer; AllowNegative: Boolean): TF_RESULT;
var
  SeniorByte: Byte;
  Tmp: PBigNumber;
  Used: Cardinal;
  I: Integer;

begin
  Assert(L > 0);
  SeniorByte:= P[L-1];
  if SeniorByte and $80 = 0 then begin
    if SeniorByte = 0 then Dec(L);
    if L = 0 then begin
      tfFreeInstance(A);  //if A <> nil then TtfRecord.Release(A);
      A:= @BigNumZero;
      Result:= TF_S_OK;
    end
    else begin
      Used:= (L + SizeOf(TLimb) - 1) div SizeOf(TLimb);
      Result:= TBigNumber.AllocNumber(Tmp, Used);
      if Result = TF_S_OK then begin
        Tmp.FLimbs[Used - 1]:= 0;
        Move(P^, Tmp.FLimbs, L);
        Tmp.FUsed:= Used;
        tfFreeInstance(A);  //if A <> nil then TtfRecord.Release(A);
        A:= Tmp;
      end;
    end;
  end
  else if AllowNegative then begin { out A < 0 }
    if SeniorByte = $FF then Dec(L);
    if L = 0 then begin
      tfFreeInstance(A);  //if A <> nil then TtfRecord.Release(A);
      A:= @BigNumMinusOne;
      Result:= TF_S_OK;
      Exit;
    end
    else begin
      Used:= (L + SizeOf(TLimb) - 1) div SizeOf(TLimb);
      Result:= TBigNumber.AllocNumber(Tmp, Used);
      if Result = TF_S_OK then begin
        Tmp.FLimbs[Used - 1]:= TLimbInfo.MaxLimb;
        Move(P^, Tmp.FLimbs, L);
        Tmp.FUsed:= Used;
        Tmp.FSign:= -1;
        for I:= 0 to Used - 1 do
          Tmp.FLimbs[I]:= not Tmp.FLimbs[I];
        arrSelfAddLimb(@Tmp^.FLimbs, 1, Used);
        tfFreeInstance(A);  //if A <> nil then TtfRecord.Release(A);
        A:= Tmp;
      end;
    end;
  end
  else
    Result:= TF_E_INVALIDARG;
end;

(*
function GetChar(P: PByte; Index, Size: Integer): Cardinal;
begin
  Inc(P, Index * Size);
  if Size = 2 then Result:= PWord(P)^
  else if Size = 4 then Result:= PUInt32(P)^
  else Result:= P^;
end;
var
  Tmp: Cardinal;
  I: Integer;

  Result:= P^;
  I:= 1;
  while I < Size do begin
    Inc(P);
    Tmp:= P^;
    Result:= Result or (Tmp shl (I * 8));
    Inc(I);
  end;
end;
*)

type
  TGetChar = function(P: Pointer; Index: Integer): Cardinal;

function GetChar1(P: Pointer; Index: Integer): Cardinal;
begin
  Result:= (PByte(P) + Index)^;
end;

function GetChar2(P: Pointer; Index: Integer): Cardinal;
begin
  Result:= (PWord(P) + Index)^;
end;

function GetChar4(P: Pointer; Index: Integer): Cardinal;
begin
  Result:= (PUInt32(P) + Index)^;
end;

const
{$IF SizeOf(TLimb) = 8}         // 16 hex digits per uint64 limb
   LIMB_SHIFT = 4;
{$ELSEIF SizeOf(TLimb) = 4}     // 8 hex digits per uint32 limb
   LIMB_SHIFT = 3;
{$ELSEIF SizeOf(TLimb) = 2}     // 4 hex digits per word limb
   LIMB_SHIFT = 2;
{$ELSE}                         // 2 hex digits per byte limb
   LIMB_SHIFT = 1;
{$IFEND}

function BigNumberFromPCharHex(var A: PBigNumber; P: PByte; L: Integer;
            GetChar: TGetChar; AllowNegative, TwoCompl: Boolean): TF_RESULT;
var
  IsMinus: Boolean;
  I, N: Integer;
  Limb: TLimb;
  Carry: Boolean;
  Digit: Cardinal;
  Ch: Cardinal;
  LimbsRequired: Cardinal;
  Tmp: PBigNumber;

begin
  I:= 0;
  if L > 0 then begin
                              // S is zero-based PChar
    if TwoCompl then begin
      IsMinus:= (GetChar(P, 0) >= Ord('8'));
      TwoCompl:= TwoCompl and IsMinus;
    end
    else begin
//      IsMinus:= GetChar(P, 0) = Ord('-');
//      if IsMinus then Inc(I);
      IsMinus:= False;
    end;
  end;

  if (L <= I) or (IsMinus and not AllowNegative) then begin
    Result:= TF_E_INVALIDARG;
    Exit;
  end;

  N:= L - I;                // number of hex digits;
                            //   1 limb holds 2 * SizeOf(TLimb) hex digits

  LimbsRequired:= (N + 2 * SizeOf(TLimb) - 1) shr LIMB_SHIFT;
  Result:= TBigNumber.AllocNumber(Tmp, LimbsRequired);
  if Result <> TF_S_OK then Exit;

  N:= 0;
  Limb:= 0;
  Carry:= True;

  repeat
                    // moving from end of string
    Ch:= GetChar(P, L - N - 1);
    case Ch of
        Ord('0')..Ord('9'): Digit:= Ch - Ord('0');
        Ord('A')..Ord('F'): Digit:= 10 + Ch - Ord('A');
        Ord('a')..Ord('f'): Digit:= 10 + Ch - Ord('a');
    else
        tfReleaseInstance(Tmp);  // TtfRecord.Release(Tmp);
        Result:= TF_E_INVALIDARG;
        Exit;
    end;
                      // shift digit to its position in a limb
    Limb:= Limb + (Digit shl ((N and (2 * SizeOf(TLimb) - 1)) shl 2));

    Inc(N);
    if N and (2 * SizeOf(TLimb) - 1) = 0 then begin

      if TwoCompl then begin
        Limb:= not Limb;
        if Carry then begin
          Inc(Limb);
          Carry:= Limb = 0;
        end;
      end;

      Tmp^.FLimbs[N shr LIMB_SHIFT - 1]:= Limb;
      Limb:= 0;
    end;
  until I + N >= L;

  if N and (2 * SizeOf(TLimb) - 1) <> 0 then begin
    if TwoCompl then begin
      Limb:= TLimb((-1) shl ((N and (2 * SizeOf(TLimb) - 1)) * 4)) or Limb;
      Limb:= not Limb;
      if Carry then Inc(Limb);
    end;
    Tmp^.FLimbs[N shr LIMB_SHIFT]:= Limb;
  end;

  N:= (N + 2 * SizeOf(TLimb) - 1) shr LIMB_SHIFT;
  Tmp^.FUsed:= N;

  TBigNumber.Normalize(Tmp);
  if IsMinus and ((Tmp.FUsed > 1) or (Tmp.FLimbs[0] <> 0))
    then Tmp.FSign:= -1;
  tfFreeInstance(A);  //if A <> nil then TtfRecord.Release(A);
  A:= Tmp;
end;

function BigNumberFromPChar(var A: PBigNumber; P: PByte; L: Integer;
         CharSize: Integer; AllowNegative: Boolean; TwoCompl: Boolean): TF_RESULT;
var
  IsMinus, IsHex: Boolean;
  I, N: Cardinal;
  Digit: Cardinal;
  Ch: Cardinal;
  Tmp: PBigNumber;
  GetChar: TGetChar;

begin
  if L <= 0 then begin
    Result:= TF_E_INVALIDARG;
    Exit;
  end;
  case CharSize of
    1: GetChar:= GetChar1;
    2: GetChar:= GetChar2;
    4: GetChar:= GetChar4;
  else
    Result:= TF_E_INVALIDARG;
    Exit;
  end;
  IsMinus:= GetChar(P, 0) = Ord('-');
  if IsMinus then begin
    Dec(L);
    if (L <= 0) or not AllowNegative or TwoCompl then begin
      Result:= TF_E_INVALIDARG;
      Exit;
    end;
    Inc(P, CharSize);
  end;
  IsHex:= GetChar(P, 0) = Ord('$');
  if IsHex then begin
    Inc(P, CharSize);
    Dec(L);
  end
  else begin
    IsHex:= (L > 1) and (GetChar(P, 0) = Ord('0'))
                    and (GetChar(P, 1) = Ord('x'));
    if IsHex then begin
      Inc(P, 2 * CharSize);
      Dec(L, 2);
    end;
  end;
  if IsHex then begin
    Result:= BigNumberFromPCharHex(A, P, L, GetChar, AllowNegative, TwoCompl);
    if (Result = TF_S_OK) and IsMinus then begin
      if A.FSign < 0 then A.FSign:= 0
      else A.FSign:= -1;
    end;
  end
  else begin
    I:= 0;
               // number of decimal digits
               // good rational approximations from above
               //   to log2(10) / 8 are:
               //     98981 / 238370;  267 / 643;  49 / 118;  5 / 12

               // number of bytes to hold these digits
    N:= (Cardinal(L) * 49) div 118 + 1;

               // number of limbs to hold these digits
{$IF SizeOf(TLimb) > 1}
    N:= (N + SizeOf(TLimb) - 1) shr (LIMB_SHIFT - 1);
{$IFEND}

    Result:= TBigNumber.AllocNumber(Tmp, N);
    if Result <> TF_S_OK then Exit;
// Tmp = 0 here
    repeat
      Ch:= GetChar(P, I);
      case Ch of
        Ord('0')..Ord('9'): begin
          Digit:= Ch - Ord('0');
// Tmp:= Tmp * 10 + Digit;
          if arrSelfMulLimb(@Tmp^.FLimbs, 10, Tmp^.FUsed) then
            Inc(Tmp^.FUsed);
          if arrSelfAddLimb(@Tmp^.FLimbs, Digit, Tmp^.FUsed) then
            Inc(Tmp^.FUsed);
        end;
      else
        tfReleaseInstance(Tmp);  //TtfRecord.Release(Tmp);
        Result:= TF_E_INVALIDARG;
        Exit;
      end;
      Inc(I);

    until I >= L;
    if IsMinus and ((Tmp.FUsed > 1) or (Tmp.FLimbs[0] <> 0))
      then Tmp.FSign:= -1;
    tfFreeInstance(A);  //if A <> nil then TtfRecord.Release(A);
    A:= Tmp;
  end;
end;

function BigNumberAlloc(var A: PBigNumber; ASize: Integer): TF_RESULT;
var
  Tmp: PBigNumber;

begin
  Result:= TBigNumber.AllocNumber(Tmp, ASize div SizeOf(TLimb));
  if Result = TF_S_OK then begin
    tfFreeInstance(A);  //if A <> nil then TtfRecord.Release(A);
    A:= Tmp;
  end;
end;

procedure SetBigNumberZero(var A: PBigNumber);
begin
  tfFreeInstance(A);
  A:= @BigNumZero;
end;

procedure SetBigNumberOne(var A: PBigNumber);
begin
  tfFreeInstance(A);
  A:= @BigNumOne;
end;

procedure SetBigNumberMinusOne(var A: PBigNumber);
begin
  tfFreeInstance(A);
  A:= @BigNumMinusOne;
end;


(*
function BigNumberFromPWideChar(var A: PBigNumber;
               P: PWideChar; L: Cardinal; AllowNegative: Boolean): HResult;
const
{$IF SizeOf(TLimb) = 8}         // 16 hex digits per uint64 limb
   LIMB_SHIFT = 4;
{$ELSEIF SizeOf(TLimb) = 4}     // 8 hex digits per uint32 limb
   LIMB_SHIFT = 3;
{$ELSEIF SizeOf(TLimb) = 2}     // 4 hex digits per word limb
   LIMB_SHIFT = 2;
{$ELSE}                         // 2 hex digits per byte limb
   LIMB_SHIFT = 1;
{$IFEND}

var
  IsMinus: Boolean;
  I, N: Cardinal;
  Digit: Cardinal;
  Ch: Char;
  Tmp: PBigNumber;

begin
  if L <= 0 then begin
    Result:= TFL_E_INVALIDARG;
  end
  else if P[0] = '$' then begin
    Result:= TBigNumber.FromPCharHex(A, @P[1], L - 1, AllowNegative, False);
  end
  else if (L > 1) and (P[0] = '0') and (P[1] = 'x') then begin
    Result:= TBigNumber.FromPCharHex(A, @P[2], L - 2, AllowNegative, True);
  end
  else begin
    I:= 0;
    IsMinus:= P[0] = '-';
    if IsMinus then
      Inc(I);

    if L <= I then begin
      Result:= TFL_E_INVALIDARG;
      Exit;
    end;
               // number of decimal digits
    N:= (L - I);

               // good rational approximations from above
               //   to log2(10) / 8 are:
               //     98981 / 238370;  267 / 643;  49 / 118;  5 / 12

               // number of bytes to hold these digits
    N:= (N * 267) div 643 + 1;

               // number of limbs to hold these digits
{$IF SizeOf(TLimb) > 1}
    N:= (N + SizeOf(TLimb) - 1) shr (LIMB_SHIFT - 1);
{$IFEND}

    Result:= TBigNumber.AllocNumber(Tmp, N);
    if Result <> TF_S_OK then Exit;
// Tmp = 0 here
    repeat
      Ch:= P[I];
      case Ch of
        '0'..'9': begin
          Digit:= Ord(Ch) - Ord('0');
// Tmp:= Tmp * 10 + Digit;
          if arrSelfMulLimb(@Tmp^.FLimbs, 10, Tmp^.FUsed) then
            Inc(Tmp^.FUsed);
          if arrSelfAddLimb(@Tmp^.FLimbs, Digit, Tmp^.FUsed) then
            Inc(Tmp^.FUsed);
        end;
      else
        TBigNumber.TtfRecord.Release((Tmp);
        Result:= TFL_E_INVALIDARG;
        Exit;
      end;
      Inc(I);

    until I >= L;
    if IsMinus and ((Tmp.FUsed > 1) or (Tmp.FLimbs[0] <> 0))
      then Tmp.FSign:= -1;
    if A <> nil then TBigNumber.TtfRecord.Release((A);
    A:= Tmp;
  end;
end;
*)

end.

