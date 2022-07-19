{ *********************************************************** }
{ *                     TForge Library                      * }
{ *       Copyright (c) Sergey Kasandrov 1997, 2016         * }
{ *********************************************************** }

unit tfWindows;

{$I TFL.inc}

interface

uses tfTypes, Windows;

// Advapi32.dll, WinCrypt.h

const
  PROV_RSA_FULL = 1;
  CRYPT_VERIFYCONTEXT = DWORD($F0000000);

type
  HCRYPTPROV = ULONG_PTR;

function CryptAcquireContext(var phProv: HCRYPTPROV; pszContainer: LPCTSTR;
  pszProvider: LPCTSTR; dwProvType: DWORD; dwFlags: DWORD): BOOL; stdcall;
function CryptReleaseContext(hProv: HCRYPTPROV; dwFlags: DWORD): BOOL; stdcall;
function CryptGenRandom(hProv: HCRYPTPROV; dwLen: DWORD; pbBuffer: LPBYTE): BOOL; stdcall;

type
  TtfLock = record
    FMutex: THandle;
    function Acquire: TF_RESULT;
    function Resease: TF_RESULT;
  end;

// nobody knows is Windows CryptoAPI threadsafe or not;
//   TForge uses CryptLock to be on the safe side.
var
  CryptLock: TtfLock;

function GenRandom(var Buf; BufSize: Cardinal): TF_RESULT;

implementation

function CryptAcquireContext; external advapi32
  name {$IFDEF UNICODE}'CryptAcquireContextW'{$ELSE}'CryptAcquireContextA'{$ENDIF};
function CryptReleaseContext; external advapi32 name 'CryptReleaseContext';
function CryptGenRandom; external advapi32 name 'CryptGenRandom';

{$ifdef fpc}
function InterlockedCompareExchangePointer(var Target: Pointer; NewValue: Pointer; Comperand: Pointer): Pointer;
begin
{$ifdef cpu64}
  Result:= Pointer(InterlockedCompareExchange64(int64(Target), int64(NewValue), int64(Comperand)));
{$else cpu64}
  Result:= Pointer(InterlockedCompareExchange(LongInt(Target), LongInt(NewValue), LongInt(Comperand)));
{$endif cpu64}
end;
{$endif fpc}


function GenRandom(var Buf; BufSize: Cardinal): TF_RESULT;
var
  Provider: HCRYPTPROV;

begin
// TForge uses GenRandom only to get a random seed value,
//   so large BufSize values aren't needed
  if BufSize > 256 then begin
    Result:= TF_E_INVALIDARG;
    Exit;
  end;
  Result:= CryptLock.Acquire;
  if Result = TF_S_OK then begin
    if CryptAcquireContext(Provider, nil, nil,
        PROV_RSA_FULL, CRYPT_VERIFYCONTEXT) then begin

      if not CryptGenRandom(Provider, BufSize, @Buf) then begin
        Result:= TF_E_FAIL;
      end;
      CryptReleaseContext(Provider, 0);
    end
    else begin
      Result:= TF_E_FAIL;
    end;
    CryptLock.Resease;
  end;
end;

{ TtfLock }

{ Initially FMutex field contains zero; TtfLock does not provide constructor
    or method to initialize the field because
    TtfLock instances are designed to be declared as a global variables.
    ===================================================================

  On the first lock attempt, FMutex field is initialized by a non-zero value.
  On collision, each thread attempts to create a mutex and compare-and-swap it
   into place as the FMutex field. On failure to swap in the FMutex field,
   the mutex is closed.
}

function TtfLock.Acquire: TF_RESULT;
var
  Tmp: THandle;

begin
  if FMutex = 0 then begin
    Tmp:= CreateMutex(nil, False, nil);
    if InterlockedCompareExchangePointer(Pointer(FMutex), Pointer(Tmp), nil) <> nil
      then CloseHandle(Tmp);
  end;
  if WaitForSingleObject(FMutex, INFINITE) = WAIT_OBJECT_0
    then Result:= TF_S_OK
    else Result:= TF_E_UNEXPECTED;
end;

function TtfLock.Resease: TF_RESULT;
begin
  ReleaseMutex(FMutex);
  Result:= TF_S_OK;
end;

end.
