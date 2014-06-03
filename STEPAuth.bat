@ECHO OFF
set OPENSSL_CONF=.\openssl.cfg
if "%1"=="VERIFY" GOTO verify
if "%1"=="SIGN" GOTO sign

GOTO usage

:usage
echo %0 ^[VERIFY^, SIGN^]
GOTO end

:verify
if "%2"=="/?" GOTO helpverify
if "%2"=="" GOTO helpverify

StepBreak %2
if ERRORLEVEL 1 goto error

set "certificate=%2.cert"
set "signature=%2.signature"
set "signaturedec=%2.sig"
set "data=%2.tmp"
set "hash=%2.hash"
set "pub=%2.pub"

@openssl.exe x509 -pubkey -noout -in %certificate% >%pub%
@openssl enc -d -base64 -in %signature% -out %signaturedec%
openssl.exe dgst -sha256 -verify %pub% -signature %signaturedec% %data%
del %certificate% %signature% %signaturedec% %data% %hash% %pub%
GOTO end

:helpverify
echo %0 VERIFY ^<data file^>
GOTO end

:sign
IF "%2"=="" GOTO helpsign
IF "%2"=="/?" GOTO helpsign
IF "%3"=="" GOTO helpsign
IF "%4"=="" GOTO helpsign

SET "signsig=%2.sig"
SET "signsig64=%2.signature"
SET "outfile=signed_%2"
openssl dgst -sha256 -sign %3 -out %signsig% %2
openssl enc -base64 -in %signsig% |repl "\n" "\r\n" xm > %signsig64%
copy %2 %outfile% >NUL
::Print the Signature to outfile.
echo.>> %outfile%
echo SIGNATURE^;>> %outfile%
type %signsig64%>> %outfile%
echo ENDSEC^;>> %outfile%
echo.>> %outfile%
echo CERTIFICATE^;>> %outfile%
type %4>> %outfile%
echo.>> %outfile%
echo ENDSEC^;>> %outfile%

del %signsig% %signsig64%
GOTO end

:helpsign
echo %0 SIGN ^<file to sign^> ^<private key^> ^<certificate^>
GOTO end

:error
echo Program Failure^.
GOTO end

:end