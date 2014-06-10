@ECHO OFF

::Initialize all the variables we may use.
set OPENSSL_CONF=.\openssl.cfg
set "signsig="
set "signsig64="
set "strip="
set "certificate="
set "signature="
set "signaturedec="
set "data="
set "pub="

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
set "strip=%data%.stripped"
set "pub=%2.pub"
STEPStrip %data%
if ERRORLEVEL 1 goto error
openssl x509 -pubkey -noout -in %certificate% >%pub%
if ERRORLEVEL 1 goto error
openssl enc -d -base64 -in %signature% -out %signaturedec%
if ERRORLEVEL 1 goto error
openssl dgst -sha256 -verify %pub% -signature %signaturedec% %strip%

GOTO cleanup

:helpverify
echo %0 VERIFY ^<data file^>
GOTO end

:sign
IF "%2"=="" GOTO helpsign
IF "%2"=="/?" GOTO helpsign
IF "%3"=="" GOTO helpsign
IF "%4"=="" GOTO helpsign

SET "signsig64=%2.signature"
SET "outfile=signed_%2"
STEPStrip %2
if ERRORLEVEL 1 goto error

SET "strip=%2.stripped"
SET "signsig=%2.sig"
openssl dgst -sha256 -sign %3 -out %signsig% %strip%
if ERRORLEVEL 1 goto error

openssl enc -base64 -in %signsig% |repl "\n" "\r\n" xm > %signsig64%
if ERRORLEVEL 1 goto error

copy %2 %outfile% >NUL
::Print the Signature to outfile. Looks like:
::SIGNATURE;
::[bunch of lines of signature stuff]
::ENDSEC;
echo.>> %outfile%
echo SIGNATURE^;>> %outfile%
type %signsig64%>> %outfile%
echo ENDSEC^;>> %outfile%
echo.>> %outfile%
::Print Public key. Gotten right from the certificate. 
::Similar to Signature, section begins with:
::PUBLIC KEY;
echo PUBLIC KEY^;>> %outfile%
openssl x509 -pubkey -noout -in %4 |repl "\n" "\r\n" xm >> %outfile%
echo ENDSEC^;>>%outfile%
echo.>> %outfile%
::Print Certificate to file. Begins with:
::CERTIFICATE;
echo CERTIFICATE^;>> %outfile%
openssl x509 -outform pem -in %4 >> %outfile%
echo.>> %outfile%
echo ENDSEC^;>> %outfile%

::Done with everything. Delete temporary files.
GOTO cleanup

:helpsign
echo %0 SIGN ^<file to sign^> ^<private key^> ^<certificate^>
GOTO end

:error
echo Program Failure^.
GOTO cleanup

:cleanup
::Check if any temporary files exist and remove them.
IF NOT "%signsig%"=="" del %signsig%
IF NOT "%signsig64%"=="" del %signsig64%
IF NOT "%strip%"=="" del %strip%
IF NOT "%certificate%"=="" del %certificate% 
IF NOT "%signature%"=="" del %signature% 
IF NOT "%signaturedec%"=="" del %signaturedec%
IF NOT "%data%"=="" del %data%
IF NOT "%pub%"=="" del %pub%
GOTO end

:end