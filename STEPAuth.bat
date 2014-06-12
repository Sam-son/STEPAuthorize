@ECHO OFF
setlocal 
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

set command=%~1
if "%command%"=="VERIFY" GOTO verify
if "%command%"=="verify" GOTO verify
if "%command%"=="SIGN" GOTO sign
if "%command%"=="sign" GOTO sign
if "%command%"=="CSR" GOTO csr
if "%command%"=="csr" GOTO csr
GOTO usage

:usage
echo %0 ^[CSR^, VERIFY^, SIGN^]
GOTO end

:verify
set infile=%~2
set verbose=%~3

if "%infile%"=="/?" GOTO helpverify
if "%infile%"=="" GOTO helpverify

echo Verifying signature^.^.^.
STEPSign VERIFY "%infile%" "%verbose%"
GOTO cleanup

:helpverify
echo %0 VERIFY ^<data file^>
GOTO end

:sign
set infile=%~2
set privatekey=%~3
set incert=%~4
set verbose=%~5
IF "%infile%"=="" GOTO helpsign
IF "%infile%"=="/?" GOTO helpsign
IF "%privatekey%"=="" GOTO helpsign
IF "%incert%"=="" GOTO helpsign

STEPSign SIGN "%infile%" "%privatekey%" "%incert%" %verbose%
GOTO end

:helpsign
echo %0 SIGN ^<file to sign^> ^<private key^> ^<certificate^>
GOTO end

:csr
set infile=%~2
if "%infile%"=="" GOTO helpcsr
openssl req -new -config cert.conf -out "%infile%.csr" -keyout "%infile%-private.key"
if ERRORLEVEL 1 goto error
GOTO end

:helpcsr
echo %0 CSR ^<output filename^>
GOTO end

:error
echo Program Failure^.
GOTO cleanup

:cleanup
::Check if any temporary files exist and remove them.
IF NOT "%signsig%"=="" del "%signsig%"
IF NOT "%signsig64%"=="" del "%signsig64%"
IF NOT "%strip%"=="" del "%strip%"
IF NOT "%certificate%"=="" del "%certificate%"
IF NOT "%signature%"=="" del "%signature%"
IF NOT "%signaturedec%"=="" del "%signaturedec%"
IF NOT "%data%"=="" del "%data%"
IF NOT "%pub%"=="" del "%pub%"
GOTO end

:end