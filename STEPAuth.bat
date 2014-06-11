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
echo %command%
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
if "%infile%"=="/?" GOTO helpverify
if "%infile%"=="" GOTO helpverify

StepBreak "%infile%"
if ERRORLEVEL 1 goto error

set "certificate=%infile%.cert"
set "signature=%infile%.signature"
set "signaturedec=%infile%.sig"
set "data=%infile%.tmp"
set "strip=%data%.stripped"
set "pub=%infile%.pub"
STEPStrip "%data%"
if ERRORLEVEL 1 goto error
openssl x509 -pubkey -noout -in "%certificate%" >"%pub%"
IF ERRORLEVEL 1 GOTO error
::Print Subject
openssl x509 -in "%certificate%" -subject -noout -nameopt multiline
if ERRORLEVEL 1 goto error
openssl enc -d -base64 -in "%signature%" -out "%signaturedec%"
if ERRORLEVEL 1 goto error
echo.
echo.
echo Verifying certificate^.^.^.
openssl verify -CAfile root-ca.crt "%certificate%"
if ERRORLEVEL 1 goto end
echo.
echo.

echo Verifying signature^.^.^.
openssl dgst -sha256 -verify "%pub%" -signature "%signaturedec%" "%strip%"
echo.
GOTO cleanup

:helpverify
echo %0 VERIFY ^<data file^>
GOTO end

:sign
set infile=%~2
set privatekey=%~3
set incert=%~4
IF "%infile%"=="" GOTO helpsign
IF "%infile%"=="/?" GOTO helpsign
IF "%privatekey%"=="" GOTO helpsign
IF "%incert%"=="" GOTO helpsign

SET "signsig64=%infile%.signature"
SET "outfile=signed_%infile%"
STEPStrip "%infile%"
if ERRORLEVEL 1 goto error

SET "strip=%infile%.stripped"
SET "signsig=%infile%.sig"
openssl dgst -sha256 -sign "%privatekey%" -out "%signsig%" "%strip%"
if ERRORLEVEL 1 goto error

openssl enc -base64 -in "%signsig%" |repl "\n" "\r\n" xm > "%signsig64%"
if ERRORLEVEL 1 goto error

copy "%infile%" "%outfile%" >NUL
::Print the Signature to outfile. Looks like:
::SIGNATURE;
::[bunch of lines of signature stuff]
::ENDSEC;
echo.>> "%outfile%"
echo SIGNATURE^;>> "%outfile%"
type "%signsig64%">> "%outfile%"
echo ENDSEC^;>> "%outfile%"
echo.>> "%outfile%"
::Print Public key. Gotten right from the certificate. 
::Similar to Signature, section begins with:
::PUBLIC KEY;
::Skip this if -old flag isn't set.
IF NOT "%5"=="-old" GOTO printcert 
echo PUBLIC KEY^;>> "%outfile%"
openssl x509 -pubkey -noout -in "%incert%" |repl "\n" "\r\n" xm >> "%outfile%"
echo ENDSEC^;>>"%outfile%"
echo.>> "%outfile%"

:printcert
::Print Certificate to file. Begins with:
::CERTIFICATE;
echo CERTIFICATE^;>> "%outfile%"
openssl x509 -outform pem -in "%incert%" >> "%outfile%"
echo.>> "%outfile%"
echo ENDSEC^;>> "%outfile%"

::Done with everything. Delete temporary files.
GOTO cleanup

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