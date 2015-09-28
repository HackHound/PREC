# PREC
Password Recovery Class for Visual Basic .NET
# Installation in your project
Add SQLiteHandler.vb and prec.vb to your project
# Example Usage
```vb.net
For Each Drive As DriveInfo In DriveInfo.GetDrives
	If Drive.RootDirectory.FullName = "C:\" Then
		Dim x As New PREC(Drive)
		With x
			.RecoverChrome()
			.RecoverFileZilla()
			.RecoverFireFox()
			.RecoverOpera()
			.RecoverPidgin()
			.RecoverThunderbird()
		End With
		For Each A As Account In x.Accounts
			MsgBox(A.ToString())
		Next
	End If
Next
