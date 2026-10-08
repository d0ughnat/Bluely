!macro NSIS_HOOK_PREINSTALL
  nsExec::ExecToLog 'schtasks.exe /End /TN "Bluely Defender Broker"'
  Pop $0
!macroend

!macro NSIS_HOOK_POSTINSTALL
  ; The broker can only scan; it runs as SYSTEM so Defender is available to every signed-in user.
  nsExec::ExecToLog 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$INSTDIR\resources\install-broker.ps1" -BrokerPath "$INSTDIR\bluely-defender-broker.exe"'
  Pop $0
  ${If} $0 != 0
    MessageBox MB_ICONEXCLAMATION|MB_OK "Bluely installed, but its Defender scanner could not be registered. File scans will show Defender unavailable."
  ${EndIf}
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  nsExec::ExecToLog 'schtasks.exe /End /TN "Bluely Defender Broker"'
  Pop $0
  nsExec::ExecToLog 'schtasks.exe /Delete /F /TN "Bluely Defender Broker"'
  Pop $0
  DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "BluelyAgent"
  DeleteRegKey HKCU "Software\Google\Chrome\NativeMessagingHosts\com.blueguard.agent"
  DeleteRegKey HKCU "Software\Chromium\NativeMessagingHosts\com.blueguard.agent"
  DeleteRegKey HKCU "Software\Microsoft\Edge\NativeMessagingHosts\com.blueguard.agent"
!macroend
