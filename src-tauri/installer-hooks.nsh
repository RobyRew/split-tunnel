; Installer hooks.
;
; The app spawns wstunnel.exe (and ssh.exe) as children, and they hold the
; files in bin\ open. An in-place upgrade then fails with
; "Error opening file for writing: ...\bin\wstunnel.exe" and the user is left
; choosing between Abort, Retry and Ignore — none of which is a good answer.
; Closing our own processes first makes the upgrade uneventful.

!macro NSIS_HOOK_PREINSTALL
  DetailPrint "Closing SplitTunnel if it is running..."
  nsExec::Exec 'taskkill /F /T /IM SplitTunnel.exe'
  nsExec::Exec 'taskkill /F /IM wstunnel.exe'
  Sleep 700
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  DetailPrint "Closing SplitTunnel..."
  nsExec::Exec 'taskkill /F /T /IM SplitTunnel.exe'
  nsExec::Exec 'taskkill /F /IM wstunnel.exe'
  Sleep 700
!macroend
