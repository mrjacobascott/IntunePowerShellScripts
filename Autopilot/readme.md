This section is for scripts that assist in different aspects of Autopilot management. 

# Usage: 
./DeleteAPDevicesEach.ps1 -sn "SerialNumberHere"
-   To delete devices one at a time
-   Asks user if they want to delete/retire the device in addition to removing from Autopilot


./DeleteAPDevicesBulkEnabled.ps1 -sn -csv
- Use -sn flag to be asked for a single serial number to be removed
- Use -csv flag to be asked for a csv to provide
- Both options allow you to specify if a retire should be done and/or just remove from Autopilot
- When using .csv, your csv should be a single column with no header row, 1 serial number per row
- Prompts will guide along the way
- Results are shown in the Powershell window
