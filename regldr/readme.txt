A tool to load and unload hive file.
The mount point is HKEY_LOCAL_MACHINE.
Usage:
regldr -l subkey_name_load_to hive_file_name
regldr -u subkey_name_loaded

For example, to load "D:\123\SOFTWARE" to HKEY_LOCAL_MACHINE\MY_SOFT:

regldr -l MY_SOFT "D:\123\SOFTWARE"
...
Do something such as read/write/delete key value.
...
regldr -u MY_SOFT

