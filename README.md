# tnum
A python script for working with Windows tokens<br>
![Alt Text](/Capture.PNG?raw=True "Image")

<h2>Features :</h2>

<b>== LIST ==</b><br>
Lists the running programs on the system, their owner and their permissions by querying their token<br>
<br>
<b>== ELEVATE ==</b><br>
Enables all privileges for the current process' token and spawns a command prompt<br>
<br>
<b>== IMPERSONATE ==</b><br>
Duplicates a token from a process, enables all of it's privileges and uses it to spawn a command prompt (you usually have to run this as SYSTEM to switch users)<br>
<br>
<b>== IMPERSONATABLE ==</b><br>
Lists all the processes whose primary tokens can be duplicated and used to spawn processes<br>
</br>
<b>== ATTRIBUTES ==</b><br>
Gets all the token attributes of a process<br>
<br>
<b>== DELEGATE ==</b><br>
Lists possible delegate tokens (BETA)<br>
<br>
<b>== NON-PRIMARY ==</b><br>
Lists non-primary tokens (BETA)
