## vba macro

- Output your base64'd shellcode to a text file
- Use something like the included `Invoke-SplitVBA.ps1` to split the text into chunks:  `Invoke-SplitVBA -InputFile b64-shellcode.txt -OutputFile vba.txt`
- Replace `sc = ""` with the chunked output from `Invoke-SplitVBA`.  It should look like:

```
sc = "blah"
sc = sc & "moreblah"
```

- Copy the lot into Word/Excel and go