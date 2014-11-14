# grabnids.py

Run it like this: `python3 grabnids.py /path/to/directory/with/stubs_a/ nids.txt`

Or you can make your own `nids.txt` using whatever tools you've got, for example of such file see `nids.txt.example`

# vitadump.py

Just load your binary into IDA and run the script from IDA menu: `File -> Script file...`

It will:

* read imports and exports from the loaded binary file and create functions
* resolve NIDs and rename functions
* find strings and create xrefs to them

## Before:
![](https://i.imgur.com/XYWiwRR.png)

## After:
![](https://i.imgur.com/c7FUcgV.png)

# License

Copyright (c) 2014 Ilya Zhuravlev

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.