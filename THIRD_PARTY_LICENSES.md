# Third-Party Licenses

This project uses or is inspired by the following third-party software:

## Dobby Hook Framework

**License:** Apache License 2.0  
**Source:** https://github.com/jmpews/Dobby  
**Usage:** This project implements Dobby-style hooking concepts including DobbySymbolResolver for ELF symbol resolution.

```
Copyright (c) 2017-present, jmpews

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

**Note on Implementation:**  
Due to compilation issues with Dobby's ARM64 closure trampoline assembly on Android NDK 26+, this project implements Dobby-compatible APIs and symbol resolution techniques without directly linking the Dobby binary. The implementation follows Dobby's design patterns for:
- ELF file parsing and symbol table extraction
- Module enumeration via /proc/self/maps
- Symbol resolution with caching
- Hook management and tracking

The Dobby project can be found at: https://github.com/jmpews/Dobby

Full Apache License 2.0 text: http://www.apache.org/licenses/LICENSE-2.0
