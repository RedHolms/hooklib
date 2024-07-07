So, I wanted to create hook library similar to kthook.  
The goal is to make multi-purpose hooking library with simple template interface.  

Current roadmap:
- [X] Functions hooks
- [X] Class methods hooks
- [X] Class constructors/destructors hooks (can't make an example, it'll work only in embedded enviroments)
- [X] Naked hooks (hook at any place where you want)
- [ ] VMT hooks
- [X] Simple call hooks
  
At this time, you can build this project only in 32-bit mode with MSVC or Clang on Windows.
