# attach_and_break.gdb
set pagination off
set confirm off
set detach-on-fork off
set follow-fork-mode parent
set follow-exec-mode same

define hb
    heap
    vis_heap_chunks
    bt
end
attach $PID

break main
catch syscall execve
break __libc_malloc
break __libc_free
commands
    silent
    printf "[*] hit: %s\n", $_siginfo._sifields._sigchld
end
hb
continue