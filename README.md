# simulation_shell_multiprocess
一个能够多进程并行执行指定命令的脚本模板，用以快速占满CPU
在do_simulation_real(args: dict)函数中替换为自己的执行命令即可。
do_simulation(q: multiprocessing.Queue, lock: multiprocessing.Lock, now: int, args_list: list)函数为进程执行入口。
> [loguru](https://github.com/Delgan/loguru.git)是一个线程安全的日志库
