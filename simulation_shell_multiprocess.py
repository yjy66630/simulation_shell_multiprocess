"""
本文件为simulation_shell.py的多进程版本
"""
import re
import shutil
import subprocess
from multiprocessing import Pool
import multiprocessing
import os
from loguru import logger

"""
以下设置脚本运行参数
"""
# 脚本中可能的协议名称
protocol_list = ["aodv", "aomdv"]
# protocol_list = ["aodv"]
# protocol_list = ["aomdv"]
# 输出文件
log_file = "log.out"
# 源-目的节点对
pairs = [1]
# 发包间隔
intervals = [i / 10 for i in range(10, 11)]
# intervals = [0.7]
# 仿真时间
# durations = [3]
durations = [200]
# 随机数种子，0代表不可重复的实验
seed = 1
times = 1
# cpu数量
cpu = multiprocessing.cpu_count()
# cpu = 2
os.chdir("..")


def do_simulation_real(args: dict):
    pair = args["pair"]
    interval = args["interval"]
    duration = args["duration"]
    time = args["time"]
    # 总目录名称
    dir_name = str(pair) + "_" + str(interval) + "_" + str(duration)
    # 创建的目录名称，每次运行ns3脚本都会将所有对应的输出移动到该目录下
    dir_name_impl = dir_name + "_" + str(time)
    # 创建文件夹
    if not os.path.exists(dir_name):
        os.mkdir(dir_name)
    os.chdir(dir_name)
    os.mkdir(dir_name_impl)
    os.chdir(dir_name_impl)
    for _ in protocol_list:
        os.mkdir(_)
    os.mkdir("分析数据")
    os.chdir("分析数据")
    for _ in protocol_list:
        os.mkdir(_)
    os.chdir("../../../")
    for protocol in protocol_list:
        # 分析得到的流的延迟和丢包率输出的文件名
        flow_delay_file = "flow_delay.csv"
        packet_loss_file = "packet_loss.csv"
        # 需要移动的文件
        generate_files = ["*.pcap", "*.routes", "*.flowmonitor",
                          "*.out", "*.tr", "initialPosition.txt", "*.csv", "flow",
                          "position.txt"]
        # 产生的数据分析文件
        data_files = ["IP.csv", "flow", "initialPosition.txt",
                      "position.txt", "*.io_stat.csv", "*.phs.csv",
                      "output.pcap", flow_delay_file, packet_loss_file]

        def mean(l: list, delayOrPacketLoss: bool) -> float:
            """
            计算平均值

            :param l: 需要计算平均值的列表
            :param delayOrPacketLoss: 判断是delay还是PacketLoss调用，如果是delay，则为true
            """
            l_mean = 0
            cnt = 0
            for i in l:
                if i == -1:
                    if delayOrPacketLoss:
                        continue
                    else:
                        l_mean += 100
                        cnt += 1
                else:
                    l_mean += i
                    cnt += 1
            return l_mean / (cnt + 1e-8)

        def variance(l: list, mean: float, delayOrPacketLoss: bool) -> float:
            l_var = 0
            cnt = 0
            for i in l:
                if i == -1:
                    if delayOrPacketLoss:
                        continue
                    else:
                        l_var += (i - 100) * (i - 100)
                        cnt += 1
                else:
                    l_var += (i - mean) * (i - mean)
                    cnt += 1
            return l_var / cnt

        assert protocol in protocol_list
        # 运行脚本
        command = "./ns3 run --cwd=\"" + dir_name + "/" + dir_name_impl + "\" \"scratch/leo-ldaomdv.cc --pair=" + str(pair) + " --interval=" + \
                  str(interval) + " --duration=" + str(duration) + \
                  " --routing=" + str(protocol) + " --seed=" + str(seed) + "\" > " + dir_name + "/" + dir_name_impl + "/log.out 2>&1"
        subprocess.run(command, shell=True)
        # 生成分析数据
        os.chdir(dir_name + "/" + dir_name_impl)
        subprocess.run("python3 ../../utils/routing-parse.py log.out", shell=True)
        os.chdir('../../')
        subprocess.run(
            "python3 utils/flowmon-parse-results.py " + dir_name + "/" + dir_name_impl + "/flow.flowmonitor > " + dir_name + "/" + dir_name_impl + "/flow",
            shell=True)
        subprocess.run("awk -f utils/position_parse.awk " + dir_name + "/" + dir_name_impl + "/log.out > " + dir_name + "/" + dir_name_impl + "/position.txt",
                       shell=True)
        os.chdir(dir_name + "/" + dir_name_impl)
        subprocess.run("python3 ../../utils/io_stat.py", shell=True)
        subprocess.run("bash ../../utils/mergecap.sh", shell=True)
        # 解析flow
        flowDelay = []
        packetLoss = []
        with open("flow") as f:
            lines = f.readlines()
            for line in lines:
                strFlowId = re.findall(r"FlowID: (\d*)", line)
                if len(strFlowId):
                    flowId = int(strFlowId[0])
                    if flowId > pair:
                        break
                strFlowDelay = re.search(r"Mean Delay: (?P<delay>\d+\.?\d*|None)", line)
                strPacketLoss = re.search(r"Packet Loss Ratio: (?P<PLR>\d+\.?\d*|None)", line)
                f = lambda x: float(x) if x != "None" else -1
                if strFlowDelay is not None:
                    flowDelay.append(f(strFlowDelay.group("delay")))
                if strPacketLoss is not None:
                    packetLoss.append(f(strPacketLoss.group("PLR")))

        assert len(flowDelay) == len(packetLoss)

        with open(flow_delay_file, "w") as f:
            for i in range(1, len(flowDelay) + 1):
                f.write(str(i) + "," + str(flowDelay[i - 1]) + "\n")
            flowDelayMean = mean(flowDelay, True)
            flowDelayVar = variance(flowDelay, flowDelayMean, True)
            f.write("-1," + str(flowDelayMean) + "\n")
            f.write("-2," + str(flowDelayVar) + "\n")

        with open(packet_loss_file, "w") as f:
            for i in range(1, len(packetLoss) + 1):
                f.write(str(i) + "," + str(packetLoss[i - 1]) + "\n")
            flowPacketLossMean = mean(packetLoss, False)
            flowPacketLossVar = variance(packetLoss, flowPacketLossMean, False)
            f.write("-1," + str(flowPacketLossMean) + "\n")
            f.write("-2," + str(flowPacketLossVar) + "\n")

        # 将脚本的输出移动到文件夹中
        for files in data_files:
            lines = os.popen("ls " + files).readlines()
            if lines is not None:
                for file in lines:
                    subprocess.run("cp " + file[:-1] + " ./分析数据/" + protocol, shell=True)

        for files in generate_files:
            lines = os.popen("ls " + files).readlines()
            if lines is not None:
                for file in lines:
                    subprocess.run("mv " + file[:-1] + " ./" + protocol, shell=True)
        os.chdir('../../')


def do_simulation(q: multiprocessing.Queue, lock: multiprocessing.Lock, now: int, args_list: list):
    lock.acquire()
    if not q.empty():
        now = q.get_nowait()
    pair = args_list[now]["pair"]
    interval = args_list[now]["interval"]
    duration = args_list[now]["duration"]
    time = args_list[now]["time"]
    global times
    dir_name = str(pair) + "_" + str(interval) + "_" + str(duration)
    dir_name_impl = dir_name + "_" + str(time)
    command = "./ns3 run --cwd=\"" + dir_name + "/" + dir_name_impl + "\" \"scratch/leo-ldaomdv.cc --pair=" + str(pair) + " --interval=" + \
              str(interval) + " --duration=" + str(duration) + " --seed="+ str(seed) + "\""
    logger.success(f"in: 当前正在运行的进程是{os.getpid()}，执行命令：" + command + " time=" + str(now % times))
    # if q.empty():
    #     now = now + 1
    # else:
    #     now = q.get_nowait()
    if now <= len(args_list):
        now = now + 1
        q.put(now)
    else:
        lock.release()
        return
    lock.release()
    do_simulation_real(args_list[now - 1])
    lock.acquire()
    logger.info(f"out: 当前正在运行的进程是{os.getpid()}，执行命令：" + command + " time=" + str(now % times))
    lock.release()


if __name__ == "__main__":
    pool = Pool(cpu)  # 制定要开启的进程数, 限定了进程上限
    manager = multiprocessing.Manager()
    q = manager.Queue()
    lock = manager.Lock()
    args_list = []  # 参数列表，自动生成
    for pair in pairs:
        for interval in intervals:
            for duration in durations:
                for time in range(times):
                    args_list.append({
                        "pair": pair,
                        "interval": interval,
                        "duration": duration,
                        "time": time
                    })
    # do_simulation_real(args_list[0])
    for _ in range(len(args_list)):
        pool.apply_async(do_simulation, args=(q, lock, 0, args_list))
    pool.close()
    pool.join()
