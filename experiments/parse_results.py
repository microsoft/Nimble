def parse_log(name):
    file = open(name, "r")

    median = 0
    tail = 0
    tput = 0

    for line in file.readlines():
        if "0.500000" in line.split():
           median = line.split()[0]
        elif "0.950000" in line.split():
            tail = line.split()[0]
        elif "Requests/sec:" in line.split():
            tput = line.split()[1]

    res = tput + "," + median + "," + tail
    return res

def parse_reconfig(folder_name):

    data_points = [100000, 200000, 500000, 1000000]

    for i in data_points:
        file = open(folder_name + str(i) + ".log", "r")

        times = []
        for line in file.readlines():
            if "Reconfiguration" in line.split():
               time = line.split()[2]
               times.append(int(time))

        times.sort()

        median = times[int((len(times)+1)/2)]
        print(str(i) + ": " + str(median))


def parse_experiment(storage, op, exp_name):
    out_file = open("results/" + storage + "_" + exp_name + "/" + op + ".dat", "w")

    data_points = [500, 1500, 2000, 2500]

    if storage == "memory" or op == "read":
        data_points += [6000, 7000, 10000, 15000, 20000, 25000, 50000, 55000]

    for i in data_points:
        out_file.write(parse_log("results/" + storage + "_" + exp_name + "/" + op + "-" + str(i) + ".log") + "\n")

def parse_all(exp_name):
    ops = ["read", "append", "create"]
    exps = ["memory", "table"]

    for op in ops:
        for exp in exps:
            parse_experiment(exp, op, exp_name)

def parse_memory(exp_name):
    ops = ["read", "append", "create"]
    for op in ops:
        parse_experiment("memory", op, exp_name)

def parse_table(exp_name):
    ops = ["read", "append", "create"]
    for op in ops:
        parse_experiment("table", op, exp_name)

#parse_memory("3_endorsers")
parse_reconfig("results/3_endorsers_reconfig_final/")
